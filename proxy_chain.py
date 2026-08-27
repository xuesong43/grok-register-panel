"""Optional dialer hop for upstream proxies that reject direct residential egress.

Keep the managed proxy pool free-form. When an upstream host matches
``proxy_dialer_hosts`` (default suffix: 1024proxy.io) and ``proxy_dialer`` is
set, connections are established through that local jump proxy first.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import select
import secrets
import socket
import socketserver
import ssl
import threading
from pathlib import Path
from urllib.parse import unquote, urlparse

ROOT = Path(__file__).resolve().parent
CONFIG_PATH = ROOT / "config.json"

HEADER_LIMIT = 64 * 1024

_SETTINGS_LOCK = threading.RLock()
_SETTINGS_CACHE: dict | None = None
_BRIDGE_LOCK = threading.RLock()
_BRIDGES: dict[str, "_DialerBridge"] = {}


def clear_settings_cache() -> None:
    global _SETTINGS_CACHE
    with _SETTINGS_LOCK:
        _SETTINGS_CACHE = None


def _split_hosts(raw: object) -> tuple[str, ...]:
    text = str(raw or "").strip()
    if not text:
        return ()
    parts: list[str] = []
    for chunk in text.replace("\n", ",").replace(";", ",").split(","):
        host = chunk.strip().lower().rstrip(".")
        if host.startswith("*."):
            host = host[2:]
        if host.startswith("."):
            host = host[1:]
        if host and host not in parts:
            parts.append(host)
    return tuple(parts)


def _read_config_file() -> dict:
    try:
        raw = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return {}
    return raw if isinstance(raw, dict) else {}


def get_dialer_settings() -> dict:
    """Return ``{url, hosts}`` from env first, then config.json."""
    global _SETTINGS_CACHE
    with _SETTINGS_LOCK:
        if _SETTINGS_CACHE is not None:
            return dict(_SETTINGS_CACHE)

        env_url = str(os.environ.get("GROK_PROXY_DIALER_URL", "") or "").strip()
        env_hosts = str(os.environ.get("GROK_PROXY_DIALER_HOSTS", "") or "").strip()
        cfg = _read_config_file()
        url = env_url or str(cfg.get("proxy_dialer") or "").strip()
        hosts_raw = env_hosts or str(cfg.get("proxy_dialer_hosts") or "").strip()
        # If dialer is configured but hosts omitted, default to 1024 gateways only.
        if url and not hosts_raw:
            hosts_raw = "1024proxy.io"
        settings = {"url": url, "hosts": _split_hosts(hosts_raw)}
        _SETTINGS_CACHE = dict(settings)
        return settings


def host_needs_dialer(hostname: object) -> bool:
    host = str(hostname or "").strip().lower().rstrip(".")
    if not host:
        return False
    settings = get_dialer_settings()
    if not settings["url"] or not settings["hosts"]:
        return False
    for suffix in settings["hosts"]:
        if host == suffix or host.endswith("." + suffix):
            return True
    return False


def proxy_needs_dialer(proxy_url: object) -> bool:
    text = str(proxy_url or "").strip()
    if not text:
        return False
    try:
        parsed = urlparse(text)
    except Exception:
        return False
    return host_needs_dialer(parsed.hostname)


def _basic_authorization_header(username: str, password: str) -> bytes:
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return f"Proxy-Authorization: Basic {token}".encode("ascii")


def _read_headers(sock: socket.socket) -> tuple[bytes, bytes]:
    data = bytearray()
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(8192)
        if not chunk:
            raise ConnectionError("connection closed before proxy headers")
        data.extend(chunk)
        if len(data) > HEADER_LIMIT:
            raise ValueError("proxy headers too large")
    head, rest = bytes(data).split(b"\r\n\r\n", 1)
    return head, rest


def _header_value(head: bytes, name: bytes) -> bytes:
    prefix = name.lower() + b":"
    for line in head.split(b"\r\n")[1:]:
        if line.lower().startswith(prefix):
            return line.split(b":", 1)[1].strip()
    return b""


def _rewrite_headers(head: bytes, authorization: bytes | None) -> bytes:
    lines = head.split(b"\r\n")
    output = [lines[0]]
    for line in lines[1:]:
        lowered = line.lower()
        if lowered.startswith(b"proxy-authorization:"):
            continue
        if lowered.startswith(b"proxy-connection:"):
            continue
        output.append(line)
    if authorization:
        output.append(authorization)
    return b"\r\n".join(output) + b"\r\n\r\n"


def _proxy_authorization(parsed) -> bytes | None:
    if parsed.username is None:
        return None
    username = unquote(parsed.username or "")
    password = unquote(parsed.password or "")
    return _basic_authorization_header(username, password)


def connect_via_dialer(host: str, port: int, timeout: float = 15.0) -> socket.socket:
    """TCP-connect to host:port through the configured HTTP dialer (CONNECT)."""
    settings = get_dialer_settings()
    dialer_url = str(settings.get("url") or "").strip()
    if not dialer_url:
        raise RuntimeError("proxy_dialer 未配置")
    dialer = urlparse(dialer_url)
    if dialer.scheme not in ("http", "https") or not dialer.hostname:
        raise RuntimeError("proxy_dialer 必须是 http(s) URL")
    dialer_port = dialer.port or (443 if dialer.scheme == "https" else 80)
    sock = socket.create_connection((dialer.hostname, dialer_port), timeout=timeout)
    try:
        if dialer.scheme == "https":
            sock = ssl.create_default_context().wrap_socket(
                sock, server_hostname=dialer.hostname
            )
        auth = _proxy_authorization(dialer)
        request = [
            f"CONNECT {host}:{int(port)} HTTP/1.1".encode("ascii"),
            f"Host: {host}:{int(port)}".encode("ascii"),
            b"Proxy-Connection: Keep-Alive",
        ]
        if auth:
            request.append(auth)
        sock.sendall(b"\r\n".join(request) + b"\r\n\r\n")
        head, rest = _read_headers(sock)
        status = head.split(b"\r\n", 1)[0]
        if b" 200 " not in status:
            snippet = head[:180].decode("latin1", errors="replace")
            raise OSError(f"dialer CONNECT failed: {snippet}")
        if rest:
            # No extra buffered payload expected for a clean CONNECT.
            raise OSError("dialer CONNECT returned unexpected payload")
        return sock
    except Exception:
        try:
            sock.close()
        except OSError:
            pass
        raise


def connect_proxy_endpoint(
    host: str,
    port: int,
    *,
    scheme: str = "http",
    timeout: float = 15.0,
) -> socket.socket:
    """Connect to an upstream proxy endpoint, optionally via dialer."""
    host = str(host or "").strip()
    if not host:
        raise ValueError("upstream proxy host is missing")
    port_i = int(port)
    if host_needs_dialer(host):
        sock = connect_via_dialer(host, port_i, timeout=timeout)
    else:
        sock = socket.create_connection((host, port_i), timeout=timeout)
    if str(scheme or "").lower() == "https":
        sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
    return sock


class _BridgeHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.server.bridge.handle_client(self.request)  # type: ignore[attr-defined]


class _BridgeServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class _DialerBridge:
    """Local HTTP proxy that reaches a dialer-required upstream via jump host."""

    def __init__(self, upstream_url: str):
        parsed = urlparse(upstream_url)
        self.upstream_url = upstream_url
        self.scheme = parsed.scheme
        self.host = parsed.hostname or ""
        self.port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self.authorization = _proxy_authorization(parsed)
        self.local_username = "dialer"
        self.local_password = secrets.token_urlsafe(18)
        self.local_authorization = (
            _basic_authorization_header(self.local_username, self.local_password)
            .split(b":", 1)[1]
            .strip()
        )
        self.server = _BridgeServer(("127.0.0.1", 0), _BridgeHandler)
        self.server.bridge = self  # type: ignore[attr-defined]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def local_url(self) -> str:
        return (
            f"http://{self.local_username}:{self.local_password}"
            f"@127.0.0.1:{self.server.server_address[1]}"
        )

    def _connect_upstream(self) -> socket.socket:
        return connect_proxy_endpoint(
            self.host,
            self.port,
            scheme=self.scheme,
            timeout=15.0,
        )

    def _send_error(self, client: socket.socket) -> None:
        try:
            client.sendall(
                b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
            )
        except OSError:
            pass

    def _send_proxy_auth_required(self, client: socket.socket) -> None:
        try:
            client.sendall(
                b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                b'Proxy-Authenticate: Basic realm="grok-proxy-dialer"\r\n'
                b"Connection: close\r\nContent-Length: 0\r\n\r\n"
            )
        except OSError:
            pass

    def _relay(self, client: socket.socket, upstream: socket.socket) -> None:
        sockets = [client, upstream]
        while True:
            readable, _, _ = select.select(sockets, [], [], 120)
            if not readable:
                return
            for source in readable:
                target = upstream if source is client else client
                data = source.recv(65536)
                if not data:
                    return
                target.sendall(data)

    def handle_client(self, client: socket.socket) -> None:
        upstream = None
        try:
            client.settimeout(30)
            head, rest = _read_headers(client)
            if _header_value(head, b"Proxy-Authorization") != self.local_authorization:
                self._send_proxy_auth_required(client)
                return
            first_line = head.split(b"\r\n", 1)[0]
            method = first_line.split(b" ", 1)[0].upper()
            upstream = self._connect_upstream()
            upstream.settimeout(30)
            outbound = _rewrite_headers(head, self.authorization)
            if method != b"CONNECT":
                outbound += rest
            upstream.sendall(outbound)
            if method == b"CONNECT":
                response_head, response_rest = _read_headers(upstream)
                response = response_head + b"\r\n\r\n" + response_rest
                client.sendall(response)
                status = response_head.split(b"\r\n", 1)[0]
                if b" 200 " not in status:
                    return
            self._relay(client, upstream)
        except Exception:
            self._send_error(client)
        finally:
            if upstream is not None:
                try:
                    upstream.close()
                except OSError:
                    pass
            try:
                client.close()
            except OSError:
                pass

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def prepare_proxy_url(proxy_url: object) -> str:
    """Return a locally reachable proxy URL, wrapping dialer-required upstreams."""
    text = str(proxy_url or "").strip()
    if not text or not proxy_needs_dialer(text):
        return text
    parsed = urlparse(text)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return text
    key = hashlib.sha256(text.encode("utf-8")).hexdigest()
    with _BRIDGE_LOCK:
        bridge = _BRIDGES.get(key)
        if bridge is None:
            bridge = _DialerBridge(text)
            _BRIDGES[key] = bridge
        return bridge.local_url


def close_runtime() -> None:
    with _BRIDGE_LOCK:
        bridges = list(_BRIDGES.values())
        _BRIDGES.clear()
    for bridge in bridges:
        try:
            bridge.close()
        except Exception:
            pass
