#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$venvPy = Join-Path $Root ".venv\Scripts\python.exe"
if (-not (Test-Path $venvPy)) {
    $sysPy = "D:\Dev\Ide\Python\python.exe"
    if (Test-Path $sysPy) {
        $venvPy = $sysPy
        Write-Host "未找到 .venv，使用系统 Python: $venvPy"
    } else {
        $cmd = Get-Command python -ErrorAction SilentlyContinue
        if ($cmd) { $venvPy = $cmd.Source; Write-Host "未找到 .venv，使用 PATH Python: $venvPy" } else {
            throw "找不到 .venv\Scripts\python.exe 且系统也无 python，先运行 scripts\setup_windows.ps1 或安装 Python 3.10+"
        }
    }
}

if (-not $env:MONITOR_TOKEN) {
    $tokFile = Join-Path $Root "log\monitor.token"
    if (Test-Path $tokFile) { $env:MONITOR_TOKEN = (Get-Content $tokFile -Raw -Encoding UTF8).Trim() }
}
if (-not $env:MONITOR_TOKEN) {
    $env:MONITOR_TOKEN = & $venvPy -c "import secrets; print(secrets.token_urlsafe(32))"
    Write-Host "MONITOR_TOKEN=$($env:MONITOR_TOKEN)"
}
$env:MONITOR_HOST = if ($env:MONITOR_HOST) { $env:MONITOR_HOST } else { "127.0.0.1" }
$env:MONITOR_PORT = if ($env:MONITOR_PORT) { $env:MONITOR_PORT } else { "8787" }
$env:PYTHONUNBUFFERED = "1"
$env:PYTHONUTF8 = "1"
if (-not $env:GROK_HEADLESS) { $env:GROK_HEADLESS = "1" }
$env:GROK_USE_XVFB = "0"

Write-Host "Panel http://$($env:MONITOR_HOST):$($env:MONITOR_PORT)/  token=$($env:MONITOR_TOKEN)"
& $venvPy -u (Join-Path $Root "webui\monitor.py")
exit $LASTEXITCODE
