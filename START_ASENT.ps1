# START_ASENT.ps1 - Start ASENT on Windows
$ErrorActionPreference = "Stop"

$root = $PSScriptRoot
Set-Location $root

$python = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path $python)) {
    Write-Host "[ASENT] Creating virtual environment..." -ForegroundColor Cyan
    python -m venv .venv
    & $python -m pip install --disable-pip-version-check -q -r requirements.lock.txt
}

$distHtml = Join-Path $root "frontend\dist\index.html"
if (-not (Test-Path $distHtml)) {
    Write-Host "[ASENT] Building frontend..." -ForegroundColor Cyan
    Push-Location (Join-Path $root "frontend")
    try {
        npx vite build
    } finally {
        Pop-Location
    }
}

Write-Host "[ASENT] Starting ASENT assurance backend on http://127.0.0.1:8000 ..." -ForegroundColor Green
& $python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
