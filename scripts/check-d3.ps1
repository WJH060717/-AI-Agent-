param([switch]$Browser, [switch]$Postgres)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Push-Location $projectRoot
try {
    & (Join-Path $PSScriptRoot 'check-d2.ps1')
    if ($Postgres) {
        & .venv/Scripts/python -m scripts.test_postgres
        if ($LASTEXITCODE -ne 0) { throw 'PostgreSQL integration tests failed' }
    }
    if ($Browser) {
        & .venv/Scripts/python -m scripts.browser_d3
        if ($LASTEXITCODE -ne 0) { throw 'Browser smoke failed' }
    }
} finally { Pop-Location }
