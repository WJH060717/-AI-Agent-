param([switch]$Browser, [switch]$Postgres)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Push-Location $projectRoot
try {
    & (Join-Path $PSScriptRoot 'check-d6.ps1') -Postgres:$Postgres -Browser:$Browser
    if ($Browser) {
        & .venv/Scripts/python -m scripts.browser_d3 --day7
        if ($LASTEXITCODE -ne 0) { throw 'D7 browser smoke failed' }
    }
} finally { Pop-Location }
