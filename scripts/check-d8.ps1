param([switch]$Browser, [switch]$Postgres)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Push-Location $projectRoot
try {
    & .venv/Scripts/python -m eval.inventory --output artifacts/d8-inventory.json
    if ($LASTEXITCODE -ne 0) { throw 'D8 inventory or frozen rules check failed' }
    & (Join-Path $PSScriptRoot 'check-d7.ps1') -Postgres:$Postgres -Browser:$Browser
    if ($Browser) {
        & .venv/Scripts/python -m scripts.browser_d3 --day8
        if ($LASTEXITCODE -ne 0) { throw 'D8 browser smoke failed' }
    }
} finally { Pop-Location }
