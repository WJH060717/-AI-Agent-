$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Push-Location $projectRoot
try {
    & .venv/Scripts/python -m scripts.export_contracts
    if ($LASTEXITCODE -ne 0) { throw 'Schema export failed' }
    & (Join-Path $PSScriptRoot 'check-d1.ps1')
} finally { Pop-Location }
