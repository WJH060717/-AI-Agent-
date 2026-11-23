param([switch]$Browser, [switch]$Postgres, [switch]$RequireDataReady)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Push-Location $projectRoot
try {
    $freezeArgs = @('-m', 'eval.freeze', '--output', 'artifacts/d9-inventory.json')
    if ($RequireDataReady) { $freezeArgs += '--require-ready' }
    & .venv/Scripts/python @freezeArgs
    if ($LASTEXITCODE -ne 0) { throw 'D9 inventory freeze/data readiness gate failed' }
    & (Join-Path $PSScriptRoot 'check-d8.ps1') -Postgres:$Postgres -Browser:$Browser
    if ($Browser) {
        & .venv/Scripts/python -m scripts.browser_d3 --day9
        if ($LASTEXITCODE -ne 0) { throw 'D9 three-scenario browser check failed' }
    }
} finally { Pop-Location }
