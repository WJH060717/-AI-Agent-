$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$projectPython = Join-Path $projectRoot '.venv/Scripts/python.exe'
Push-Location $projectRoot
try {
    & $projectPython -m pytest -q
    if ($LASTEXITCODE -ne 0) { throw 'Python tests failed' }
    & $projectPython -m ruff check .
    if ($LASTEXITCODE -ne 0) { throw 'Ruff failed' }
    & $projectPython -m ruff format --check .
    if ($LASTEXITCODE -ne 0) { throw 'Formatting failed' }
    & $projectPython -m pip check
    if ($LASTEXITCODE -ne 0) { throw 'Dependency check failed' }
    Push-Location 'apps/web'
    try {
        foreach ($taskName in @('typegen', 'typecheck', 'lint', 'build')) {
            & npm run $taskName
            if ($LASTEXITCODE -ne 0) { throw "Frontend task failed: $taskName" }
        }
    } finally { Pop-Location }
} finally { Pop-Location }
