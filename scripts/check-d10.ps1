param(
    [Parameter(Mandatory=$true)][string]$Freeze,
    [Parameter(Mandatory=$true)][string]$Output,
    [switch]$Postgres,
    [switch]$Browser,
    [switch]$RequireRelease,
    [string]$Candidate
)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Push-Location $projectRoot
try {
    $checkArgs = @('-m', 'scripts.check_d10', '--freeze', $Freeze, '--output', $Output)
    if ($Postgres) { $checkArgs += '--postgres' }
    if ($Browser) { $checkArgs += '--browser' }
    if ($RequireRelease) { $checkArgs += '--require-release' }
    if ($Candidate) { $checkArgs += @('--candidate', $Candidate) }
    & .venv/Scripts/python @checkArgs
    if ($LASTEXITCODE -ne 0) { throw "D10 gate exit $LASTEXITCODE; inspect the evidence directory" }
} finally { Pop-Location }
