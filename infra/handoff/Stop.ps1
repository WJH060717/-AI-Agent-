$ErrorActionPreference = 'Stop'
$script:PrivateDir = Join-Path $PSScriptRoot '_local'
. (Join-Path $PSScriptRoot 'Common.ps1')
Assert-NoLink $PSScriptRoot
$statePath = Join-Path $script:PrivateDir 'state.json'
if (-not (Test-Path -LiteralPath $statePath)) { Write-Host 'This bundle has not been started.'; exit 0 }
Assert-NoLink $statePath
$state = Get-Content -LiteralPath $statePath -Raw -Encoding UTF8 | ConvertFrom-Json
$null = Assert-EngineBinding $state
$lock = [IO.File]::Open((Join-Path $script:PrivateDir 'startup.lock'), 'OpenOrCreate', 'ReadWrite', 'None')
try {
    $null = Invoke-HandoffDocker ((Get-ComposeArguments $state $PSScriptRoot) + @('stop','--timeout','30','web','api','worker','db'))
    Write-Host 'Stopped this bundle. All data and credentials retained.'
} finally { $lock.Dispose() }
