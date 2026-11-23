param([Parameter(Mandatory=$true)][string]$Freeze,
      [Parameter(Mandatory=$true)][string]$Output,
      [Parameter(Mandatory=$true)][string]$AnalysisInput,
      [string]$Candidate,
      [switch]$Postgres, [switch]$Browser, [switch]$RequireRelease)
$arguments = @('-m','scripts.check_d12','--freeze',$Freeze,'--output',$Output,'--analysis-input',$AnalysisInput)
if ($Candidate) { $arguments += @('--candidate',$Candidate) }
if ($Postgres) { $arguments += '--postgres' }
if ($Browser) { $arguments += '--browser' }
if ($RequireRelease) { $arguments += '--require-release' }
& .venv/Scripts/python.exe @arguments
exit $LASTEXITCODE
