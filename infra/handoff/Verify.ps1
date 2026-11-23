param([switch]$RuntimeOnly)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Common.ps1')
Assert-NoLink $PSScriptRoot
$manifest = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'manifest.json') -Raw -Encoding UTF8 | ConvertFrom-Json
if ($manifest.version -ne 'dev24-handoff@1') { throw 'Unsupported bundle version.' }
$prefix = [IO.Path]::GetFullPath($PSScriptRoot).TrimEnd('\') + '\'
$checked = 0
foreach ($entry in $manifest.files.PSObject.Properties) {
    $name = $entry.Name
    if ($name.StartsWith('/') -or $name.Contains('\') -or $name.Contains(':') -or ($name.Split('/') -contains '..')) { throw 'Invalid manifest path.' }
    if ($RuntimeOnly -and $name.StartsWith('project/')) { continue }
    $path = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot $name))
    if (-not $path.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { throw 'Invalid manifest scope.' }
    Assert-NoLink $path
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing file: $name" }
    if ((Get-Item -LiteralPath $path).Length -ne $entry.Value.bytes -or (Get-HandoffFileHash $path) -ne $entry.Value.sha256) { throw "Changed file: $name" }
    $checked++
}
foreach ($required in @('Start.ps1','Stop.ps1','Common.ps1','Verify.ps1','compose.yaml','images.json','images.tar')) {
    if (-not ($manifest.files.PSObject.Properties.Name -contains $required)) { throw "Missing manifest entry: $required" }
}
Write-Host "Integrity checked: $checked files."
