param([int]$Port = 0, [switch]$NoOpen)
$ErrorActionPreference = 'Stop'
$script:PrivateDir = $null
. (Join-Path $PSScriptRoot 'Common.ps1')
Assert-NoLink $PSScriptRoot
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { throw 'Install and start Docker Desktop, then try again.' }
$engine = Get-HandoffEngine
$null = Invoke-HandoffDocker @('compose','version','--short')
& (Join-Path $PSScriptRoot 'Verify.ps1') -RuntimeOnly
$script:PrivateDir = Join-Path $PSScriptRoot '_local'
Assert-NoLink $script:PrivateDir
if (-not (Test-Path -LiteralPath $script:PrivateDir)) { $null = New-Item -ItemType Directory -Path $script:PrivateDir }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
& icacls $script:PrivateDir /inheritance:r /grant:r "${identity}:(OI)(CI)F" 'SYSTEM:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Cannot protect the local credentials directory.' }
$lock = $null
try {
    $lock = [IO.File]::Open((Join-Path $script:PrivateDir 'startup.lock'), 'OpenOrCreate', 'ReadWrite', 'None')
    $statePath = Join-Path $script:PrivateDir 'state.json'
    $images = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'images.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    $needLoad = $false
    foreach ($image in $images.images) {
        try { $actual = Invoke-HandoffDocker @('image','inspect','--format','{{.Id}}',$image.tag) }
        catch { $actual = ''; $needLoad = $true }
        if ($actual -and -not (Test-HandoffImageId $image $actual)) { throw 'An image tag conflicts with this bundle. Existing image preserved.' }
    }
    if ($needLoad) {
        Write-Host 'Loading bundled images. This can take several minutes...'
        $null = Invoke-HandoffDocker @('load','--input',(Join-Path $PSScriptRoot 'images.tar'))
    }
    foreach ($image in $images.images) {
        if (-not (Test-HandoffImageId $image (Invoke-HandoffDocker @('image','inspect','--format','{{.Id}}',$image.tag)))) { throw 'Loaded image mismatch.' }
        if ((Invoke-HandoffDocker @('image','inspect','--format','{{.Os}}/{{.Architecture}}',$image.tag)) -ne 'linux/amd64') { throw 'Loaded image platform mismatch.' }
    }
    if (Test-Path -LiteralPath $statePath) {
        Assert-NoLink $statePath
        $state = Get-Content -LiteralPath $statePath -Raw -Encoding UTF8 | ConvertFrom-Json
        $null = Assert-EngineBinding $state
        if ($state.bundle -ne $images.bundle -or $state.owner_password -notmatch '^[a-f0-9]{64}$' -or $state.app_password -notmatch '^[a-f0-9]{64}$') { throw 'Local state belongs to another bundle or is damaged.' }
    } else {
        if (Test-Path -LiteralPath (Join-Path $script:PrivateDir 'access.json')) { throw 'Credentials already exist without local state. Preserve this folder for recovery.' }
        $state = [PSCustomObject]@{ bundle=$images.bundle; project=('tracehandoff'+[Guid]::NewGuid().ToString('N').Substring(0,16)); port=8080; owner_password=(New-RandomHex); app_password=(New-RandomHex); docker_context=$engine.context; docker_endpoint=$engine.endpoint }
        Write-LocalJson $statePath $state
    }
    if ($Port -and ($Port -lt 1024 -or $Port -gt 65535)) { throw 'Choose a port from 1024 to 65535.' }
    # Generate only known keys; no inherited app/model/database values enter Compose.
    function Save-Environment {
        $lines = @("HANDOFF_APP_IMAGE=$($images.images[0].tag)","HANDOFF_WEB_IMAGE=$($images.images[1].tag)","HANDOFF_DB_IMAGE=$($images.images[2].tag)","HANDOFF_PORT=$($state.port)","HANDOFF_OWNER_PASSWORD=$($state.owner_password)","HANDOFF_APP_PASSWORD=$($state.app_password)")
        [IO.File]::WriteAllLines((Join-Path $script:PrivateDir 'runtime.env'), $lines, [Text.UTF8Encoding]::new($false))
    }
    Save-Environment
    $compose = Get-ComposeArguments $state $PSScriptRoot
    $ownWeb = Invoke-HandoffDocker ($compose + @('ps','--status','running','-q','web'))
    if ($Port -and $Port -ne $state.port -and $ownWeb) { throw 'Stop this bundle before changing its port.' }
    if ($Port) { $state.port = $Port }
    if (-not $ownWeb -and -not (Test-FreePort $state.port)) {
        if ($Port) { throw 'Requested port is occupied. Existing service preserved.' }
        $found = $false
        foreach ($candidate in 8080..8199) { if (Test-FreePort $candidate) { $state.port=$candidate; $found=$true; break } }
        if (-not $found) { throw 'No free local port found.' }
    }
    Write-LocalJson $statePath $state
    Save-Environment
    $null = Invoke-HandoffDocker ($compose + @('up','-d','--wait','--wait-timeout','180','db'))
    $null = Invoke-HandoffDocker ($compose + @('run','--rm','--no-deps','initialize'))
    $null = Invoke-HandoffDocker ($compose + @('up','-d','--wait','--wait-timeout','180','api','worker','web'))
    $url = 'http://127.0.0.1:' + $state.port
    $access = Get-Content -LiteralPath (Join-Path $script:PrivateDir 'access.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    $null = Invoke-WebRequest -UseBasicParsing -Uri ($url+'/api/v1/health/live') -TimeoutSec 15
    [IO.File]::WriteAllText((Join-Path $script:PrivateDir 'login.txt'), ($url+[Environment]::NewLine+$access.tokens.admin), [Text.UTF8Encoding]::new($false))
    Write-Host "Ready: $url"
    Write-Host 'Model disabled. Your token is in _local/login.txt. Data persists after STOP.'
    if (-not $NoOpen) {
        Set-Clipboard -Value $access.tokens.admin
        Start-Process $url
        Write-Host 'Token copied. Paste it into the access-token box and connect.'
    }
} finally { if ($lock) { $lock.Dispose() } }
