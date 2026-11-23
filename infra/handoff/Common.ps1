$ErrorActionPreference = 'Stop'

function Get-HandoffFileHash([string]$Path) {
    # .NET works even when a host inherits another PowerShell version's module path.
    $algorithm = [Security.Cryptography.SHA256]::Create()
    $stream = [IO.File]::OpenRead($Path)
    try { return -join ($algorithm.ComputeHash($stream) | ForEach-Object { $_.ToString('x2') }) }
    finally { $stream.Dispose(); $algorithm.Dispose() }
}

function Test-HandoffImageId($Image, [string]$Actual) {
    # Docker stores may expose the OCI index/manifest or the image config digest.
    # All accepted digests are derived from the exact bundled Linux/amd64 archive.
    return ($Actual -cmatch '^sha256:[a-f0-9]{64}$') -and (@($Image.id, $Image.platform_id, $Image.config_id) -ccontains $Actual)
}

function Assert-NoLink([string]$Path) {
    $item = [IO.Path]::GetFullPath($Path)
    while ($item) {
        if (Test-Path -LiteralPath $item) {
            if ((Get-Item -Force -LiteralPath $item).Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw 'Linked paths are not supported. Extract into a new ordinary folder.'
            }
        }
        $parent = [IO.Directory]::GetParent($item)
        if ($null -eq $parent) { break }
        $item = $parent.FullName
    }
}

function Write-LocalJson([string]$Path, $Value) {
    Assert-NoLink $Path
    $temporary = $Path + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
    [IO.File]::WriteAllText($temporary, ($Value | ConvertTo-Json -Depth 12), [Text.UTF8Encoding]::new($false))
    if (Test-Path -LiteralPath $Path) {
        # Windows PowerShell 5.1 coerces $null to an empty backup pathname.
        # Use a new private backup pathname and never replace an older backup.
        $backup = $Path + '.' + [Guid]::NewGuid().ToString('N') + '.previous'
        [IO.File]::Replace($temporary, $Path, $backup)
    }
    else { [IO.File]::Move($temporary, $Path) }
}

function Invoke-HandoffDocker([string[]]$Arguments) {
    # Explicit compose configuration must not be overridden by inherited settings.
    $saved = @{}
    if ($Arguments[0] -eq 'compose') {
        Get-ChildItem Env: | Where-Object { $_.Name -like 'HANDOFF_*' -or $_.Name -like 'COMPOSE_*' } | ForEach-Object {
            $saved[$_.Name] = $_.Value
            [Environment]::SetEnvironmentVariable($_.Name, $null, 'Process')
        }
    }
    try {
        $previous = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        $result = & docker @Arguments 2>&1
        $code = $LASTEXITCODE
        $ErrorActionPreference = $previous
        $log = ($result | Out-String)
        if ($script:PrivateDir -and (Test-Path -LiteralPath $script:PrivateDir)) {
            [IO.File]::WriteAllText((Join-Path $script:PrivateDir 'last-command.log'), $log, [Text.UTF8Encoding]::new($false))
        }
        if ($code -ne 0) { throw 'Docker command failed. See _local/last-command.log (private).' }
        return $log.Trim()
    } finally {
        foreach ($key in $saved.Keys) { [Environment]::SetEnvironmentVariable($key, $saved[$key], 'Process') }
    }
}

function Get-ComposeArguments($State, [string]$Root) {
    if ($State.project -notmatch '^tracehandoff[a-f0-9]{16}$' -or $State.port -lt 1024 -or $State.port -gt 65535) {
        throw 'Invalid local state; original data has been preserved.'
    }
    return @('compose', '--project-name', $State.project, '--env-file', (Join-Path $Root '_local/runtime.env'), '-f', (Join-Path $Root 'compose.yaml'))
}

function Test-FreePort([int]$Port) {
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, $Port)
    try { $listener.Server.ExclusiveAddressUse = $true; $listener.Start(); return $true }
    catch { return $false }
    finally { $listener.Stop() }
}

function New-RandomHex {
    $buffer = New-Object byte[] 32
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($buffer) } finally { $rng.Dispose() }
    return -join ($buffer | ForEach-Object { $_.ToString('x2') })
}

function Get-HandoffEngine {
    if ($env:DOCKER_HOST) { throw 'Clear DOCKER_HOST and select the local Docker Desktop context.' }
    $context = Invoke-HandoffDocker @('context','show')
    $endpoint = Invoke-HandoffDocker @('context','inspect','--format','{{.Endpoints.docker.Host}}')
    if (-not $endpoint.StartsWith('npipe:')) { throw 'Use the local Docker Desktop context.' }
    $platform = Invoke-HandoffDocker @('version','--format','{{.Server.Os}}/{{.Server.Arch}}')
    if ($platform -ne 'linux/amd64') { throw 'This package requires Docker Desktop Linux containers (amd64).' }
    return [PSCustomObject]@{ context=$context; endpoint=$endpoint }
}

function Assert-EngineBinding($State) {
    $engine = Get-HandoffEngine
    if ($State.docker_context -ne $engine.context -or $State.docker_endpoint -ne $engine.endpoint) {
        throw 'A different Docker context is selected. Switch back to the context recorded in _local/state.json.'
    }
    return $engine
}
