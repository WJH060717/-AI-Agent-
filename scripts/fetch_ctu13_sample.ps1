param([Parameter(Mandatory=$true)][string]$OutputDirectory,
      [ValidateSet(4,32)][int]$MaxMiB = 4)
$ErrorActionPreference = 'Stop'
$target = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $target) { throw 'Output directory already exists' }
$null = New-Item -ItemType Directory -Path $target
$url = 'https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-48/bro/conn.log'
$cap = $MaxMiB * 1024 * 1024
$client = [Net.Http.HttpClient]::new()
$client.Timeout = [TimeSpan]::FromSeconds(45)
$request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Get, $url)
$request.Headers.Range = [Net.Http.Headers.RangeHeaderValue]::new(0, $cap - 1)
$response = $null
$stream = $null
$file = $null
try {
    $response = $client.SendAsync($request, [Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
    $null = $response.EnsureSuccessStatusCode()
    if ([int]$response.StatusCode -ne 206 -or $response.Content.Headers.ContentRange.From -ne 0) {
        throw 'Expected official byte range beginning at zero'
    }
    if ($response.RequestMessage.RequestUri.AbsoluteUri -ne $url) { throw 'Unexpected redirect' }
    $stream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
    $path = Join-Path $target 'conn.prefix.log'
    $file = [IO.File]::Open($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
    $buffer = [byte[]]::new(65536)
    $total = 0
    while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
        $total += $read
        if ($total -gt $cap) { throw 'Download exceeded configured byte bound' }
        $file.Write($buffer, 0, $read)
    }
    $file.Dispose(); $file = $null
    if ($total -ne $response.Content.Headers.ContentLength) { throw 'Incomplete HTTP response' }
    [ordered]@{
        url = $url
        source_page = 'https://www.stratosphereips.org/datasets-ctu13'
        scenario = 7
        capture = 'CTU-Malware-Capture-Botnet-48'
        retrieved_at = [DateTime]::UtcNow.ToString('o')
        http_status = [int]$response.StatusCode
        content_range = $response.Content.Headers.ContentRange.ToString()
        etag = $response.Headers.ETag.ToString()
        last_modified = $response.Content.Headers.LastModified.ToString()
        byte_count = $total
        sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        selection = 'Original conn.log bytes; sample policy recorded separately by offline adapter'
        citation = 'Garcia, Sebastian. Malware Capture Facility Project. https://stratosphereips.org'
    } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $target 'download.json') -Encoding utf8
    Write-Output "Downloaded $total bytes with TLS certificate validation."
} finally {
    if ($file) { $file.Dispose() }
    if ($stream) { $stream.Dispose() }
    if ($response) { $response.Dispose() }
    $request.Dispose(); $client.Dispose()
}
