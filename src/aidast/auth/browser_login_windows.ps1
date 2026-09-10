param(
    [Parameter(Mandatory=$true)][string]$TargetUrl,
    [Parameter(Mandatory=$true)][string]$OutputPath
)
$ErrorActionPreference = 'Stop'
$target = [Uri]$TargetUrl
if ($target.Scheme -notin @('https', 'http') -or $target.UserInfo) { throw 'Invalid target URL' }
$targetOrigin = $target.GetLeftPart([UriPartial]::Authority).ToLowerInvariant()
$targetHost = $target.Host.ToLowerInvariant()
$chromePath = $null
foreach ($baseDir in @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:LOCALAPPDATA)) {
    if ($baseDir) {
        $candidate = Join-Path $baseDir 'Google\Chrome\Application\chrome.exe'
        if (Test-Path -LiteralPath $candidate) { $chromePath = $candidate; break }
    }
}
if (-not $chromePath) { throw 'Google Chrome is not installed on Windows' }
$sessionDir = Split-Path -Parent $OutputPath
$profileDir = Join-Path $sessionDir 'chrome-profile'
$null = New-Item -ItemType Directory -Force -Path $profileDir
$activePortPath = Join-Path $profileDir 'DevToolsActivePort'
if (Test-Path -LiteralPath $activePortPath) { Remove-Item -LiteralPath $activePortPath }
$chromeArgs = @('--remote-debugging-port=0', "--user-data-dir=`"$profileDir`"",
    '--no-first-run', '--no-default-browser-check', '--no-proxy-server', "`"$TargetUrl`"")
$chromeProcess = $null
$script:socket = $null
$script:messageId = 0
function Invoke-Cdp([string]$Method, [hashtable]$Parameters = @{}, [string]$SessionId = '') {
    $script:messageId++
    $id = $script:messageId
    $message = @{id=$id; method=$Method; params=$Parameters}
    if ($SessionId) { $message.sessionId = $SessionId }
    $bytes = [Text.Encoding]::UTF8.GetBytes(($message | ConvertTo-Json -Depth 30 -Compress))
    $cancel = New-Object Threading.CancellationTokenSource
    $cancel.CancelAfter(15000)
    try {
        $segment = New-Object 'ArraySegment[byte]' -ArgumentList (,$bytes)
        $script:socket.SendAsync($segment, [Net.WebSockets.WebSocketMessageType]::Text, $true, $cancel.Token).GetAwaiter().GetResult()
        while ($true) {
            $buffer = New-Object byte[] 65536
            $stream = New-Object IO.MemoryStream
            try {
                do {
                    $chunk = $script:socket.ReceiveAsync([ArraySegment[byte]]::new($buffer), $cancel.Token).GetAwaiter().GetResult()
                    if ($chunk.MessageType -eq [Net.WebSockets.WebSocketMessageType]::Close) { throw 'Chrome closed the session export connection' }
                    $stream.Write($buffer, 0, $chunk.Count)
                    if ($stream.Length -gt 16777216) { throw 'Session export response exceeds limit' }
                } while (-not $chunk.EndOfMessage)
                $reply = [Text.Encoding]::UTF8.GetString($stream.ToArray()) | ConvertFrom-Json
            } finally { $stream.Dispose() }
            if ($reply.id -eq $id) {
                if ($reply.error) { throw "Chrome session export command failed: $Method" }
                return $reply.result
            }
        }
    } finally { $cancel.Dispose() }
}
try {
    $chromeProcess = Start-Process -FilePath $chromePath -ArgumentList $chromeArgs -PassThru
    Write-Host 'Log in using the Windows Chrome window. Keep the target page open when finished.'
    $null = Read-Host 'After completing login, press Enter to export the target session'
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    while (-not (Test-Path -LiteralPath $activePortPath)) {
        if ([DateTime]::UtcNow -gt $deadline) { throw 'Chrome export connection is unavailable' }
        Start-Sleep -Milliseconds 100
    }
    $portInfo = Get-Content -LiteralPath $activePortPath
    $port = [int]$portInfo[0]
    if ($port -lt 1 -or $port -gt 65535 -or -not $portInfo[1].StartsWith('/devtools/browser/')) { throw 'Invalid Chrome export endpoint' }
    $script:socket = New-Object Net.WebSockets.ClientWebSocket
    $connectCancel = New-Object Threading.CancellationTokenSource
    $connectCancel.CancelAfter(15000)
    try {
        $script:socket.ConnectAsync([Uri]("ws://127.0.0.1:" + $port + $portInfo[1]), $connectCancel.Token).GetAwaiter().GetResult()
    } finally { $connectCancel.Dispose() }
    $cookies = @()
    foreach ($cookie in (Invoke-Cdp 'Storage.getCookies').cookies) {
        $domain = $cookie.domain.ToLowerInvariant()
        $root = $domain.TrimStart('.')
        if ($targetHost -eq $root -or ($domain.StartsWith('.') -and $targetHost.EndsWith('.' + $root))) {
            $cookies += $cookie
        }
    }
    $origins = @()
    $sessionStorage = @{}
    $encodedOrigin = $targetOrigin | ConvertTo-Json -Compress
    $expression = "(() => { if (location.origin !== $encodedOrigin) return null; return {origin: location.origin, localStorage: Object.entries(localStorage).map(([name,value]) => ({name,value})), sessionStorage: Object.fromEntries(Object.entries(sessionStorage))}; })()"
    foreach ($tab in (Invoke-Cdp 'Target.getTargets').targetInfos) {
        if ($tab.type -ne 'page') { continue }
        try { $tabOrigin = ([Uri]$tab.url).GetLeftPart([UriPartial]::Authority).ToLowerInvariant() } catch { continue }
        if ($tabOrigin -ne $targetOrigin) { continue }
        $session = (Invoke-Cdp 'Target.attachToTarget' @{targetId=$tab.targetId; flatten=$true}).sessionId
        try {
            $evaluated = Invoke-Cdp 'Runtime.evaluate' @{expression=$expression; returnByValue=$true} $session
            if ($evaluated.exceptionDetails) { throw 'Could not export target browser storage' }
            $value = $evaluated.result.value
            if ($value -and $value.origin -eq $targetOrigin) {
                $origins = @(@{origin=$targetOrigin; localStorage=@($value.localStorage)})
                $sessionStorage[$targetOrigin] = $value.sessionStorage
            }
        } finally { $null = Invoke-Cdp 'Target.detachFromTarget' @{sessionId=$session} }
    }
    if ($origins.Count -eq 0) { throw 'Finish login and return to the target origin before exporting' }
    $document = @{cookies=$cookies; origins=$origins; session_storage=$sessionStorage}
    [IO.File]::WriteAllText($OutputPath, ($document | ConvertTo-Json -Depth 50), [Text.UTF8Encoding]::new($false))
    Write-Host 'Target session exported. Returning to AI-DAST.'
} finally {
    if ($script:socket) {
        try { $null = Invoke-Cdp 'Browser.close' } catch { }
        $script:socket.Dispose()
    }
    if ($chromeProcess -and -not $chromeProcess.HasExited) {
        if (-not $chromeProcess.WaitForExit(5000)) { $chromeProcess.Kill() }
    }
}
