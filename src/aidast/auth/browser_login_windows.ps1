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
$listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
try {
    $listener.Start()
    $debugPort = ([Net.IPEndPoint]$listener.LocalEndpoint).Port
} finally {
    $listener.Stop()
}
$chromeArgs = @("--remote-debugging-port=$debugPort", '--remote-debugging-address=127.0.0.1', "--user-data-dir=`"$profileDir`"",
    '--no-first-run', '--no-default-browser-check', '--no-proxy-server', "`"$TargetUrl`"")
$chromeProcess = $null
$script:socket = $null
$script:messageId = 0
$script:authenticationEndpoints = @{}
$script:identityHeaders = @{}
$script:pendingNetworkEnable = @{}
function ConvertTo-SafeAuthenticationPath([Uri]$RequestUri) {
    $sensitive = @('activate','activation','auth','callback','confirm','invite','magic','magic-link','magic-login','oauth','reset','session','token','verify','verification')
    $knownRoutes = @('account','accounts','activate','activation','admin','api','auth','authenticate','callback','confirm','identity','invite','login','logout','magic','magic-link','magic-login','oauth','password','refresh','reset','rest','session','sessions','sign-in','signin','token','user','users','v1','v2','v3','verify','verification')
    $segments = $RequestUri.AbsolutePath.Split('/')
    $safe = New-Object Collections.Generic.List[string]
    for ($index = 0; $index -lt $segments.Count; $index++) {
        $segment = $segments[$index]
        if (-not $segment) { $safe.Add($segment); continue }
        $decoded = [Uri]::UnescapeDataString($segment)
        $previous = if ($index -gt 0) { $segments[$index - 1].ToLowerInvariant() } else { '' }
        if ($decoded -eq $segment -and $knownRoutes -contains $segment.ToLowerInvariant()) {
            $safe.Add($segment)
            continue
        }
        $dynamic = (
            $sensitive -contains $previous -or
            $decoded -match '^\d+$' -or
            $decoded -match '^[0-9a-fA-F]{8,}$' -or
            $decoded -match '^[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,}$' -or
            ($decoded.Length -ge 16 -and $decoded -match '^[A-Za-z0-9_+=.-]+$' -and
             $decoded -match '[A-Za-z]' -and $decoded -match '\d') -or
            $decoded -ne $segment
        )
        if ($dynamic) { $safe.Add(':secret'); continue }
        return $null
    }
    return ($safe -join '/')
}
function Save-AuthenticationRequest($Parameters) {
    if (-not $Parameters -or -not $Parameters.request) { return }
    try { $requestUri = [Uri]$Parameters.request.url } catch { return }
    if ($requestUri.GetLeftPart([UriPartial]::Authority).ToLowerInvariant() -ne $targetOrigin) { return }
    $requestHeaders = $Parameters.request.headers
    if ($requestHeaders) {
        foreach ($headerName in $requestHeaders.Keys) {
            $normalizedHeader = ([string]$headerName).ToLowerInvariant()
            $headerValue = [string]$requestHeaders[$headerName]
            if ($normalizedHeader -match '(authorization|auth[-_]?token|api[-_]?key|csrf)' -and
                $normalizedHeader -notin @('cookie','set-cookie','proxy-authorization') -and
                $headerValue.Length -le 16384) {
                $script:identityHeaders[[string]$headerName] = $headerValue
            }
        }
    }
    $method = ([string]$Parameters.request.method).ToUpperInvariant()
    if (-not $method -or -not $requestUri.AbsolutePath.StartsWith('/')) { return }
    $path = ConvertTo-SafeAuthenticationPath $requestUri
    if (-not $path) { return }
    $key = "$method`n$targetOrigin`n$path"
    $script:authenticationEndpoints[$key] = @{
        method = $method
        origin = $targetOrigin
        path = $path
        source = 'auth_bootstrap'
    }
}
function Send-Cdp([string]$Method, [hashtable]$Parameters = @{}, [string]$SessionId = '') {
    $script:messageId++
    $id = $script:messageId
    $message = @{id=$id; method=$Method; params=$Parameters}
    if ($SessionId) { $message.sessionId = $SessionId }
    $bytes = [Text.Encoding]::UTF8.GetBytes(($message | ConvertTo-Json -Depth 30 -Compress))
    $segment = New-Object 'ArraySegment[byte]' -ArgumentList (,$bytes)
    $script:socket.SendAsync(
        $segment, [Net.WebSockets.WebSocketMessageType]::Text, $true,
        [Threading.CancellationToken]::None
    ).GetAwaiter().GetResult()
    return $id
}
function Receive-Cdp([Threading.CancellationToken]$CancellationToken) {
    $buffer = New-Object byte[] 65536
    $stream = New-Object IO.MemoryStream
    try {
        do {
            $chunk = $script:socket.ReceiveAsync(
                [ArraySegment[byte]]::new($buffer), $CancellationToken
            ).GetAwaiter().GetResult()
            if ($chunk.MessageType -eq [Net.WebSockets.WebSocketMessageType]::Close) {
                throw 'Chrome closed the session export connection'
            }
            $stream.Write($buffer, 0, $chunk.Count)
            if ($stream.Length -gt 16777216) { throw 'Session export response exceeds limit' }
        } while (-not $chunk.EndOfMessage)
        return [Text.Encoding]::UTF8.GetString($stream.ToArray()) | ConvertFrom-Json
    } finally { $stream.Dispose() }
}
function Start-CdpReceive {
    $buffer = New-Object byte[] 65536
    return @{
        buffer = $buffer
        task = $script:socket.ReceiveAsync(
            [ArraySegment[byte]]::new($buffer), [Threading.CancellationToken]::None
        )
    }
}
function Complete-CdpReceive($Pending) {
    $stream = New-Object IO.MemoryStream
    try {
        $chunk = $Pending.task.GetAwaiter().GetResult()
        while ($true) {
            if ($chunk.MessageType -eq [Net.WebSockets.WebSocketMessageType]::Close) {
                throw 'Chrome closed the session export connection'
            }
            $stream.Write($Pending.buffer, 0, $chunk.Count)
            if ($stream.Length -gt 16777216) { throw 'Session export response exceeds limit' }
            if ($chunk.EndOfMessage) { break }
            $chunk = $script:socket.ReceiveAsync(
                [ArraySegment[byte]]::new($Pending.buffer),
                [Threading.CancellationToken]::None
            ).GetAwaiter().GetResult()
        }
        return [Text.Encoding]::UTF8.GetString($stream.ToArray()) | ConvertFrom-Json
    } finally { $stream.Dispose() }
}
function Handle-CdpEvent($Reply) {
    $replyId = [string]$Reply.id
    if ($Reply.id -and $script:pendingNetworkEnable.ContainsKey($replyId)) {
        $sessionId = $script:pendingNetworkEnable[$replyId]
        $null = $script:pendingNetworkEnable.Remove($replyId)
        if ($Reply.error) { throw 'Chrome Network observer could not be enabled' }
        $null = Send-Cdp 'Runtime.runIfWaitingForDebugger' @{} $sessionId
        return $true
    }
    if ($Reply.method -eq 'Network.requestWillBeSent') {
        Save-AuthenticationRequest $Reply.params
        return $true
    }
    if ($Reply.method -eq 'Target.attachedToTarget') {
        if ($Reply.params.targetInfo.type -eq 'page') {
            $enableId = Send-Cdp 'Network.enable' @{
                maxTotalBufferSize=0; maxResourceBufferSize=0; maxPostDataSize=0
            } $Reply.params.sessionId
            $script:pendingNetworkEnable[[string]$enableId] = $Reply.params.sessionId
        } else {
            $null = Send-Cdp 'Runtime.runIfWaitingForDebugger' @{} $Reply.params.sessionId
        }
        return $true
    }
    return $false
}
function Invoke-Cdp([string]$Method, [hashtable]$Parameters = @{}, [string]$SessionId = '') {
    $cancel = New-Object Threading.CancellationTokenSource
    $cancel.CancelAfter(15000)
    try {
        $id = Send-Cdp $Method $Parameters $SessionId
        while ($true) {
            $reply = Receive-Cdp $cancel.Token
            if (Handle-CdpEvent $reply) { continue }
            if ($reply.id -eq $id) {
                if ($reply.error) { throw "Chrome session export command failed: $Method" }
                return $reply.result
            }
        }
    } finally { $cancel.Dispose() }
}
function Receive-CdpDuringLogin {
    Write-Host 'After completing login, press Enter here to export the target session.'
    $inputTask = [Console]::In.ReadLineAsync()
    $pending = Start-CdpReceive
    while ($true) {
        $winner = [Threading.Tasks.Task]::WhenAny(
            [Threading.Tasks.Task[]]@($inputTask, $pending.task)
        ).GetAwaiter().GetResult()
        if ($winner -eq $pending.task) {
            $reply = Complete-CdpReceive $pending
            $null = Handle-CdpEvent $reply
            $pending = Start-CdpReceive
            continue
        }

        # Wake the uncancelled pending receive, then drain through this command's
        # response. This leaves no concurrent receive before normal export calls.
        $wakeId = Send-Cdp 'Browser.getVersion'
        while ($true) {
            $reply = Complete-CdpReceive $pending
            if (-not (Handle-CdpEvent $reply) -and $reply.id -eq $wakeId) { break }
            $pending = Start-CdpReceive
        }
        break
    }
    $null = $inputTask.GetAwaiter().GetResult()
}
try {
    $chromeProcess = Start-Process -FilePath $chromePath -ArgumentList $chromeArgs -PassThru
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    $version = $null
    while (-not $version) {
        if ([DateTime]::UtcNow -gt $deadline) { throw 'Chrome export connection is unavailable' }
        try {
            $version = Invoke-RestMethod -Uri "http://127.0.0.1:$debugPort/json/version" -TimeoutSec 1
        } catch {
            Start-Sleep -Milliseconds 100
        }
    }
    $browserSocket = [Uri]$version.webSocketDebuggerUrl
    if ($browserSocket.Scheme -ne 'ws' -or $browserSocket.Host -ne '127.0.0.1' -or
        $browserSocket.Port -ne $debugPort -or -not $browserSocket.AbsolutePath.StartsWith('/devtools/browser/')) {
        throw 'Invalid Chrome export endpoint'
    }
    $script:socket = New-Object Net.WebSockets.ClientWebSocket
    $connectCancel = New-Object Threading.CancellationTokenSource
    $connectCancel.CancelAfter(15000)
    try {
        $script:socket.ConnectAsync($browserSocket, $connectCancel.Token).GetAwaiter().GetResult()
    } finally { $connectCancel.Dispose() }
    # Auto-attach passive Network observers before operator interaction so SSO
    # popups and newly opened tabs are covered. Only same-origin auth-like
    # request headers are retained for the private B-session sidecar; no cookies,
    # post data, response bodies, routing, or proxying are enabled.
    $null = Invoke-Cdp 'Target.setDiscoverTargets' @{discover=$true}
    $null = Invoke-Cdp 'Target.setAutoAttach' @{
        autoAttach=$true; waitForDebuggerOnStart=$true; flatten=$true
    }
    Write-Host 'Log in using the Windows Chrome window. Keep the target page open when finished.'
    Receive-CdpDuringLogin
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
    $document = @{
        cookies=$cookies
        origins=$origins
        session_storage=$sessionStorage
        authentication_endpoints=@($script:authenticationEndpoints.Values)
        identity_headers=$script:identityHeaders
    }
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
