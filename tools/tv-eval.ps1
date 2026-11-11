# Évalue une expression JavaScript dans l'appli en cours de débogage sur la TV.
# Usage : .\tv-eval.ps1 -Port 45094 -Expr "document.title"
param(
    [Parameter(Mandatory = $true)][int]$Port,
    [Parameter(Mandatory = $true)][string]$Expr
)
$pages = (Invoke-WebRequest "http://127.0.0.1:$Port/json" -UseBasicParsing).Content | ConvertFrom-Json
$url = $pages[0].webSocketDebuggerUrl
$ws = New-Object System.Net.WebSockets.ClientWebSocket
$ct = [System.Threading.CancellationToken]::None
$ws.ConnectAsync([Uri]$url, $ct).Wait()
$msg = @{ id = 1; method = 'Runtime.evaluate'; params = @{ expression = $Expr; returnByValue = $true } } | ConvertTo-Json -Depth 5 -Compress
$bytes = [System.Text.Encoding]::UTF8.GetBytes($msg)
$ws.SendAsync((New-Object System.ArraySegment[byte] -ArgumentList @(, $bytes)), 'Text', $true, $ct).Wait()
$buf = New-Object byte[] 262144
while ($true) {
    $sb = New-Object System.Text.StringBuilder
    do {
        $seg = New-Object System.ArraySegment[byte] -ArgumentList @(, $buf)
        $res = $ws.ReceiveAsync($seg, $ct).Result
        [void]$sb.Append([System.Text.Encoding]::UTF8.GetString($buf, 0, $res.Count))
    } while (-not $res.EndOfMessage)
    $obj = $sb.ToString() | ConvertFrom-Json
    if ($obj.id -eq 1) {
        if ($obj.result.result.value -ne $null) { $obj.result.result.value } else { $sb.ToString() }
        break
    }
}
$ws.Dispose()
