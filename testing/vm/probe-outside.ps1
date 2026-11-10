# Run in the guest by guard-checks.ps1: can a TCP connection be made to an address and port within a few seconds?
# Prints OPEN or BLOCKED. A copy of this file is put at C:\lab\probe-outside.ps1.
param([string]$Address = '1.1.1.1', [int]$Port = 443, [int]$Seconds = 6)
$client = New-Object Net.Sockets.TcpClient
try {
    $attempt = $client.BeginConnect($Address, $Port, $null, $null)
    if ($attempt.AsyncWaitHandle.WaitOne($Seconds * 1000) -and $client.Connected) { 'OPEN' } else { 'BLOCKED' }
} catch { 'BLOCKED' } finally { $client.Close() }
