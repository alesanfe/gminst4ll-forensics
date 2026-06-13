$events = Get-WinEvent -LogName Application -MaxEvents 50 -ErrorAction SilentlyContinue
$crash  = $events | Where-Object { $_.Id -in @(1000,1026,1001) }
foreach ($e in $crash) {
    Write-Host "--- EventID: $($e.Id) | $($e.TimeCreated) ---"
    Write-Host $e.Message
    Write-Host ""
}

Write-Host "=== PCAP size ==="
$pcap = "C:\malware_reports\20260612_083825\capture.pcap"
if (Test-Path $pcap) {
    Write-Host ("PCAP: " + [math]::Round((Get-Item $pcap).Length/1KB,1) + " KB")
} else {
    Write-Host "No PCAP encontrado"
}

Write-Host "=== netstat_after.txt (conexiones) ==="
Get-Content "C:\malware_reports\20260612_083825\netstat_after.txt" -ErrorAction SilentlyContinue

Write-Host "=== Diferencias en registro Run ==="
$before = Get-Content "C:\malware_reports\20260612_083825\reg_run_before.reg" -ErrorAction SilentlyContinue
$after  = Get-Content "C:\malware_reports\20260612_083825\reg_run_after.reg" -ErrorAction SilentlyContinue
Compare-Object $before $after | Format-Table -AutoSize

Write-Host "=== Diferencias en registro Run (usuario) ==="
$ubefore = Get-Content "C:\malware_reports\20260612_083825\reg_run_user_before.reg" -ErrorAction SilentlyContinue
$uafter  = Get-Content "C:\malware_reports\20260612_083825\reg_run_user_after.reg" -ErrorAction SilentlyContinue
Compare-Object $ubefore $uafter | Format-Table -AutoSize
