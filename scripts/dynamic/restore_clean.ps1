# restore_clean.ps1 - Revertir VM Windows al snapshot clean_state
# Ejecutar desde el HOST despues de cada analisis dinamico

$vboxManage = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
$vmName     = "virus_windows_1781204143362_4051"
$snapshot   = "clean_state"

Write-Host "=== Restaurando snapshot '$snapshot' ==="

# 1. Apagar VM si esta corriendo
$running = & $vboxManage list runningvms | Select-String $vmName
if ($running) {
    Write-Host "Apagando VM..."
    & $vboxManage controlvm $vmName poweroff
    Start-Sleep -Seconds 5
}

# 2. Restaurar snapshot
Write-Host "Restaurando snapshot..."
& $vboxManage snapshot $vmName restore $snapshot

# 3. Arrancar VM
Write-Host "Arrancando VM..."
& $vboxManage startvm $vmName --type headless

# 4. Esperar WinRM
Write-Host "Esperando WinRM (60s)..."
Start-Sleep -Seconds 60

# 5. Verificar firewall
$fw = vagrant winrm windows -c "netsh advfirewall show allprofiles | findstr BlockOutbound" 2>$null
if ($fw -match "BlockOutbound") {
    Write-Host "Firewall OK - BlockOutbound activo"
} else {
    Write-Host "ADVERTENCIA: Verificar firewall manualmente"
}

Write-Host ""
Write-Host "VM restaurada a estado limpio. Lista para siguiente analisis."
