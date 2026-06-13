# dynamic_analysis.ps1 - Protocolo de analisis dinamico
# Uso: llamar desde el host via vagrant winrm
# Parametros: $Sample (nombre muestra), $RunSeconds (tiempo de ejecucion)
param(
    [string]$Sample = "C:\malware_samples\beket_extracted\appy.exe",
    [int]$RunSeconds = 120
)

$ts     = Get-Date -Format 'yyyyMMdd_HHmmss'
$outDir = "C:\malware_reports\$ts"
New-Item -ItemType Directory $outDir -Force | Out-Null

Write-Host "=== PRE-EJECUCION ==="
Write-Host "Muestra : $Sample"
Write-Host "Directorio salida: $outDir"

# --- Verificar firewall ---
$fw = netsh advfirewall show allprofiles | Select-String "BlockOutbound"
if (-not $fw) {
    Write-Host "ERROR: Firewall NO bloqueado. Abortando."
    exit 1
}
Write-Host "Firewall : BlockInbound,BlockOutbound OK"

# --- Hashes previos ---
$hash = Get-FileHash $Sample -Algorithm SHA256
"SHA256: $($hash.Hash)" | Out-File "$outDir\hash.txt"
Write-Host "SHA256   : $($hash.Hash)"

# --- Snapshot de registro antes ---
Write-Host "Capturando estado registro (Run/RunOnce)..."
reg export "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"     "$outDir\reg_run_before.reg"    /y 2>$null
reg export "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"     "$outDir\reg_run_user_before.reg" /y 2>$null
reg export "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" "$outDir\reg_runonce_before.reg" /y 2>$null

# --- Lista de procesos antes ---
Get-Process | Select-Object Id,Name,Path | Export-Csv "$outDir\procs_before.csv" -NoTypeInformation

# --- Lista de conexiones antes ---
netstat -anob 2>$null | Out-File "$outDir\netstat_before.txt"

# --- Lista de servicios antes ---
Get-Service | Export-Csv "$outDir\services_before.csv" -NoTypeInformation

# --- Lista de tareas programadas antes ---
schtasks /query /fo CSV /v 2>$null | Out-File "$outDir\tasks_before.csv"

# --- Lista de archivos en directorios de persistencia antes ---
$persistDirs = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:APPDATA\Roaming",
    "C:\ProgramData"
)
foreach ($d in $persistDirs) {
    if (Test-Path $d) {
        Get-ChildItem $d -Recurse -ErrorAction SilentlyContinue |
            Select-Object FullName,Length,LastWriteTime |
            Export-Csv "$outDir\files_before_$(Split-Path $d -Leaf).csv" -NoTypeInformation
    }
}

Write-Host ""
Write-Host "=== EJECUCION (${RunSeconds}s) ==="

# Iniciar Sysmon log flush
wevtutil cl "Microsoft-Windows-Sysmon/Operational" 2>$null

# Iniciar captura de red con tshark si Wireshark instalado
$tshark = "C:\Program Files\Wireshark\tshark.exe"
$pcapJob = $null
if (Test-Path $tshark) {
    Write-Host "Iniciando captura de red..."
    $pcapJob = Start-Process -FilePath $tshark `
        -ArgumentList "-i 1 -w `"$outDir\capture.pcap`"" `
        -PassThru -WindowStyle Hidden
}

# EJECUTAR MUESTRA
Write-Host "Ejecutando: $Sample"
$proc = Start-Process -FilePath $Sample -PassThru -WindowStyle Normal
Write-Host "PID: $($proc.Id)"
"PID: $($proc.Id)" | Out-File "$outDir\pid.txt"

# Esperar y monitorizar
Start-Sleep -Seconds $RunSeconds

# Matar proceso si sigue corriendo
if (-not $proc.HasExited) {
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    Write-Host "Proceso terminado (timeout)"
} else {
    Write-Host "Proceso termino solo (exit: $($proc.ExitCode))"
}

# Detener captura
if ($pcapJob -and -not $pcapJob.HasExited) {
    Stop-Process -Id $pcapJob.Id -Force -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "=== POST-EJECUCION ==="

# --- Estado de procesos despues ---
Get-Process | Select-Object Id,Name,Path | Export-Csv "$outDir\procs_after.csv" -NoTypeInformation

# --- Conexiones despues ---
netstat -anob 2>$null | Out-File "$outDir\netstat_after.txt"

# --- Servicios despues ---
Get-Service | Export-Csv "$outDir\services_after.csv" -NoTypeInformation

# --- Tareas programadas despues ---
schtasks /query /fo CSV /v 2>$null | Out-File "$outDir\tasks_after.csv"

# --- Registro despues ---
reg export "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"     "$outDir\reg_run_after.reg"    /y 2>$null
reg export "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"     "$outDir\reg_run_user_after.reg" /y 2>$null
reg export "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" "$outDir\reg_runonce_after.reg" /y 2>$null

# --- Archivos nuevos en directorios clave ---
foreach ($d in $persistDirs) {
    if (Test-Path $d) {
        Get-ChildItem $d -Recurse -ErrorAction SilentlyContinue |
            Select-Object FullName,Length,LastWriteTime |
            Export-Csv "$outDir\files_after_$(Split-Path $d -Leaf).csv" -NoTypeInformation
    }
}

# --- Archivos nuevos en %TEMP% y %APPDATA% ---
Get-ChildItem "$env:TEMP","$env:APPDATA" -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -gt (Get-Date).AddSeconds(-($RunSeconds + 30)) } |
    Select-Object FullName,Length,LastWriteTime |
    Export-Csv "$outDir\new_files_temp_appdata.csv" -NoTypeInformation

# --- Logs de Sysmon ---
wevtutil qe "Microsoft-Windows-Sysmon/Operational" /f:Text /rd:true 2>$null |
    Out-File "$outDir\sysmon_events.txt"

# --- Event log de seguridad (ultimos 200 eventos) ---
Get-WinEvent -LogName Security -MaxEvents 200 -ErrorAction SilentlyContinue |
    Select-Object TimeCreated,Id,Message |
    Export-Csv "$outDir\security_events.csv" -NoTypeInformation

Write-Host "Informe guardado en: $outDir"
Write-Host ""
Write-Host "=== RESUMEN RAPIDO ==="

# Diferencias en procesos
$before = Import-Csv "$outDir\procs_before.csv"
$after  = Import-Csv "$outDir\procs_after.csv"
$newProcs = $after | Where-Object { $before.Id -notcontains $_.Id }
Write-Host "Procesos nuevos: $($newProcs.Count)"
$newProcs | ForEach-Object { Write-Host "  PID $($_.Id): $($_.Name) - $($_.Path)" }

# Diferencias en servicios
$svcBefore = Import-Csv "$outDir\services_before.csv"
$svcAfter  = Import-Csv "$outDir\services_after.csv"
$newSvcs = $svcAfter | Where-Object { $svcBefore.Name -notcontains $_.Name }
Write-Host "Servicios nuevos: $($newSvcs.Count)"
$newSvcs | ForEach-Object { Write-Host "  $($_.Name): $($_.Status)" }

# Archivos nuevos
$newFiles = Import-Csv "$outDir\new_files_temp_appdata.csv"
Write-Host "Archivos nuevos en TEMP/APPDATA: $($newFiles.Count)"
$newFiles | Select-Object -First 20 | ForEach-Object { Write-Host "  $($_.FullName)" }

# PCAP
if (Test-Path "$outDir\capture.pcap") {
    $pcapSize = [math]::Round((Get-Item "$outDir\capture.pcap").Length/1KB, 1)
    Write-Host "PCAP capturado: $pcapSize KB"
}

Write-Host ""
Write-Host "IMPORTANTE: Revertir snapshot 'clean_state' desde el host antes de siguiente analisis"
