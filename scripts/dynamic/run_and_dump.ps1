# Ejecuta appy_patched.exe y hace dump de memoria con ProcDump
$ExePath = "C:\malware_samples\beket_extracted\appy_patched.exe"
$ProcDump = "C:\tools\sysinternals\procdump.exe"
$DumpDir  = "C:\malware_samples\dumps"

if (-not (Test-Path $DumpDir)) { New-Item -ItemType Directory -Path $DumpDir -Force | Out-Null }

Write-Host "Iniciando $ExePath..."
$proc = Start-Process -FilePath $ExePath -PassThru
$pid = $proc.Id
Write-Host "PID: $pid"

# Esperar 4 segundos para que el .cctor termine y la clave AES esté en memoria
Start-Sleep -Seconds 4

Write-Host "Haciendo dump con ProcDump..."
& $ProcDump -ma $pid "$DumpDir\appy_patched.dmp" -accepteula

Write-Host "Dump completado."
# Terminar proceso si sigue vivo
Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
