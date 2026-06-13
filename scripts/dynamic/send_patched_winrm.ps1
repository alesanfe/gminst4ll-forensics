# Enviar appy_patched.exe a la VM usando vagrant winrm (que ya maneja la conexion)
# Se llama desde el host con: vagrant winrm windows -s powershell -c (Get-Content ...)
# En su lugar, usamos python en Ubuntu para enviar via SSH tunel

# Este script se ejecuta DENTRO de la VM Windows para decodificar el B64 guardado en C:\tmp\payload.b64
param([string]$B64File = "C:\tmp\payload.b64", [string]$Out = "C:\malware_samples\beket_extracted\appy_patched.exe")

$dir = Split-Path $Out -Parent
if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
$b64 = Get-Content $B64File -Raw
$bytes = [Convert]::FromBase64String($b64.Trim())
[System.IO.File]::WriteAllBytes($Out, $bytes)
Write-Host "Escrito $($bytes.Length) bytes en $Out"
