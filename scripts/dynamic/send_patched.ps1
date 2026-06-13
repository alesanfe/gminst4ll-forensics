# Transfiere appy_patched.exe desde el host a la VM Windows via WinRM Base64
param(
    [string]$LocalPath = "C:\Users\alex0\Documents\virus\appy_patched.exe",
    [string]$RemotePath = "C:\malware_samples\beket_extracted\appy_patched.exe"
)

$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
$cred = New-Object System.Management.Automation.PSCredential(
    "vagrant",
    (ConvertTo-SecureString "vagrant" -AsPlainText -Force)
)
$s = New-PSSession -ComputerName 127.0.0.1 -Port 55985 -Credential $cred `
     -SessionOption $so -Authentication Basic

$bytes  = [System.IO.File]::ReadAllBytes($LocalPath)
$b64    = [Convert]::ToBase64String($bytes)
$chunkSz = 500000

Write-Host "Enviando $($bytes.Length) bytes en chunks de $chunkSz..."

Invoke-Command -Session $s -ScriptBlock {
    param($path) 
    $dir = Split-Path $path -Parent
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    if (Test-Path $path) { Remove-Item $path -Force }
    [System.IO.File]::WriteAllBytes($path, [byte[]]@())
} -ArgumentList $RemotePath

for ($i = 0; $i -lt $b64.Length; $i += $chunkSz) {
    $chunk = $b64.Substring($i, [Math]::Min($chunkSz, $b64.Length - $i))
    Invoke-Command -Session $s -ScriptBlock {
        param($path, $chunk)
        $bytes = [Convert]::FromBase64String($chunk)
        $fs = [System.IO.File]::OpenWrite($path)
        $fs.Seek(0, [System.IO.SeekOrigin]::End) | Out-Null
        $fs.Write($bytes, 0, $bytes.Length)
        $fs.Close()
    } -ArgumentList $RemotePath, $chunk
    Write-Host "  Chunk $([Math]::Floor($i/$chunkSz)+1) enviado"
}

$remoteSize = Invoke-Command -Session $s -ScriptBlock {
    param($path) (Get-Item $path).Length
} -ArgumentList $RemotePath

Write-Host "Transferencia completada. Tamano remoto: $remoteSize bytes (local: $($bytes.Length))"
Remove-PSSession $s
