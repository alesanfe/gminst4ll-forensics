# Busca nonces AES-GCM en appy-cleaned.exe
$ExePath = "C:\malware_samples\beket_extracted\appy-cleaned.exe"

$bytes = [System.IO.File]::ReadAllBytes($ExePath)
$len = $bytes.Length
Write-Host "Tamano: $len bytes"

# Nonces originales
$nonce1 = [byte[]](0xBC, 0xA1, 0xE4, 0x45, 0x34, 0xEB, 0x95, 0x84, 0x94, 0x76, 0x9C, 0x76)
$nonce2 = [byte[]](0xA1, 0x27, 0x33, 0x90, 0x49, 0x22, 0x64, 0xE2, 0x1B, 0xC1, 0xFF, 0x3C)

Write-Host "Buscando nonce1..."
$idx1 = [System.Array]::IndexOf($bytes, $nonce1[0])
if ($idx1 -ge 0) {
    $match = $true
    for ($i = 1; $i -lt 12; $i++) {
        if ($bytes[$idx1 + $i] -ne $nonce1[$i]) { $match = $false; break }
    }
    if ($match) {
        Write-Host "Nonce1 encontrado en offset 0x$($idx1.ToString('X'))"
        # Extraer 1808 bytes después
        $blob = $bytes[$idx1..($idx1+1807)]
        $b64 = [Convert]::ToBase64String($blob)
        Write-Host "BLOB1_B64:$b64"
    }
}

Write-Host "Buscando nonce2..."
$idx2 = [System.Array]::IndexOf($bytes, $nonce2[0])
if ($idx2 -ge 0) {
    $match = $true
    for ($i = 1; $i -lt 12; $i++) {
        if ($bytes[$idx2 + $i] -ne $nonce2[$i]) { $match = $false; break }
    }
    if ($match) {
        Write-Host "Nonce2 encontrado en offset 0x$($idx2.ToString('X'))"
        $blob = $bytes[$idx2..($idx2+735)]
        $b64 = [Convert]::ToBase64String($blob)
        Write-Host "BLOB2_B64:$b64"
    }
}

# Buscar strings de 32 bytes que parezcan claves AES
Write-Host "Buscando claves AES de 32 bytes..."
for ($i = 0; $i -lt $len - 32; $i += 4) {
    $chunk = $bytes[$i..($i+31)]
    # Verificar si todos los bytes son imprimibles o tienen alta entropía
    $printable = 0
    foreach ($b in $chunk) {
        if ($b -ge 32 -and $b -le 126) { $printable++ }
    }
    if ($printable -ge 28) {
        $str = [System.Text.Encoding]::ASCII.GetString($chunk)
        Write-Host "POSSIBLE_KEY:0x$($i.ToString('X')):$str"
    }
}

Write-Host "DONE"
