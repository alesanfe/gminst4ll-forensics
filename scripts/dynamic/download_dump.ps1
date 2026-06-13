# Lee appy_patched.dmp en chunks B64 y los imprime para capturar
$DumpPath = "C:\malware_samples\dumps\appy_patched.dmp"
$ChunkSz = 500000  # bytes por chunk

$fs = [System.IO.File]::OpenRead($DumpPath)
$len = $fs.Length
Write-Host "SIZE:$len"

$buffer = New-Object byte[] $ChunkSz
$pos = 0
while ($pos -lt $len) {
    $read = $fs.Read($buffer, 0, [Math]::Min($ChunkSz, $len - $pos))
    $chunk = [Convert]::ToBase64String($buffer, 0, $read)
    Write-Host "CHUNK:$pos:$chunk"
    $pos += $read
}
$fs.Close()
Write-Host "DONE"
