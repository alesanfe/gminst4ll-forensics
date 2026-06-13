Add-Type -Assembly 'System.IO.Compression.FileSystem'

$fecha = Get-Date -Format 'yyyyMMdd_HHmm'
$src   = 'C:\Users\alex0\Documents\virus'
$dst   = "C:\Users\alex0\Documents\virus_backup_$fecha.zip"

$zip = [System.IO.Compression.ZipFile]::Open($dst, 'Create')

Get-ChildItem $src -Recurse -File | Where-Object {
    $_.FullName -notmatch [regex]::Escape('\.vagrant\') -and
    $_.FullName -notmatch [regex]::Escape('\.idea\')
} | ForEach-Object {
    $rel = $_.FullName.Substring($src.Length + 1)
    [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $_.FullName, $rel) | Out-Null
    Write-Host "  + $rel"
}

$zip.Dispose()
Write-Host ""
Write-Host "Backup creado: $dst"
Write-Host ("Tamano: " + [math]::Round((Get-Item $dst).Length/1MB, 1) + ' MB')
