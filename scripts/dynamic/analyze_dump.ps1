# Analiza appy_patched.dmp para extraer strings C2 descifrados
$DumpPath = "C:\malware_samples\dumps\appy_patched.dmp"

Write-Host "Leyendo dump (251 MB)..."
$bytes = [System.IO.File]::ReadAllBytes($DumpPath)
$len = $bytes.Length
Write-Host "Leidos $len bytes"

# Buscar strings que parezcan IPs (formato x.x.x.x)
Write-Host "Buscando IPs..."
$ip_pattern = [regex]"\b(\d{1,3}\.){3}\d{1,3}\b"
$ips = @()
for ($i = 0; $i -lt $len - 15; $i++) {
    $chunk = [System.Text.Encoding]::ASCII.GetString($bytes, $i, 15)
    if ($ip_pattern.IsMatch($chunk)) {
        $match = $ip_pattern.Match($chunk)
        $ip = $match.Value
        # Excluir IPs no enrutables triviales
        $parts = $ip.Split('.')
        if ($parts[0] -notin @(0,127,169,224,240) -and $ip -ne "0.0.0.0" -and $ip -ne "255.255.255.255") {
            if ($ips -notcontains $ip) {
                $ips += $ip
                Write-Host "IP_ENCONTRADA:$ip:0x$($i.ToString('X'))"
            }
        }
    }
}

# Buscar strings que parezcan dominios
Write-Host "Buscando dominios..."
$dom_pattern = [regex]"\b[a-zA-Z0-9\-]{4,50}\.(com|net|ru|xyz|top|io|cc|org|me|tk|pw|fun|online|site|space)\b"
$doms = @()
for ($i = 0; $i -lt $len - 60; $i++) {
    $chunk = [System.Text.Encoding]::ASCII.GetString($bytes, $i, 60)
    if ($dom_pattern.IsMatch($chunk)) {
        $match = $dom_pattern.Match($chunk)
        $dom = $match.Value
        $low = $dom.ToLower()
        if ($low -notmatch "microsoft|windows|nuget|github|googleapis") {
            if ($doms -notcontains $dom) {
                $doms += $dom
                Write-Host "DOMINIO_ENCONTRADO:$dom:0x$($i.ToString('X'))"
            }
        }
    }
}

# Buscar strings con "host", "port", "server", "connect"
Write-Host "Buscando keywords C2..."
$keywords = @("host", "port", "server", "connect", "tcp", "ssl", "http")
foreach ($kw in $keywords) {
    $kwBytes = [System.Text.Encoding]::UTF8.GetBytes($kw)
    $idx = [System.Array]::IndexOf($bytes, $kwBytes[0])
    while ($idx -ge 0 -and $idx -lt $len - 32) {
        $match = $true
        for ($j = 1; $j -lt $kwBytes.Length; $j++) {
            if ($bytes[$idx + $j] -ne $kwBytes[$j]) { $match = $false; break }
        }
        if ($match) {
            $ctx = [System.Text.Encoding]::ASCII.GetString($bytes, ($idx-32), 64)
            Write-Host "KEYWORD:$kw:0x$($idx.ToString('X')):$ctx"
        }
        $idx = [System.Array]::IndexOf($bytes, $kwBytes[0], $idx + 1)
    }
}

# Buscar strings específicos del malware
Write-Host "Buscando strings específicos del malware..."
$malware_strings = @(
    "Pulsar",
    "FUeRrUAjh9FA",
    "8Ewy4tag9i7dw8n5uVKSL",
    "szgxkqqyqlqtnfcghslo",
    "YGSa8hQFZrbG6u",
    "bRka9Mxr9TWSzm6S22qRIoP0K"
)

foreach ($str in $malware_strings) {
    $strBytes = [System.Text.Encoding]::UTF8.GetBytes($str)
    $idx = [System.Array]::IndexOf($bytes, $strBytes[0])
    while ($idx -ge 0 -and $idx -lt $len - $strBytes.Length) {
        $match = $true
        for ($j = 1; $j -lt $strBytes.Length; $j++) {
            if ($bytes[$idx + $j] -ne $strBytes[$j]) { $match = $false; break }
        }
        if ($match) {
            Write-Host "MALWARE_STRING:$str:0x$($idx.ToString('X'))"
            # Extraer 128 bytes alrededor
            $start = [Math]::Max(0, $idx - 64)
            $end = [Math]::Min($len - 1, $idx + 64)
            $ctx = $bytes[$start..$end]
            $ctx_hex = ($ctx | ForEach-Object { $_.ToString('X2') }) -join ''
            Write-Host "CTX:$ctx_hex"
            break
        }
        $idx = [System.Array]::IndexOf($bytes, $strBytes[0], $idx + 1)
    }
}

# Buscar blobs de 1808 bytes con alta entropía (config principal descifrada)
Write-Host "Buscando blobs de 1808 bytes con alta entropía..."
for ($i = 0; $i -lt $len - 1808; $i += 4096) {
    $blob = $bytes[$i..($i+1807)]
    # Calcular entropía simple (conteo de bytes únicos)
    $unique = ($blob | Group-Object | Measure-Object).Count
    $ratio = $unique / 1808.0
    if ($ratio -gt 0.95) {
        # Alta entropía - podría ser la config descifrada
        Write-Host "HIGH_ENTROPY_BLOB:0x$($i.ToString('X')):ratio=$ratio"
        # Mostrar primeros 64 bytes como hex
        $hex = ($blob[0..63] | ForEach-Object { $_.ToString('X2') }) -join ''
        Write-Host "HEX:$hex"
    }
}

Write-Host "DONE"
Write-Host "Total IPs: $($ips.Count)"
Write-Host "Total dominios: $($doms.Count)"
