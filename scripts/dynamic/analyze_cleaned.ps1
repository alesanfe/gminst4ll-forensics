# Analiza appy-cleaned.exe para extraer strings C2 después de de4dot
$ExePath = "C:\malware_samples\beket_extracted\appy-cleaned.exe"

Write-Host "Leyendo strings del binario desofuscado..."
$bytes = [System.IO.File]::ReadAllBytes($ExePath)
$len = $bytes.Length
Write-Host "Tamano: $len bytes"

# Buscar strings ASCII imprimibles
$strings = @()
for ($i = 0; $i -lt $len - 4; $i++) {
    if ($bytes[$i] -ge 32 -and $bytes[$i] -le 126) {
        $str = ""
        $j = $i
        while ($j -lt $len -and $bytes[$j] -ge 32 -and $bytes[$j] -le 126) {
            $str += [char]$bytes[$j]
            $j++
        }
        if ($str.Length -ge 4) {
            $strings += $str
        }
        $i = $j
    }
}

Write-Host "Total strings encontrados: $($strings.Count)"

# Filtrar strings que parezcan C2
$c2_keywords = @("http", "https", "tcp", "ssl", "host", "port", "server", "connect", "domain", "ip", "key", "password", "token", "auth")
$c2_strings = @()
foreach ($str in $strings) {
    $low = $str.ToLower()
    foreach ($kw in $c2_keywords) {
        if ($low -match $kw -and $low -notmatch "microsoft|windows|nuget|github|googleapis|system") {
            if ($c2_strings -notcontains $str) {
                $c2_strings += $str
                Write-Host "C2_STRING:$str"
            }
            break
        }
    }
}

# Buscar IPs
$ip_pattern = [regex]"\b(\d{1,3}\.){3}\d{1,3}\b"
$ips = @()
foreach ($str in $strings) {
    if ($ip_pattern.IsMatch($str)) {
        $ip = $ip_pattern.Match($str).Value
        $parts = $ip.Split('.')
        if ($parts[0] -notin @(0,127,169,224,240) -and $ip -ne "0.0.0.0" -and $ip -ne "255.255.255.255") {
            if ($ips -notcontains $ip) {
                $ips += $ip
                Write-Host "IP:$ip"
            }
        }
    }
}

# Buscar dominios
$dom_pattern = [regex]"\b[a-zA-Z0-9\-]{4,50}\.(com|net|ru|xyz|top|io|cc|org|me|tk|pw|fun|online|site|space)\b"
$doms = @()
foreach ($str in $strings) {
    if ($dom_pattern.IsMatch($str)) {
        $dom = $dom_pattern.Match($str).Value
        $low = $dom.ToLower()
        if ($low -notmatch "microsoft|windows|nuget|github|googleapis") {
            if ($doms -notcontains $dom) {
                $doms += $dom
                Write-Host "DOMAIN:$dom"
            }
        }
    }
}

Write-Host "DONE"
Write-Host "Total C2 strings: $($c2_strings.Count)"
Write-Host "Total IPs: $($ips.Count)"
Write-Host "Total dominios: $($doms.Count)"
