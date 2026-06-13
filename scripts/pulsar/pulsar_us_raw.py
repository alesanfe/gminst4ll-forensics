#!/usr/bin/env python3
"""
Lee el heap #US directamente desde el binario usando pefile puro
y vuelca todos los strings relevantes para C2 config.
Tambien busca IPs, dominios y puertos en todo el binario.
"""
import pefile, re, struct

PE  = "/home/vagrant/beket_extracted2/appy.exe"
pe  = pefile.PE(PE, fast_load=False)
pe.parse_data_directories()
raw = open(PE, 'rb').read()

# ── Localizar el stream #US via la cabecera CLR ──────────────────────────────
# Directorio 14 = COM Descriptor (.NET header)
clr_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
clr_rva  = clr_dir.VirtualAddress
clr_off  = pe.get_offset_from_rva(clr_rva)
# Leer CLR header (cb=4, MajorRuntime=2, MinorRuntime=2, MetaDataRVA=4, MetaDataSize=4, ...)
cb = struct.unpack_from('<I', raw, clr_off)[0]
meta_rva  = struct.unpack_from('<I', raw, clr_off+8)[0]
meta_size = struct.unpack_from('<I', raw, clr_off+12)[0]
meta_off  = pe.get_offset_from_rva(meta_rva)
print(f"CLR header RVA=0x{clr_rva:08X} MetaData RVA=0x{meta_rva:08X} size={meta_size}")
meta      = raw[meta_off:meta_off+meta_size]

# Parsear cabecera Metadata
sig = struct.unpack_from('<I', meta, 0)[0]
assert sig == 0x424A5342, "No es metadata .NET valida"
ver_len = struct.unpack_from('<I', meta, 12)[0]
# Alinear a 4
ver_len = (ver_len + 3) & ~3
off = 16 + ver_len
flags, n_streams = struct.unpack_from('<HH', meta, off)
off += 4

streams = {}
for _ in range(n_streams):
    stream_off  = struct.unpack_from('<I', meta, off)[0]
    stream_size = struct.unpack_from('<I', meta, off+4)[0]
    name_start = off + 8
    name_end   = name_start
    while meta[name_end] != 0:
        name_end += 1
    name = meta[name_start:name_end].decode('ascii', errors='ignore')
    # Alinear
    padded = (name_end - name_start + 1 + 3) & ~3
    off += 8 + padded
    streams[name] = (meta_off + stream_off, stream_size)
    print(f"  Stream: '{name}' offset=0x{meta_off+stream_off:08X} size={stream_size}")

print()

# ── Leer #US heap ─────────────────────────────────────────────────────────────
if '#US' in streams:
    us_off, us_size = streams['#US']
    us_data = raw[us_off:us_off+us_size]
    print(f"=== #US HEAP: {us_size} bytes en 0x{us_off:08X} ===")
    
    pos = 1  # byte 0 siempre es 0x00
    all_strings = []
    while pos < len(us_data):
        b0 = us_data[pos]
        if b0 == 0:
            pos += 1; continue
        if (b0 & 0x80) == 0:
            length = b0; pos += 1
        elif (b0 & 0xC0) == 0x80:
            if pos+1 >= len(us_data): break
            length = ((b0 & 0x3F) << 8) | us_data[pos+1]; pos += 2
        elif (b0 & 0xE0) == 0xC0:
            if pos+3 >= len(us_data): break
            length = ((b0 & 0x1F) << 24) | (us_data[pos+1] << 16) | (us_data[pos+2] << 8) | us_data[pos+3]; pos += 4
        else:
            pos += 1; continue

        if length <= 0 or length > 16384:
            pos += 1; continue

        sdata = us_data[pos:pos+length]
        pos  += length

        try:
            val = sdata.decode('utf-16-le', errors='ignore').rstrip('\x00').strip()
        except:
            continue

        if val:
            all_strings.append(val)

    print(f"  Total strings: {len(all_strings)}")
    print()

    # Filtrar por palabras clave de C2
    c2_kw = ['host', 'port', 'mutex', 'key', 'pass', 'server', 'connect',
              'tcp', 'ssl', 'cert', 'install', 'startup', 'appdata',
              'pulsar', 'version', 'tag', 'id', 'token', 'auth',
              '.com', '.net', '.ru', '.xyz', '.top', '.io', '.cc',
              'http', 'ws://', 'wss://', 'discord', 'telegram']
    
    print("=== STRINGS CON KEYWORDS C2 ===")
    for s in all_strings:
        sl = s.lower()
        if any(k in sl for k in c2_kw):
            print(f"  {repr(s)}")

    print()
    print("=== STRINGS QUE PARECEN IPs O DOMINIOS ===")
    ip_re  = re.compile(r'\b(\d{1,3}\.){3}\d{1,3}\b')
    dom_re = re.compile(r'\b[a-zA-Z0-9\-]{3,}\.(com|net|ru|xyz|top|io|cc|org|me|tk|pw|fun|online)\b')
    for s in all_strings:
        if ip_re.search(s) or dom_re.search(s):
            print(f"  {repr(s)}")

    print()
    print("=== STRINGS DE 32-44 CHARS (posibles hashes/claves/tokens) ===")
    for s in all_strings:
        if 28 <= len(s) <= 60 and not ' ' in s:
            print(f"  [{len(s)}] {repr(s)}")

    print()
    print("=== TODOS LOS STRINGS (primeros 200) ===")
    for s in all_strings[:200]:
        print(f"  {repr(s)}")

# ── Buscar IPs y dominios en el binario crudo (sin parsear) ──────────────────
print()
print("=== BUSQUEDA CRUDA DE IPs EN EL BINARIO ===")
ip_re = re.compile(rb'\b(\d{1,3}\.){3}\d{1,3}\b')
for m in ip_re.finditer(raw):
    ip = m.group().decode()
    parts = list(map(int, ip.split('.')))
    # Excluir IPs no enrutables triviales y 0.x.x.x
    if parts[0] in (0, 127, 169, 224) or parts[0] >= 240:
        continue
    # Excluir las del propio PE (alineacion)
    if ip in ('0.0.0.0', '255.255.255.255', '1.0.0.0', '2.0.0.0'):
        continue
    print(f"  0x{m.start():08X}: {ip}")

print()
print("=== BUSQUEDA CRUDA DE DOMINIOS EN EL BINARIO ===")
dom_re = re.compile(rb'[a-zA-Z0-9\-]{4,50}\.(com|net|ru|xyz|top|io|cc|org|me|tk|pw|fun|online|site|space)')
seen = set()
for m in dom_re.finditer(raw):
    s = m.group().decode('ascii', errors='ignore')
    if s not in seen:
        seen.add(s)
        # Excluir dominios de Microsoft/Windows
        low = s.lower()
        if any(x in low for x in ['microsoft', 'windows', 'nuget', 'github', 'googleapis']):
            continue
        print(f"  0x{m.start():08X}: {s}")
