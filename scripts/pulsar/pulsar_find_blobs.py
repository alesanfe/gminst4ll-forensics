#!/usr/bin/env python3
"""
Estrategia C: Extraer la clave AES-GCM estaticamente.
 
El analisis estatico previo confirmo 2 blobs cifrados: 1808B y 736B.
Estructura esperada: nonce(12B) + ciphertext(N-28B) + tag(16B)
 
Este script:
1. Localiza los blobs en el binario por patron (alta entropia, tamanyos exactos)
2. Extrae el US heap (#US) para encontrar strings de config sin cifrar
3. Busca la clave en los .cctor que la inicializan con bytes literales
4. Intenta descifrar AES-GCM con claves candidatas
"""
import dnfile
import struct
import math
import collections
import sys
from pathlib import Path

if len(sys.argv) < 2:
    print("Uso: python3 pulsar_find_blobs.py <archivo>")
    sys.exit(1)

PE = sys.argv[1]
if not Path(PE).exists():
    print(f"Error: Archivo no encontrado: {PE}")
    sys.exit(1)

dn = dnfile.dnPE(PE)
md = dn.net.mdtables
pe_data = open(PE, 'rb').read()

def entropy(data):
    if not data:
        return 0
    c = collections.Counter(data)
    total = len(data)
    return -sum((v/total)*math.log2(v/total) for v in c.values())

def rva_to_offset(rva):
    for s in dn.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + s.Misc_VirtualSize:
            return rva - s.VirtualAddress + s.PointerToRawData
    return None

# ── 1. Buscar blobs por tamano y entropia alta en toda la seccion .text ──────
print("=== 1. BUSCAR BLOBS 1808B y 736B (entropia > 7.5) ===")
TARGET_SIZES = [1808, 736]
STEP = 4  # alineacion
results = []

for start in range(0, len(pe_data) - max(TARGET_SIZES), STEP):
    for sz in TARGET_SIZES:
        chunk = pe_data[start:start+sz]
        e = entropy(chunk)
        if e > 7.5:
            results.append((start, sz, e))

# Agrupar por zona contigua
print(f"  Candidatos (entropia>7.5): {len(results)}")
seen = set()
for off, sz, e in sorted(results, key=lambda x: -x[2])[:20]:
    zone = off // 256
    if zone in seen:
        continue
    seen.add(zone)
    chunk = pe_data[off:off+sz]
    print(f"  offset=0x{off:08X} size={sz} entropy={e:.3f}")
    print(f"    primeros 28B: {chunk[:28].hex()}")
    # nonce(12) + primer byte ciphertext
    nonce = chunk[:12]
    print(f"    nonce(12B): {nonce.hex()}")

# ── 2. Extraer #US heap y buscar strings de config ───────────────────────────
print()
print("=== 2. #US HEAP - STRINGS UTILES (host, ip, puerto, mutex) ===")
us_stream = None
if hasattr(dn.net, 'metadata') and hasattr(dn.net.metadata, 'streams_list'):
    for s in dn.net.metadata.streams_list:
        if hasattr(s, 'name') and s.name == "#US":
            us_stream = s
            break

if us_stream:
    us_off  = us_stream.get_file_offset()
    us_size = us_stream.get_stream_size()
    us_data = pe_data[us_off:us_off+us_size]
    print(f"  #US stream: offset=0x{us_off:08X} size={us_size}")
    
    # Recorrer strings del heap
    pos = 1
    interesting = []
    while pos < len(us_data):
        # Leer longitud (blob encoding)
        b0 = us_data[pos]
        if b0 == 0:
            pos += 1
            continue
        if (b0 & 0x80) == 0:
            length = b0
            pos += 1
        elif (b0 & 0xC0) == 0x80:
            if pos+1 >= len(us_data): break
            length = ((b0 & 0x3F) << 8) | us_data[pos+1]
            pos += 2
        elif (b0 & 0xE0) == 0xC0:
            if pos+3 >= len(us_data): break
            length = ((b0 & 0x1F) << 24) | (us_data[pos+1] << 16) | (us_data[pos+2] << 8) | us_data[pos+3]
            pos += 4
        else:
            pos += 1
            continue
        
        if length <= 0 or length > 8192:
            pos += 1
            continue
        
        str_data = us_data[pos:pos+length]
        pos += length
        
        # Decodificar UTF-16LE
        try:
            s_val = str_data.decode('utf-16-le', errors='ignore').rstrip('\x00').strip()
        except:
            continue
        
        if len(s_val) < 3:
            continue
        
        # Filtrar strings interesantes para C2
        keywords = ['host', 'port', 'mutex', 'key', 'pass', 'connect', 
                    'server', 'tcp', 'ip', '192.', '10.', '172.', 'http',
                    '.com', '.net', '.ru', '.xyz', '.top', 'pulsar',
                    'install', 'startup', 'appdata', 'roaming']
        sl = s_val.lower()
        if any(k in sl for k in keywords) or (s_val.replace('.','').replace(':','').isdigit() and len(s_val) > 5):
            interesting.append(s_val)
            print(f"  [{len(s_val):4d}] {repr(s_val)}")
    
    print(f"\n  Total strings interesantes: {len(interesting)}")
else:
    print("  #US stream no encontrado")
    # Intentar acceso alternativo
    for attr in dir(dn.net.metadata):
        print(f"  metadata attr: {attr}")

# ── 3. Buscar clave AES en strings del heap por tamano (32B = AES-256) ────────
print()
print("=== 3. BUSCAR POSIBLES CLAVES AES (strings de 32 bytes exactos) ===")
if us_stream:
    pos = 1
    while pos < len(us_data):
        b0 = us_data[pos]
        if b0 == 0:
            pos += 1
            continue
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
        
        if length not in (64, 66, 68):  # 32 chars UTF-16 = 64B + 1B terminal
            pos += length
            continue
        
        str_data = us_data[pos:pos+length]
        pos += length
        try:
            s_val = str_data.decode('utf-16-le', errors='ignore').rstrip('\x00')
        except:
            continue
        
        if len(s_val) == 32 and all(c in '0123456789abcdefABCDEF' for c in s_val):
            print(f"  POSIBLE CLAVE HEX 32B: {s_val}")
        elif len(s_val) == 32:
            print(f"  STRING 32B: {repr(s_val)}")

# ── 4. Buscar en #Blob heap blobs de 32B (clave AES-256 raw) ─────────────────
print()
print("=== 4. BLOB HEAP - ENTRADAS DE 32B (candidatos clave AES-256) ===")
blob_stream = None
if hasattr(dn.net, 'metadata') and hasattr(dn.net.metadata, 'streams_list'):
    for s in dn.net.metadata.streams_list:
        if hasattr(s, 'name') and s.name == "#Blob":
            blob_stream = s
            break

if blob_stream:
    blob_off  = blob_stream.get_file_offset()
    blob_size = blob_stream.get_stream_size()
    blob_data = pe_data[blob_off:blob_off+blob_size]
    print(f"  #Blob stream: offset=0x{blob_off:08X} size={blob_size}")
    
    pos = 0
    while pos < len(blob_data):
        b0 = blob_data[pos]
        if (b0 & 0x80) == 0:
            length = b0; pos += 1
        elif (b0 & 0xC0) == 0x80:
            if pos+1 >= len(blob_data): break
            length = ((b0 & 0x3F) << 8) | blob_data[pos+1]; pos += 2
        else:
            pos += 1; continue
        
        if length == 32:
            chunk = blob_data[pos:pos+32]
            e = entropy(chunk)
            if e > 6.0:
                print(f"  offset=0x{blob_off+pos:08X} len=32 entropy={e:.2f}: {chunk.hex()}")
        pos += length
