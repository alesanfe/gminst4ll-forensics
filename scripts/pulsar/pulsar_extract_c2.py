#!/usr/bin/env python3
"""
Extrae y descifra los blobs AES-GCM del Pulsar RAT.
Blobs encontrados:
  - 0x000B9CC8: 1808B  nonce=bca1e44534eb958494769c76
  - 0x000B9EC8: 1808B  nonce=a87c0a3c01543435d0093b38  (region solapada)
 
El static constructor usa RuntimeHelpers.InitializeArray para cargar
la clave como array de bytes inline en el IL. Buscamos esa secuencia.
"""
import dnfile
import struct
import math
import collections
import sys

PE = "/home/vagrant/beket_extracted2/appy.exe"
dn  = dnfile.dnPE(PE)
md  = dn.net.mdtables
raw = open(PE, 'rb').read()

def entropy(data):
    if not data: return 0
    c = collections.Counter(data)
    t = len(data)
    return -sum((v/t)*math.log2(v/t) for v in c.values())

def rva_to_off(rva):
    for s in dn.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + s.Misc_VirtualSize:
            return rva - s.VirtualAddress + s.PointerToRawData
    return None

# ── Localizar los dos blobs con entropia maxima ───────────────────────────────
print("=== BLOBS CIFRADOS ===")
BLOB_SIZES = [1808, 736]
blobs = {}

for sz in BLOB_SIZES:
    best = (0, 0.0)
    for start in range(0, len(raw)-sz, 4):
        e = entropy(raw[start:start+sz])
        if e > best[1]:
            best = (start, e)
    blobs[sz] = best
    nonce = raw[best[0]:best[0]+12]
    ct    = raw[best[0]+12:best[0]+sz-16]
    tag   = raw[best[0]+sz-16:best[0]+sz]
    print(f"  Blob {sz}B @ 0x{best[0]:08X} (entropy={best[1]:.3f})")
    print(f"    nonce : {nonce.hex()}")
    print(f"    ct[0:16]: {ct[:16].hex()}")
    print(f"    tag   : {tag.hex()}")
    # Guardar para descifrado
    blobs[sz] = {'off': best[0], 'nonce': nonce, 'ct': ct, 'tag': tag, 'full': raw[best[0]:best[0]+sz]}

# ── Buscar la clave: patron newarr byte[] + RuntimeHelpers.InitializeArray ────
print()
print("=== BUSCANDO PATRON DE CLAVE (newarr+InitializeArray) en todos los metodos ===")

def read_il_at(rva):
    off = rva_to_off(rva)
    if off is None: return None, 0
    hdr = raw[off]
    if (hdr & 0x3) == 0x2:
        sz = hdr >> 2
        return raw[off+1:off+1+sz], off+1
    elif (hdr & 0x3) == 0x3:
        fat = struct.unpack_from('<BBHII', raw, off)
        sz  = fat[3]
        return raw[off+12:off+12+sz], off+12
    return None, 0

# Pattern: ldc.i4 N (0x20 XX XX XX XX) + newarr System.Byte (0x8D) + dup (0x25) + ldtoken + call InitializeArray
NEWARR_BYTE_TOKENS = set()
# Primero encontrar el token de newarr System.Byte buscando TypeRef
for rid, row in enumerate(md.TypeRef.rows, 1):
    nm = str(row.TypeName)
    if nm == "Byte":
        NEWARR_BYTE_TOKENS.add(0x01000000 | rid)

key_candidates = []

for mrid, mrow in enumerate(md.MethodDef.rows, 1):
    if mrow.Rva == 0:
        continue
    il, il_off = read_il_at(mrow.Rva)
    if il is None or len(il) < 20:
        continue
    
    i = 0
    while i < len(il) - 15:
        # ldc.i4 con valor 16, 24, 32 (tamanyos clave AES)
        if il[i] == 0x20 and i+4 < len(il):
            key_sz = struct.unpack_from('<i', il, i+1)[0]
            if key_sz in (16, 24, 32):
                # newarr (0x8D) a continuacion
                if i+5 < len(il) and il[i+5] == 0x8D:
                    # dup (0x25) + ldtoken (0xD0)
                    if i+10 < len(il) and il[i+10] == 0x25 or il[i+11] == 0x25:
                        j = i + 5
                        while j < min(i+30, len(il)-5):
                            if il[j] == 0xD0:
                                field_token = struct.unpack_from('<I', il, j+1)[0]
                                field_tbl   = (field_token >> 24) & 0xFF
                                field_rid   = field_token & 0x00FFFFFF
                                if field_tbl == 0x04 and field_rid <= len(md.Field.rows):
                                    fname = str(md.Field.rows[field_rid-1].Name)
                                    print(f"  RID={mrid} off=0x{il_off+i:08X} key_sz={key_sz} field_rid={field_rid} [{fname[:40]}]")
                                    key_candidates.append((mrid, il_off+i, key_sz, field_rid))
                            j += 1
        i += 1

# ── Buscar clave como bytes literales en IL: secuencia de ldc.i4.s seguidos ───
print()
print("=== BUSCANDO CLAVE COMO BYTES LITERALES (secuencias ldc.i4.s de 16/32 bytes) ===")

for mrid, mrow in enumerate(md.MethodDef.rows, 1):
    if mrow.Rva == 0: continue
    il, il_off = read_il_at(mrow.Rva)
    if il is None or len(il) < 64: continue
    
    i = 0
    while i < len(il) - 64:
        # Contar cuantos ldc.i4.s (0x1F XX) consecutivos hay
        if il[i] == 0x1f:
            count = 0
            j = i
            vals = []
            while j < len(il) - 1 and il[j] == 0x1f:
                vals.append(il[j+1])
                j += 2
                count += 1
            if count in (16, 24, 32):
                key_bytes = bytes(vals)
                e = entropy(key_bytes)
                if e > 3.5:
                    mname = str(mrow.Name)
                    print(f"  RID={mrid} ({mname[:20]}) off=0x{il_off+i:08X} count={count} entropy={e:.2f}")
                    print(f"    KEY: {key_bytes.hex()}")
                    key_candidates.append(('literal', il_off+i, count, key_bytes))
        i += 1

# ── Intentar descifrado con claves candidatas + claves conocidas ──────────────
print()
print("=== INTENTANDO DESCIFRADO AES-GCM ===")

try:
    from Crypto.Cipher import AES
    HAS_CRYPTO = True
except ImportError:
    print("  pycryptodome no disponible, instalando...")
    import subprocess
    subprocess.run([sys.executable, '-m', 'pip', 'install', 'pycryptodome', '-q'])
    from Crypto.Cipher import AES
    HAS_CRYPTO = True

# Claves candidatas a probar (hex)
KEY_CANDIDATES_HEX = [
    # Derivadas del string "MDBK" (0x4D42444B) encontrado en .cctor RID=336
    b"MDBK" * 8,                          # 32B repetido
    b"MDBK" * 4,                          # 16B
    # SHA256 de "MDBK"
]

import hashlib
KEY_CANDIDATES_HEX.append(hashlib.sha256(b"MDBK").digest())
KEY_CANDIDATES_HEX.append(hashlib.md5(b"MDBK").digest())
KEY_CANDIDATES_HEX.append(hashlib.sha256(b"PulsarRAT").digest())
KEY_CANDIDATES_HEX.append(hashlib.sha256(b"Pulsar").digest())

# Anadir claves literales encontradas
for item in key_candidates:
    if item[0] == 'literal':
        KEY_CANDIDATES_HEX.append(item[3])

for sz, binfo in blobs.items():
    print(f"\n  --- Blob {sz}B ---")
    nonce = binfo['nonce']
    ct    = binfo['ct']
    tag   = binfo['tag']
    
    for key in KEY_CANDIDATES_HEX:
        if len(key) not in (16, 24, 32):
            continue
        try:
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            pt = cipher.decrypt_and_verify(ct, tag)
            print(f"  *** DESCIFRADO OK con clave {key.hex()} ***")
            print(f"  Primeros 64B: {pt[:64].hex()}")
            print(f"  Como string: {pt[:128].decode('utf-8', errors='replace')}")
            # Guardar
            with open(f"/tmp/pulsar_decrypted_{sz}.bin", 'wb') as f:
                f.write(pt)
            print(f"  Guardado: /tmp/pulsar_decrypted_{sz}.bin")
        except Exception:
            pass

print()
print("=== RESUMEN ===")
print(f"  Blobs encontrados: {len(blobs)}")
print(f"  Claves candidatas probadas: {len(KEY_CANDIDATES_HEX)}")
print(f"  Claves literales en IL: {sum(1 for x in key_candidates if x[0]=='literal')}")
