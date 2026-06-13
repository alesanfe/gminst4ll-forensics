#!/usr/bin/env python3
"""
Parchea appy.exe en Windows para saltarse el check anti-VM.
Metodo: bRka9Mxr9TWSzm6S22qRIoP0K (RVA=0x0000BB14)
"""
import struct, shutil, os

SRC = r"C:\malware_samples\beket_extracted\appy.exe"
DST = r"C:\malware_samples\beket_extracted\appy_patched.exe"

shutil.copy2(SRC, DST)
raw = bytearray(open(DST, 'rb').read())

def rva_to_off(rva, sections):
    for s in sections:
        va  = s['va']
        vsz = s['vsz']
        raw_off = s['raw']
        if va <= rva < va + vsz:
            return rva - va + raw_off
    return None

# Parsear secciones PE
e_lfanew = struct.unpack_from('<I', raw, 0x3C)[0]
pe_off   = e_lfanew
nsecs    = struct.unpack_from('<H', raw, pe_off + 6)[0]
opt_sz   = struct.unpack_from('<H', raw, pe_off + 20)[0]
sec_off  = pe_off + 24 + opt_sz

sections = []
for i in range(nsecs):
    so  = sec_off + i * 40
    va  = struct.unpack_from('<I', raw, so + 12)[0]
    vsz = struct.unpack_from('<I', raw, so + 8)[0]
    roff= struct.unpack_from('<I', raw, so + 20)[0]
    nm  = raw[so:so+8].rstrip(b'\x00').decode('ascii', errors='ignore')
    sections.append({'name': nm, 'va': va, 'vsz': vsz, 'raw': roff})

ANTIVM_RVA = 0x0000BB14
off = rva_to_off(ANTIVM_RVA, sections)
print(f"bRka9Mxr9TWSzm6S22qRIoP0K RVA=0x{ANTIVM_RVA:08X} -> offset=0x{off:08X}")

hdr = raw[off]
if (hdr & 0x3) == 0x2:
    orig_size = hdr >> 2
    il_start  = off + 1
elif (hdr & 0x3) == 0x3:
    fat = struct.unpack_from('<BBHII', raw, off)
    orig_size = fat[3]
    il_start  = off + 12
else:
    print(f"ERROR: header desconocido 0x{hdr:02X}")
    exit(1)

# Patch: ldc.i4.0 + ret (devuelve false = no VM detectado)
PATCH_IL    = bytes([0x16, 0x2A])
TINY_HDR    = (len(PATCH_IL) << 2) | 0x02

raw[off]   = TINY_HDR
raw[il_start]     = PATCH_IL[0]
raw[il_start + 1] = PATCH_IL[1]
for i in range(2, orig_size):
    raw[il_start + i] = 0x00

# Nop callvirt a antiVM en 0x000011E4
CALLVIRT_OFF = rva_to_off(0x000011E4, sections)
if CALLVIRT_OFF:
    for i in range(5):
        raw[CALLVIRT_OFF + i] = 0x00
    print(f"Noped callvirt en 0x{CALLVIRT_OFF:08X}")

with open(DST, 'wb') as f:
    f.write(raw)

print(f"Patch completado: {DST}")
