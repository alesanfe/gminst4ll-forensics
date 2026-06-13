#!/usr/bin/env python3
"""
Parchea appy.exe para saltarse el check anti-VM.
 
Metodo objetivo: bRka9Mxr9TWSzm6S22qRIoP0K
  RID=511, RVA=0x0000BB14, Flags=0x0086 (static, private)
 
Estrategia: sustituir el cuerpo IL por "ldc.i4.0 / ret" (tiny header).
  - Si la funcion devuelve bool: ldc.i4.0 (0x16) + ret (0x2A) = tiny header 0x0A
  - Si devuelve void: ret (0x2A) solo = tiny header 0x0A
 
La firma del metodo es privada estatica; por el contexto anti-VM
probablemente devuelve bool o void. Probamos con ret solo primero
y si el ensamblado no valida, usamos ldc.i4.0 + ret.
"""
import struct, shutil, os

SRC  = "/home/vagrant/beket_extracted2/appy.exe"
DST  = "/home/vagrant/beket_extracted2/appy_patched.exe"

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

# Parsear secciones PE manualmente
e_lfanew = struct.unpack_from('<I', raw, 0x3C)[0]
pe_off   = e_lfanew
opt_off  = pe_off + 24
magic    = struct.unpack_from('<H', raw, opt_off)[0]
nsecs    = struct.unpack_from('<H', raw, pe_off + 6)[0]
opt_sz   = struct.unpack_from('<H', raw, pe_off + 20)[0]
sec_off  = opt_off + opt_sz

sections = []
for i in range(nsecs):
    so  = sec_off + i * 40
    va  = struct.unpack_from('<I', raw, so + 12)[0]
    vsz = struct.unpack_from('<I', raw, so + 8)[0]
    roff= struct.unpack_from('<I', raw, so + 20)[0]
    nm  = raw[so:so+8].rstrip(b'\x00').decode('ascii', errors='ignore')
    sections.append({'name': nm, 'va': va, 'vsz': vsz, 'raw': roff})
    print(f"  Section {nm}: VA=0x{va:08X} VSZ=0x{vsz:08X} Raw=0x{roff:08X}")

# RVA del metodo anti-VM
ANTIVM_RVA = 0x0000BB14
off = rva_to_off(ANTIVM_RVA, sections)
print(f"\nbRka9Mxr9TWSzm6S22qRIoP0K RVA=0x{ANTIVM_RVA:08X} -> file offset=0x{off:08X}")

# Leer cabecera IL actual
hdr = raw[off]
print(f"IL header byte: 0x{hdr:02X}")

if (hdr & 0x3) == 0x2:
    # Tiny header: bits 7:2 = code size
    orig_size = hdr >> 2
    il_start  = off + 1
    print(f"Tiny header, original IL size = {orig_size} bytes")
    print(f"IL original: {bytes(raw[il_start:il_start+orig_size]).hex()}")
elif (hdr & 0x3) == 0x3:
    # Fat header
    fat = struct.unpack_from('<BBHII', raw, off)
    orig_size = fat[3]
    il_start  = off + 12
    print(f"Fat header, original IL size = {orig_size} bytes")
    print(f"IL original (primeros 32B): {bytes(raw[il_start:il_start+min(32,orig_size)]).hex()}")
else:
    print(f"ERROR: formato de cabecera desconocido: 0x{hdr:02X}")
    exit(1)

# Determinar tipo de retorno por la firma (Signature del MethodDef)
# Basado en el analisis previo: el metodo tiene Flags=0x0086 (SpecialName|HideBySig|Private|Static)
# Los checks anti-VM tipicamente devuelven bool (true=detectado) o void
# Miramos los primeros bytes del IL original para inferir:
il_orig = bytes(raw[il_start:il_start+min(orig_size, 64)])

# Si el IL original termina con ret (0x2A) y tiene ldc.i4.1 (0x17) antes -> devuelve bool
# Patch: sustituir todo por ldc.i4.0 + ret (devolver false = no detectado)
# Tiny header para 2 bytes: 0x0A = (2 << 2) | 0x02

PATCH_IL    = bytes([0x16, 0x2A])  # ldc.i4.0 + ret -> devuelve false
TINY_HDR    = (len(PATCH_IL) << 2) | 0x02  # 0x0A

print(f"\nPatch IL: {PATCH_IL.hex()} (ldc.i4.0 + ret)")
print(f"Tiny header byte: 0x{TINY_HDR:02X}")

# Escribir el patch: sustituir el header y los primeros bytes del IL
# El header ocupa 1B (tiny) o 12B (fat); rellenamos el resto con nop (0x00)
if (hdr & 0x3) == 0x2:
    # Tiny: sobreescribir header + IL (total = 1 + orig_size bytes disponibles)
    raw[off] = TINY_HDR
    raw[il_start]     = PATCH_IL[0]  # ldc.i4.0
    raw[il_start + 1] = PATCH_IL[1]  # ret
    # Rellenar resto con nop para mantener tamano
    for i in range(2, orig_size):
        raw[il_start + i] = 0x00
elif (hdr & 0x3) == 0x3:
    # Fat header: convertir a tiny reescribiendo header + IL
    # Necesitamos que el espacio sea suficiente (fat = 12B header, nosotros solo necesitamos 3B total)
    # Sobreescribir los 12 bytes del fat header y el IL con el tiny patch
    # Primero verificar que podemos hacerlo sin romper alineacion
    raw[off]   = TINY_HDR
    raw[off+1] = PATCH_IL[0]
    raw[off+2] = PATCH_IL[1]
    # Rellenar fat header restante + IL original con nops
    for i in range(3, 12 + orig_size):
        raw[off + i] = 0x00

with open(DST, 'wb') as f:
    f.write(raw)

print(f"\nPatch escrito en {DST}")
print(f"Verificando patch...")

# Verificar
raw2 = open(DST, 'rb').read()
hdr2 = raw2[off]
print(f"  Header byte post-patch: 0x{hdr2:02X}")
il2 = raw2[off+1:off+3]
print(f"  IL post-patch: {il2.hex()}")

if hdr2 == TINY_HDR and il2 == PATCH_IL:
    print("  OK - Patch aplicado correctamente")
else:
    print("  ERROR - Patch no aplicado")
    exit(1)

# ── Segundo patch: metodo .cctor de YGSa8hQFZrbG6u si existe check ────────────
# El .cctor RID del namespace del antiVM es el que llama a bRka9Mx...
# Encontrar si hay algun .cctor que llame a este metodo y parchear el call por nop*5
# (esto es opcional, el primer patch deberia ser suficiente)

print()
print("=== Buscando calls al metodo anti-VM en otros .cctor ===")
# Token de bRka9Mxr9TWSzm6S22qRIoP0K = 0x060001FF (RID=511, tabla MethodDef=0x06)
ANTIVM_TOKEN = struct.pack('<I', (0x06 << 24) | 511)
# call = 0x28 + token
CALL_ANTIVM = bytes([0x28]) + ANTIVM_TOKEN
# callvirt = 0x6F + token
CALLVIRT_ANTIVM = bytes([0x6F]) + ANTIVM_TOKEN

for pattern, name in [(CALL_ANTIVM, 'call'), (CALLVIRT_ANTIVM, 'callvirt')]:
    pos = 0
    while True:
        idx = raw2.find(pattern, pos)
        if idx == -1:
            break
        print(f"  Encontrado {name} a antiVM en offset 0x{idx:08X}")
        # Nopear los 5 bytes del call
        raw_patch = bytearray(raw2)
        for i in range(5):
            raw_patch[idx + i] = 0x00
        with open(DST, 'wb') as f:
            f.write(raw_patch)
        print(f"  Noped 5 bytes en 0x{idx:08X}")
        pos = idx + 5

print()
print(f"Patch final guardado en {DST}")
print("Listo para ejecutar en VM Windows.")
