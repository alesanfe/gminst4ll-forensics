#!/usr/bin/env python3
"""
Traza la asignacion de Field[1497] (EncryptionKey) y Field[1500] (Signature/base64).
Busca el metodo que hace stsfld a esos campos y extrae los valores.
Tambien extrae todos los ldstr que se usan en el .cctor principal del RAT.
"""
import dnfile, struct, hashlib

PE  = "/home/vagrant/beket_extracted2/appy.exe"
dn  = dnfile.dnPE(PE)
md  = dn.net.mdtables
raw = open(PE, 'rb').read()

def rva_to_off(rva):
    for s in dn.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + s.Misc_VirtualSize:
            return rva - s.VirtualAddress + s.PointerToRawData
    return None

def read_il(rva):
    off = rva_to_off(rva)
    if off is None: return None, 0
    hdr = raw[off]
    if (hdr & 0x3) == 0x2:
        sz = hdr >> 2; return raw[off+1:off+1+sz], off+1
    elif (hdr & 0x3) == 0x3:
        fat = struct.unpack_from('<BBHII', raw, off)
        return raw[off+12:off+12+fat[3]], off+12
    return None, 0

# Leer string del heap #Strings
def get_us_string(token):
    """Leer string del heap #US dado un token ldstr (0x70XXXXXX)"""
    heap_idx = token & 0x00FFFFFF
    # Encontrar el stream #US
    for s in dn.net.metadata.streams_list:
        sname = s.name if hasattr(s, 'name') else ''
        if sname == '#US' or sname == b'#US':
            off  = s.get_file_offset()
            size = s.get_stream_size()
            us   = raw[off:off+size]
            if heap_idx >= size: return None
            # Leer longitud BlobEncoding
            b0 = us[heap_idx]
            if (b0 & 0x80) == 0:
                length = b0; data_start = heap_idx + 1
            elif (b0 & 0xC0) == 0x80:
                length = ((b0 & 0x3F) << 8) | us[heap_idx+1]; data_start = heap_idx + 2
            else:
                length = ((b0 & 0x1F) << 24) | (us[heap_idx+1] << 16) | (us[heap_idx+2] << 8) | us[heap_idx+3]
                data_start = heap_idx + 4
            data = us[data_start:data_start+length]
            try:
                return data.decode('utf-16-le', errors='ignore').rstrip('\x00')
            except:
                return data.hex()
    return None

# Targets: campos de interes
FIELD_TARGETS = {
    1497: "FUeRrUAjh9FA (EncryptionKey)",
    1498: "sfRGNA2Id1TUuxp (Tag)",
    1500: "L6kE5zXkE8 (Signature/b64)",
    1484: "YybLbFwp55XUiIKTeq (Version)",
    # Campos del .cctor RID=1388 que gestiona config:
    1484+11: "posible host/ip",
}
# Anadir campos de la config del cctor 1388
for i in range(0xCC, 0xEC):
    FIELD_TARGETS[0x400 + i] = f"config_field_0x{i:02X}"

print("=== BUSCANDO stsfld A CAMPOS CLAVE ===")
results = {}

for mrid, mrow in enumerate(md.MethodDef.rows, 1):
    if mrow.Rva == 0: continue
    il, il_off = read_il(mrow.Rva)
    if il is None or len(il) < 5: continue

    i = 0
    pending_str = None  # ultimo ldstr visto
    pending_val = None  # ultimo valor literal

    while i < len(il) - 4:
        op = il[i]

        # ldstr
        if op == 0x72:
            token = struct.unpack_from('<I', il, i+1)[0]
            s = get_us_string(token & 0x00FFFFFF)
            pending_str = s
            i += 5; continue

        # ldc.i4
        elif op == 0x20:
            pending_val = struct.unpack_from('<i', il, i+1)[0]
            i += 5; continue

        # ldc.i4.s
        elif op == 0x1f:
            pending_val = struct.unpack_from('<b', il, i+1)[0]
            i += 2; continue

        # ldc.i4.X (0x16..0x1e)
        elif 0x14 <= op <= 0x1e:
            pending_val = op - 0x16
            i += 1; continue

        # stsfld
        elif op == 0x80:
            token = struct.unpack_from('<I', il, i+1)[0]
            frid = token & 0x00FFFFFF
            ftbl = (token >> 24) & 0xFF
            if ftbl == 0x04 and frid in FIELD_TARGETS:
                fname = FIELD_TARGETS[frid]
                val = pending_str if pending_str is not None else pending_val
                print(f"  Method[{mrid}] stsfld Field[{frid}] ({fname})")
                print(f"    = {repr(val)}")
                results[frid] = val
            pending_str = None
            pending_val = None
            i += 5; continue

        else:
            # Reset pending en otros opcodes que modifican la pila
            if op not in (0x25, 0x17, 0x16, 0x1f, 0x20, 0x72):
                pending_str = None
                pending_val = None
            i += 1

print()
print("=== EXTRAER TODAS LAS STRINGS DEL .cctor PRINCIPAL (RID=1388) ===")
mrow = md.MethodDef.rows[1387]  # RID=1388
il, il_off = read_il(mrow.Rva)
if il:
    i = 0
    while i < len(il) - 4:
        op = il[i]
        if op == 0x72:
            token = struct.unpack_from('<I', il, i+1)[0]
            s = get_us_string(token & 0x00FFFFFF)
            if s and len(s) > 2:
                print(f"  ldstr[0x{token&0xFFFFFF:06X}] = {repr(s)}")
            i += 5
        else:
            i += 1

print()
print("=== EXTRAER TODAS LAS STRINGS DEL .cctor RID=336 ===")
mrow336 = md.MethodDef.rows[335]
il336, il_off336 = read_il(mrow336.Rva)
if il336:
    i = 0
    while i < len(il336) - 4:
        op = il336[i]
        if op == 0x72:
            token = struct.unpack_from('<I', il336, i+1)[0]
            s = get_us_string(token & 0x00FFFFFF)
            if s and len(s) > 2:
                print(f"  ldstr[0x{token&0xFFFFFF:06X}] = {repr(s)}")
            i += 5
        else:
            i += 1

print()
print("=== BUSCAR stsfld Field[1497] EN TODOS LOS METODOS (scan amplio) ===")
TARGET_TOKEN = (0x04 << 24) | 1497
for mrid, mrow in enumerate(md.MethodDef.rows, 1):
    if mrow.Rva == 0: continue
    il, il_off = read_il(mrow.Rva)
    if il is None: continue
    il_hex = il.hex()
    # stsfld = 0x80, token little-endian de Field[1497] = 0xE9050004
    needle = bytes([0x80]) + struct.pack('<I', TARGET_TOKEN)
    if needle in il:
        pos = il.index(needle)
        ctx_start = max(0, pos-40)
        print(f"  Method[{mrid}] RVA=0x{mrow.Rva:08X} offset_in_IL={pos}")
        print(f"    contexto IL: {il[ctx_start:pos+5].hex()}")
        # Ver que hay justo antes (los 40 bytes)
        ctx = il[ctx_start:pos]
        # Buscar el ultimo ldstr o ldc antes de este stsfld
        j = len(ctx)-1
        while j >= 0:
            b = ctx[j]
            if b == 0x72 and j+4 < len(ctx):
                token = struct.unpack_from('<I', ctx, j+1)[0]
                s = get_us_string(token & 0x00FFFFFF)
                print(f"    ldstr previo = {repr(s)}")
                break
            j -= 1
