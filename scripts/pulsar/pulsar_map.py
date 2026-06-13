#!/usr/bin/env python3
"""
Mapea el ensamblado Pulsar RAT:
- Localiza la clase/metodo del crash: bRka9Mxr9TWSzm6S22qRIoP0K
- Localiza static constructors (.cctor) con blobs grandes
- Vuelca el IL raw de esos metodos para analizar la generacion de clave AES-GCM
"""
import dnfile
import sys
import struct

PE = "/home/vagrant/beket_extracted2/appy.exe"
dn = dnfile.dnPE(PE)

md = dn.net.mdtables

def get_str(field):
    return str(field)

print("=== BUSCANDO METODO CRASH: bRka9Mxr9TWSzm6S22qRIoP0K ===")
target_method = None
for rid, row in enumerate(md.MethodDef.rows, 1):
    name = get_str(row.Name)
    if "bRka9Mxr9TWSzm6S22qRIoP0K" in name:
        flags = row.struct.Flags
        print(f"  Encontrado: RID={rid} Name={name} RVA=0x{row.Rva:08X} Flags=0x{flags:04X}")
        target_method = row

print()
print("=== BUSCANDO CLASE DEL METODO CRASH ===")
target_class_name = None
for rid, row in enumerate(md.TypeDef.rows, 1):
    ns = get_str(row.TypeNamespace)
    nm = get_str(row.TypeName)
    if "YGSa8hQFZrbG6u" in nm or "szgxkqqyqlqtnfcghslo" in ns:
        print(f"  Clase RID={rid}: {ns}.{nm}")
        target_class_name = nm

print()
print("=== STATIC CONSTRUCTORS (.cctor) CON BLOBS GRANDES ===")
cctor_list = []
for rid, row in enumerate(md.MethodDef.rows, 1):
    name = get_str(row.Name)
    if name == ".cctor" and row.Rva > 0:
        cctor_list.append((rid, row))

print(f"  Total .cctor encontrados: {len(cctor_list)}")

# Leer IL de cada .cctor y buscar los que referencian blobs grandes (ldtoken, newarr grande)
pe_data = open(PE, 'rb').read()

def rva_to_offset(pe, rva):
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + s.Misc_VirtualSize:
            return rva - s.VirtualAddress + s.PointerToRawData
    return None

interesting = []
for rid, cctor in cctor_list:
    off = rva_to_offset(dn, cctor.Rva)
    if off is None:
        continue
    hdr = pe_data[off]
    if (hdr & 0x3) == 0x2:  # Tiny header
        code_size = (hdr >> 2)
        il = pe_data[off+1 : off+1+code_size]
    elif (hdr & 0x3) == 0x3:  # Fat header
        fat = struct.unpack_from('<BBHII', pe_data, off)
        code_size = fat[3]
        il = pe_data[off+12 : off+12+code_size]
    else:
        continue

    has_large_array = False
    i = 0
    max_array = 0
    while i < len(il):
        op = il[i]
        if op == 0x20 and i+4 < len(il):  # ldc.i4 <int32>
            val = struct.unpack_from('<i', il, i+1)[0]
            if val > 100:
                has_large_array = True
                max_array = max(max_array, val)
            i += 5
        elif op == 0xd0 and i+4 < len(il):  # ldtoken
            has_large_array = True
            i += 5
        elif op == 0x1f and i+1 < len(il):  # ldc.i4.s
            i += 2
        else:
            i += 1

    if has_large_array:
        interesting.append((rid, cctor, il, max_array, off))

print(f"  .cctor con arrays/tokens grandes: {len(interesting)}")
print()

for rid, cctor, il, max_arr, off in interesting:
    print(f"  RID={rid} RVA=0x{cctor.Rva:08X} offset=0x{off:08X} IL_len={len(il)} max_array_size={max_arr}")
    print(f"  IL hex (primeros 64B): {il[:64].hex()}")
    print()

print("=== CAMPOS CON RVA EMBEBIDO (tabla FieldRva) ===")
frva_rows = md.FieldRva.rows if md.FieldRva else []
# Ordenar por RVA para estimar tamanyo entre campos consecutivos
sorted_rvas = sorted([frow.Rva for frow in frva_rows])
print(f"  Total FieldRva rows: {len(frva_rows)}")

for frid, frow in enumerate(frva_rows, 1):
    rva = frow.Rva
    off = rva_to_offset(dn, rva)
    # Tamanyo estimado = distancia al siguiente RVA
    idx = sorted_rvas.index(rva)
    if idx + 1 < len(sorted_rvas):
        size_est = sorted_rvas[idx+1] - rva
    else:
        size_est = 64  # ultimo campo, volcar 64B
    # Nombre del Field: el indice apunta a la tabla Field
    field_idx = frow.Field
    field_rid = field_idx.row_index if hasattr(field_idx, 'row_index') else int(str(field_idx).split('(')[-1].rstrip(')')) if '(' in str(field_idx) else 0
    fname = "?"
    if field_rid and field_rid <= len(md.Field.rows):
        fname = get_str(md.Field.rows[field_rid-1].Name)
    print(f"  FieldRva RID={frid} RVA=0x{rva:08X} offset=0x{off if off else 0:08X} size~={size_est} Field={fname}")
    if off and size_est > 0:
        blob = pe_data[off:off+min(size_est, 2048)]
        print(f"    primeros 32B: {blob[:32].hex()}")
        # Si el tamanyo es multiplo de 16+12+16 = AES-GCM (nonce+cipher+tag)
        if size_est in (736, 1808, 48, 64, 32, 16):
            print(f"    *** CANDIDATO AES-GCM (size={size_est}) ***")
            print(f"    BLOB completo ({size_est}B): {blob[:size_est].hex()}")

print()
print("=== CAMPOS Field con HasFieldRVA flag (0x0100) ===")
for frid, frow in enumerate(md.Field.rows, 1):
    flags = frow.struct.Flags
    if flags & 0x0100:
        name = get_str(frow.Name)
        print(f"  Field RID={frid} Name={name} Flags=0x{flags:04X}")
