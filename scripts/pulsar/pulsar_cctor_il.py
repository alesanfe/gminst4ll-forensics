#!/usr/bin/env python3
"""
Disassembla el IL del .cctor RID=1388 y busca los blobs AES-GCM (1808B y 736B).
Sigue referencias ldtoken -> Field -> FieldRva para extraer datos embebidos.
"""
import dnfile
import struct

PE = "/home/vagrant/beket_extracted2/appy.exe"
dn = dnfile.dnPE(PE)
md = dn.net.mdtables
pe_data = open(PE, 'rb').read()

def rva_to_offset(rva):
    for s in dn.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + s.Misc_VirtualSize:
            return rva - s.VirtualAddress + s.PointerToRawData
    return None

def read_il(rva):
    off = rva_to_offset(rva)
    if off is None:
        return None, 0
    hdr = pe_data[off]
    if (hdr & 0x3) == 0x2:
        code_size = hdr >> 2
        return pe_data[off+1:off+1+code_size], off+1
    elif (hdr & 0x3) == 0x3:
        fat = struct.unpack_from('<BBHII', pe_data, off)
        code_size = fat[3]
        return pe_data[off+12:off+12+code_size], off+12
    return None, 0

def token_to_rid(token):
    return token & 0x00FFFFFF

def token_table(token):
    return (token >> 24) & 0xFF

# Disassembla IL mostrando todos los opcodes con sus operandos
def disasm_il(il, il_off):
    i = 0
    while i < len(il):
        op = il[i]
        pos = il_off + i
        if op == 0xfe and i+1 < len(il):  # prefijo 2 bytes
            op2 = il[i+1]
            print(f"  0x{pos:06X}: FE {op2:02X}")
            i += 2
            continue
        # Opcodes relevantes
        if op == 0x20:   # ldc.i4
            val = struct.unpack_from('<i', il, i+1)[0]
            print(f"  0x{pos:06X}: ldc.i4 {val} (0x{val:08X})")
            i += 5
        elif op == 0x1f: # ldc.i4.s
            val = struct.unpack_from('<b', il, i+1)[0]
            print(f"  0x{pos:06X}: ldc.i4.s {val}")
            i += 2
        elif op == 0xd0: # ldtoken
            token = struct.unpack_from('<I', il, i+1)[0]
            tbl = token_table(token)
            rid = token_to_rid(token)
            name = "?"
            if tbl == 0x04 and rid <= len(md.Field.rows):  # Field
                name = str(md.Field.rows[rid-1].Name)
            elif tbl == 0x06 and rid <= len(md.MethodDef.rows):  # MethodDef
                name = str(md.MethodDef.rows[rid-1].Name)
            print(f"  0x{pos:06X}: ldtoken 0x{token:08X} (tbl={tbl} rid={rid}) [{name[:40]}]")
            i += 5
        elif op == 0x70: # ldstr
            token = struct.unpack_from('<I', il, i+1)[0]
            print(f"  0x{pos:06X}: ldstr 0x{token:08X}")
            i += 5
        elif op == 0x28 or op == 0x6f or op == 0x73 or op == 0x74: # call/callvirt/newobj/castclass
            token = struct.unpack_from('<I', il, i+1)[0]
            tbl = token_table(token)
            rid = token_to_rid(token)
            name = "?"
            if tbl == 0x0a and rid <= len(md.MemberRef.rows):
                name = str(md.MemberRef.rows[rid-1].Name)
            elif tbl == 0x06 and rid <= len(md.MethodDef.rows):
                name = str(md.MethodDef.rows[rid-1].Name)
            opcname = {0x28:'call',0x6f:'callvirt',0x73:'newobj',0x74:'castclass'}[op]
            print(f"  0x{pos:06X}: {opcname} 0x{token:08X} (tbl={tbl} rid={rid}) [{name[:40]}]")
            i += 5
        elif op == 0x80: # stsfld
            token = struct.unpack_from('<I', il, i+1)[0]
            rid = token_to_rid(token)
            tbl = token_table(token)
            name = "?"
            if tbl == 0x04 and rid <= len(md.Field.rows):
                name = str(md.Field.rows[rid-1].Name)[:40]
            elif tbl == 0x0a and rid <= len(md.MemberRef.rows):
                name = str(md.MemberRef.rows[rid-1].Name)[:40]
            print(f"  0x{pos:06X}: stsfld 0x{token:08X} [{name}]")
            i += 5
        elif op == 0x7e: # ldsfld
            token = struct.unpack_from('<I', il, i+1)[0]
            rid = token_to_rid(token)
            tbl = token_table(token)
            name = "?"
            if tbl == 0x04 and rid <= len(md.Field.rows):
                name = str(md.Field.rows[rid-1].Name)[:40]
            print(f"  0x{pos:06X}: ldsfld 0x{token:08X} [{name}]")
            i += 5
        elif op == 0x2a: # ret
            print(f"  0x{pos:06X}: ret")
            i += 1
        elif op == 0x16: # ldc.i4.0
            print(f"  0x{pos:06X}: ldc.i4.0")
            i += 1
        elif op == 0x17: # ldc.i4.1
            print(f"  0x{pos:06X}: ldc.i4.1")
            i += 1
        else:
            print(f"  0x{pos:06X}: 0x{op:02X}")
            i += 1

# Target .cctor candidatos
TARGETS = [336, 1388]

for rid, row in enumerate(md.MethodDef.rows, 1):
    if rid not in TARGETS:
        continue
    il, il_off = read_il(row.Rva)
    if il is None:
        continue
    print(f"\n{'='*60}")
    print(f"=== .cctor RID={rid} RVA=0x{row.Rva:08X} IL_len={len(il)} ===")
    print(f"{'='*60}")
    disasm_il(il, il_off)

# Buscar ManifestResource que podria tener blobs cifrados
print(f"\n{'='*60}")
print("=== ManifestResource (recursos embebidos) ===")
for rid, row in enumerate(md.ManifestResource.rows, 1):
    name = str(row.Name)
    off_val = row.Offset
    print(f"  RID={rid} Name={name} Offset=0x{off_val:08X} Flags=0x{row.Flags:08X}")
