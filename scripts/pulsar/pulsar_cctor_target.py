#!/usr/bin/env python3
"""
Disassembla el .cctor de la clase YGSa8hQFZrbG6u (RID=116, donde ocurre el crash)
y todos los metodos de esa clase para entender la derivacion de clave AES-GCM.
"""
import dnfile, struct

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
        sz = hdr >> 2
        return raw[off+1:off+1+sz], off+1
    elif (hdr & 0x3) == 0x3:
        fat = struct.unpack_from('<BBHII', raw, off)
        sz  = fat[3]
        return raw[off+12:off+12+sz], off+12
    return None, 0

def resolve_token(token):
    tbl = (token >> 24) & 0xFF
    rid = token & 0x00FFFFFF
    try:
        if tbl == 0x04 and rid <= len(md.Field.rows):
            return f"Field[{rid}]:{str(md.Field.rows[rid-1].Name)[:30]}"
        if tbl == 0x06 and rid <= len(md.MethodDef.rows):
            return f"Method[{rid}]:{str(md.MethodDef.rows[rid-1].Name)[:30]}"
        if tbl == 0x0a and rid <= len(md.MemberRef.rows):
            r = md.MemberRef.rows[rid-1]
            return f"MemberRef[{rid}]:{str(r.Name)[:30]}"
        if tbl == 0x01 and rid <= len(md.TypeRef.rows):
            r = md.TypeRef.rows[rid-1]
            return f"TypeRef[{rid}]:{str(r.TypeName)[:30]}"
        if tbl == 0x02 and rid <= len(md.TypeDef.rows):
            r = md.TypeDef.rows[rid-1]
            return f"TypeDef[{rid}]:{str(r.TypeName)[:30]}"
        if tbl == 0x2b and rid <= len(md.MethodSpec.rows):
            return f"MethodSpec[{rid}]"
    except: pass
    return f"0x{token:08X}"

def disasm(il, base_off):
    """Disassembler IL completo con todos los opcodes de 1-5 bytes"""
    OPCODES_1 = {
        0x00:'nop', 0x01:'break', 0x02:'ldarg.0', 0x03:'ldarg.1',
        0x04:'ldarg.2', 0x05:'ldarg.3', 0x06:'ldloc.0', 0x07:'ldloc.1',
        0x08:'ldloc.2', 0x09:'ldloc.3', 0x0a:'stloc.0', 0x0b:'stloc.1',
        0x0c:'stloc.2', 0x0d:'stloc.3', 0x0e:'ldarg.s', 0x10:'starg.s',
        0x11:'ldloc.s', 0x12:'ldloca.s', 0x13:'stloc.s',
        0x14:'ldnull', 0x15:'ldc.i4.m1', 0x16:'ldc.i4.0', 0x17:'ldc.i4.1',
        0x18:'ldc.i4.2', 0x19:'ldc.i4.3', 0x1a:'ldc.i4.4', 0x1b:'ldc.i4.5',
        0x1c:'ldc.i4.6', 0x1d:'ldc.i4.7', 0x1e:'ldc.i4.8',
        0x25:'dup', 0x26:'pop', 0x2a:'ret',
        0x58:'add', 0x59:'sub', 0x5a:'mul', 0x5f:'and', 0x60:'or', 0x61:'xor',
        0x62:'shl', 0x63:'shr', 0x65:'neg', 0x66:'not',
        0x6a:'conv.i4', 0x69:'conv.u4', 0x8e:'ldlen',
        0x91:'ldelem.u1', 0x9c:'stelem.i1',
    }
    OPCODES_TOKEN = {0x28:'call', 0x6f:'callvirt', 0x73:'newobj',
                     0x74:'castclass', 0x75:'isinst', 0x79:'unbox.any',
                     0x70:'ldstr', 0x72:'ldstr', 0x7b:'ldfld',
                     0x7c:'ldflda', 0x7d:'stfld', 0x7e:'ldsfld',
                     0x7f:'ldsflda', 0x80:'stsfld', 0x8d:'newarr',
                     0xd0:'ldtoken'}
    OPCODES_BR = {0x2b:'br.s', 0x2c:'brfalse.s', 0x2d:'brtrue.s',
                  0x32:'bgt.s', 0x3a:'br', 0x3b:'brfalse', 0x3c:'brtrue',
                  0x3f:'blt', 0x41:'bge', 0x44:'bgt',
                  0x30:'blt.s', 0x31:'ble.s', 0x33:'bge.s',
                  0x45:'ble', 0x46:'bne.un', 0x35:'bne.un.s'}

    i = 0
    lines = []
    while i < len(il):
        op = il[i]
        pos = base_off + i

        if op == 0xfe and i+1 < len(il):
            op2 = il[i+1]
            fe_ops = {0x01:'ceq', 0x02:'cgt', 0x04:'clt', 0x09:'ldarg', 0x0a:'starg', 0x0e:'initblk'}
            nm = fe_ops.get(op2, f'fe.{op2:02x}')
            lines.append(f"  {pos:08X}: {nm}")
            i += 2
            continue

        if op in OPCODES_1:
            nm = OPCODES_1[op]
            # algunos tienen 1 byte de operando
            if op in (0x0e, 0x10, 0x11, 0x12, 0x13):
                v = raw[base_off+i+1] if i+1 < len(il) else 0
                lines.append(f"  {pos:08X}: {nm} {v}")
                i += 2
            else:
                lines.append(f"  {pos:08X}: {nm}")
                i += 1

        elif op in OPCODES_TOKEN:
            token = struct.unpack_from('<I', il, i+1)[0] if i+4 < len(il) else 0
            nm = OPCODES_TOKEN[op]
            ref = resolve_token(token)
            lines.append(f"  {pos:08X}: {nm} {ref}")
            i += 5

        elif op in OPCODES_BR:
            nm = OPCODES_BR[op]
            if op in (0x2b, 0x2c, 0x2d, 0x30, 0x31, 0x32, 0x33, 0x35):
                v = struct.unpack_from('<b', il, i+1)[0] if i+1 < len(il) else 0
                lines.append(f"  {pos:08X}: {nm} {v:+d} -> {pos+2+v:08X}")
                i += 2
            else:
                v = struct.unpack_from('<i', il, i+1)[0] if i+4 < len(il) else 0
                lines.append(f"  {pos:08X}: {nm} {v:+d} -> {pos+5+v:08X}")
                i += 5

        elif op == 0x1f:  # ldc.i4.s
            v = struct.unpack_from('<b', il, i+1)[0] if i+1 < len(il) else 0
            lines.append(f"  {pos:08X}: ldc.i4.s {v}")
            i += 2

        elif op == 0x20:  # ldc.i4
            v = struct.unpack_from('<i', il, i+1)[0] if i+4 < len(il) else 0
            lines.append(f"  {pos:08X}: ldc.i4 {v} (0x{v&0xFFFFFFFF:08X})")
            i += 5

        elif op == 0x21:  # ldc.i8
            v = struct.unpack_from('<q', il, i+1)[0] if i+8 < len(il) else 0
            lines.append(f"  {pos:08X}: ldc.i8 {v}")
            i += 9

        elif op == 0x22:  # ldc.r4
            lines.append(f"  {pos:08X}: ldc.r4")
            i += 5

        elif op == 0x38:  # br (4 byte)
            v = struct.unpack_from('<i', il, i+1)[0] if i+4 < len(il) else 0
            lines.append(f"  {pos:08X}: br {v:+d} -> {pos+5+v:08X}")
            i += 5

        elif op == 0x45:
            v = struct.unpack_from('<i', il, i+1)[0] if i+4 < len(il) else 0
            lines.append(f"  {pos:08X}: ble {v:+d}")
            i += 5

        else:
            lines.append(f"  {pos:08X}: 0x{op:02X}")
            i += 1

    return lines

# ── Encontrar el .cctor de YGSa8hQFZrbG6u ────────────────────────────────────
TARGET_CLASS = "YGSa8hQFZrbG6u"
TARGET_NS    = "szgxkqqyqlqtnfcghslo"

# Encontrar RID de la clase
class_rid = None
for rid, row in enumerate(md.TypeDef.rows, 1):
    if str(row.TypeName) == TARGET_CLASS and str(row.TypeNamespace) == TARGET_NS:
        class_rid = rid
        break

print(f"Clase {TARGET_NS}.{TARGET_CLASS} => TypeDef RID={class_rid}")

# Metodos de esta clase: desde MethodList hasta el siguiente TypeDef
def get_method_list_rid(ml):
    """Extrae el primer RID de un MethodList (puede ser MDTableIndex o lista)"""
    if hasattr(ml, 'row_index'):
        return ml.row_index
    if isinstance(ml, list) and len(ml) > 0:
        first = ml[0]
        if hasattr(first, 'row_index'):
            return first.row_index
        s = str(first)
        # Buscar digitos en la representacion
        import re
        m = re.search(r'\b(\d+)\b', s)
        if m:
            return int(m.group(1))
    # Fallback: buscar en MethodDef por orden
    return None

if class_rid:
    trow = md.TypeDef.rows[class_rid-1]

    # Estrategia alternativa: iterar todos los metodos y filtrar por clase via TypeDef range
    # El estandar .NET asigna metodos de forma consecutiva por clase
    # Buscamos el .cctor y bRka9Mx... directamente por nombre
    TARGET_METHODS = {".cctor", "bRka9Mxr9TWSzm6S22qRIoP0K"}
    mstart = 1
    mend   = len(md.MethodDef.rows) + 1

    # Usar MethodList si es accesible
    ml_val = trow.MethodList
    ml_rid = get_method_list_rid(ml_val)
    if ml_rid:
        mstart = ml_rid
        if class_rid < len(md.TypeDef.rows):
            ml2 = md.TypeDef.rows[class_rid].MethodList
            ml2_rid = get_method_list_rid(ml2)
            if ml2_rid:
                mend = ml2_rid
        print(f"Metodos RID {mstart} .. {mend-1}:")
    else:
        print(f"MethodList no resuelto, buscando por nombre...")

    for mrid in range(mstart, mend):
        if mrid > len(md.MethodDef.rows): break
        mrow = md.MethodDef.rows[mrid-1]
        mname = str(mrow.Name)
        print(f"\n  [{mrid}] {mname}  RVA=0x{mrow.Rva:08X}")
        if mrow.Rva == 0: continue
        il, il_off = read_il(mrow.Rva)
        if il is None: continue
        print(f"  IL length: {len(il)}")
        lines = disasm(il, il_off)
        for l in lines:
            print(l)
