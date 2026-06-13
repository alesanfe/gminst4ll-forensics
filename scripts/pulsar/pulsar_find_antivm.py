#!/usr/bin/env python3
"""
Busca todos los métodos que podrían ser checks anti-VM en appy.exe.
Criterios:
- Métodos estáticos privados
- Que devuelven bool o int
- Con IL corto (< 100 bytes)
- Que contengan ldstr con keywords VM, sandbox, virtual, debug
"""
import dnfile, sys

PE = "/home/vagrant/beket_extracted2/appy.exe"
dn = dnfile.dnPE(PE)

keywords = ["vm", "virtual", "sandbox", "debug", "vbox", "vmware", "qemu", "xen", "hyper-v"]

print("Buscando métodos anti-VM...")
print()

for md in dn.net.mdtables.MethodDef:
    if not hasattr(md, 'RID'):
        continue
    rid = md.RID
    if rid == 0:
        continue
    
    # Solo métodos estáticos
    flags = md.Flags
    if not (flags & 0x0010):  # Static
        continue
    
    # Obtener IL si existe
    if not hasattr(md, 'MethodBody') or md.MethodBody is None:
        continue
    
    body = md.MethodBody
    if not hasattr(body, 'IL') or body.IL is None:
        continue
    
    il = body.IL
    il_hex = il.hex()
    
    # Buscar keywords en IL (como ldstr)
    if any(kw in il_hex.lower() for kw in keywords):
        print(f"RID={rid} RVA=0x{md.RVA:08X} Flags=0x{flags:04X}")
        print(f"  IL size: {len(il)} bytes")
        print(f"  IL hex: {il_hex[:64]}...")
        print()
    
    # Métodos muy cortos (< 50 bytes) podrían ser checks simples
    if len(il) < 50 and len(il) > 0:
        print(f"RID={rid} RVA=0x{md.RVA:08X} Flags=0x{flags:04X} (short method)")
        print(f"  IL size: {len(il)} bytes")
        print(f"  IL hex: {il_hex}")
        print()

print("Done.")
