#!/usr/bin/env python3
"""
Extrae strings del binario desofuscado appy-cleaned.exe usando dnfile.
Busca strings ofuscados que de4dot no pudo renombrar (probable config C2).
"""
import dnfile, sys

PE = "/home/vagrant/beket_extracted2/appy-cleaned.exe"
dn = dnfile.dnPE(PE)

print("Analizando binario desofuscado con dnfile...")
print()

# Extraer strings del heap #US
if hasattr(dn.net, 'user_strings') and dn.net.user_strings:
    us = dn.net.user_strings
    print(f"#US heap: {len(us)} strings")
    print()
    
    # Filtrar strings que parezcan ofuscados (caracteres aleatorios)
    ofuscados = []
    for idx, s in enumerate(us):
        if s and len(s) > 8:
            # String parece ofuscado si tiene mezcla de mayúsculas/minúsculas sin espacios
            if ' ' not in s and '.' not in s and '/' not in s and '\\' not in s:
                # Contiene letras pero no palabras reconocibles
                ofuscados.append(s)
    
    print(f"Strings ofuscados candidatos: {len(ofuscados)}")
    for s in ofuscados[:50]:  # Primeros 50
        print(f"  {s}")
    print()

# Buscar en los campos (Field) que de4dot renombró
print("Campos (Field) renombrados por de4dot:")
for fd in dn.net.mdtables.Field:
    if hasattr(fd, 'Name') and fd.Name:
        if 'ip' in fd.Name.lower() or 'port' in fd.Name.lower() or 'host' in fd.Name.lower() or 'server' in fd.Name.lower() or 'key' in fd.Name.lower():
            print(f"  Field: {fd.Name}")
print()

# Buscar en los métodos (Method) renombrados
print("Métodos (Method) renombrados por de4dot con keywords C2:")
c2_keywords = ["connect", "disconnect", "server", "client", "host", "port", "key", "auth", "token", "certificate"]
for md in dn.net.mdtables.MethodDef:
    if hasattr(md, 'Name') and md.Name:
        low = md.Name.lower()
        for kw in c2_keywords:
            if kw in low:
                print(f"  Method: {md.Name}")
                break

print()
print("Done.")
