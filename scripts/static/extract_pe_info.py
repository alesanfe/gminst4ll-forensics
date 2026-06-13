#!/usr/bin/env python3
"""
Extrae información detallada de archivos PE (Portable Executable).
Uso: python3 extract_pe_info.py <archivo>
"""
import sys
import pefile
from pathlib import Path

def extract_pe_info(filepath):
    """Extrae información detallada de un archivo PE."""
    try:
        pe = pefile.PE(filepath)
    except Exception as e:
        print(f"Error al leer PE: {e}")
        return None
    
    info = {
        'file': filepath,
        'entry_point': hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        'image_base': hex(pe.OPTIONAL_HEADER.ImageBase),
        'sections': [],
        'imports': [],
        'exports': [],
        'timestamp': pe.FILE_HEADER.TimeDateStamp
    }
    
    # Secciones
    for section in pe.sections:
        info['sections'].append({
            'name': section.Name.decode('utf-8').rstrip('\x00'),
            'virtual_address': hex(section.VirtualAddress),
            'virtual_size': section.Misc_VirtualSize,
            'raw_size': section.SizeOfRawData,
            'characteristics': hex(section.Characteristics)
        })
    
    # Imports
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8')
            imports = [imp.name.decode('utf-8') if imp.name else 'None' for imp in entry.imports]
            info['imports'].append({'dll': dll_name, 'functions': imports[:10]})  # Primeras 10
    
    # Exports
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                info['exports'].append(exp.name.decode('utf-8'))
    
    pe.close()
    return info

def main():
    if len(sys.argv) < 2:
        print("Uso: python3 extract_pe_info.py <archivo>")
        sys.exit(1)
    
    filepath = sys.argv[1]
    if not Path(filepath).exists():
        print(f"Error: Archivo no encontrado: {filepath}")
        sys.exit(1)
    
    print(f"Analizando PE: {filepath}")
    info = extract_pe_info(filepath)
    
    if not info:
        sys.exit(1)
    
    # Generar nombre de archivo de salida
    output_file = Path(filepath).stem + '_pe_info.txt'
    
    # Guardar en archivo
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(f"=== Información PE ===\n")
        f.write(f"Archivo: {info['file']}\n")
        f.write(f"Entry Point: {info['entry_point']}\n")
        f.write(f"Image Base: {info['image_base']}\n")
        f.write(f"Timestamp: {info['timestamp']}\n")
        
        f.write(f"\n=== Secciones ({len(info['sections'])}) ===\n")
        for sec in info['sections']:
            f.write(f"  {sec['name']}: VA={sec['virtual_address']}, VS={sec['virtual_size']}, RS={sec['raw_size']}\n")
        
        f.write(f"\n=== Imports ({len(info['imports'])}) ===\n")
        for imp in info['imports']:
            f.write(f"  {imp['dll']}: {', '.join(imp['functions'][:5])}\n")
        
        f.write(f"\n=== Exports ({len(info['exports'])}) ===\n")
        for exp in info['exports']:
            f.write(f"  {exp}\n")
    
    # Imprimir en pantalla
    print(f"\n=== Información PE ===")
    print(f"Archivo: {info['file']}")
    print(f"Entry Point: {info['entry_point']}")
    print(f"Image Base: {info['image_base']}")
    print(f"Timestamp: {info['timestamp']}")
    
    print(f"\n=== Secciones ({len(info['sections'])}) ===")
    for sec in info['sections']:
        print(f"  {sec['name']}: VA={sec['virtual_address']}, VS={sec['virtual_size']}, RS={sec['raw_size']}")
    
    print(f"\n=== Imports ({len(info['imports'])}) ===")
    for imp in info['imports'][:20]:
        print(f"  {imp['dll']}: {', '.join(imp['functions'][:5])}")
    
    print(f"\n=== Exports ({len(info['exports'])}) ===")
    for exp in info['exports'][:20]:
        print(f"  {exp}")
    
    print(f"\nGuardado en: {output_file}")

if __name__ == '__main__':
    main()
