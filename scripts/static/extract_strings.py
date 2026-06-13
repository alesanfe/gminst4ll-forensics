#!/usr/bin/env python3
"""
Extrae strings de archivos con filtros específicos para análisis de malware.
Uso: python3 extract_strings.py <archivo> [min_length]
"""
import sys
import re
from pathlib import Path

def extract_strings(filepath, min_length=8):
    """Extrae strings ASCII de un archivo."""
    strings = []
    current_string = ""
    
    with open(filepath, 'rb') as f:
        while True:
            byte = f.read(1)
            if not byte:
                if current_string:
                    strings.append(current_string)
                break
            
            char = byte[0]
            # Caracteres imprimibles ASCII (32-126)
            if 32 <= char <= 126:
                current_string += chr(char)
            else:
                if len(current_string) >= min_length:
                    strings.append(current_string)
                current_string = ""
    
    return strings

def filter_strings(strings):
    """Filtra strings por categorías de interés para malware."""
    categories = {
        'urls': [],
        'ips': [],
        'paths': [],
        'registry': [],
        'crypto': [],
        'other': []
    }
    
    url_pattern = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+')
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    path_pattern = re.compile(r'[A-Za-z]:\\[^\s<>"]+|C:\\[^\s<>"]+|%[A-Z_]+%')
    registry_pattern = re.compile(r'HK[A-Z_]+\\[^\s<>"]+')
    crypto_pattern = re.compile(r'\b[0-9a-fA-F]{40,}\b')  # Hashes largos
    
    for s in strings:
        if url_pattern.search(s):
            categories['urls'].append(s)
        elif ip_pattern.search(s):
            categories['ips'].append(s)
        elif path_pattern.search(s):
            categories['paths'].append(s)
        elif registry_pattern.search(s):
            categories['registry'].append(s)
        elif crypto_pattern.search(s):
            categories['crypto'].append(s)
        else:
            categories['other'].append(s)
    
    return categories

def main():
    if len(sys.argv) < 2:
        print("Uso: python3 extract_strings.py <archivo> [min_length]")
        sys.exit(1)
    
    filepath = sys.argv[1]
    min_length = int(sys.argv[2]) if len(sys.argv) > 2 else 8
    
    if not Path(filepath).exists():
        print(f"Error: Archivo no encontrado: {filepath}")
        sys.exit(1)
    
    print(f"Extrayendo strings (min={min_length}) de: {filepath}")
    strings = extract_strings(filepath, min_length)
    print(f"Total strings encontrados: {len(strings)}")
    
    # Filtrar por categorías
    categories = filter_strings(strings)
    
    # Imprimir resultados
    print(f"\n=== URLs ({len(categories['urls'])}) ===")
    for s in categories['urls'][:20]:
        print(f"  {s}")
    
    print(f"\n=== IPs ({len(categories['ips'])}) ===")
    for s in categories['ips'][:20]:
        print(f"  {s}")
    
    print(f"\n=== Rutas ({len(categories['paths'])}) ===")
    for s in categories['paths'][:20]:
        print(f"  {s}")
    
    print(f"\n=== Registry ({len(categories['registry'])}) ===")
    for s in categories['registry'][:20]:
        print(f"  {s}")
    
    print(f"\n=== Hashes/Crypto ({len(categories['crypto'])}) ===")
    for s in categories['crypto'][:20]:
        print(f"  {s}")
    
    # Guardar todos los strings
    output_file = f"{filepath}_strings.txt"
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(f"Archivo: {filepath}\n")
        f.write(f"Total strings: {len(strings)}\n\n")
        f.write("=== URLs ===\n")
        for s in categories['urls']:
            f.write(f"{s}\n")
        f.write("\n=== IPs ===\n")
        for s in categories['ips']:
            f.write(f"{s}\n")
        f.write("\n=== Rutas ===\n")
        for s in categories['paths']:
            f.write(f"{s}\n")
        f.write("\n=== Registry ===\n")
        for s in categories['registry']:
            f.write(f"{s}\n")
        f.write("\n=== Hashes/Crypto ===\n")
        for s in categories['crypto']:
            f.write(f"{s}\n")
        f.write("\n=== Otros Strings ===\n")
        for s in categories['other']:
            f.write(f"{s}\n")
    
    print(f"\nGuardado en: {output_file}")

if __name__ == '__main__':
    main()
