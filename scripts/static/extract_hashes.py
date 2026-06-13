#!/usr/bin/env python3
"""
Extrae hashes (MD5, SHA1, SHA256, ssdeep) de archivos.
Uso: python3 extract_hashes.py <archivo> [directorio_salida]
"""
import sys
import hashlib
import os
import subprocess
from pathlib import Path

def calculate_hashes(filepath):
    """Calcula MD5, SHA1, SHA256 de un archivo."""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    
    return {
        'md5': md5.hexdigest(),
        'sha1': sha1.hexdigest(),
        'sha256': sha256.hexdigest()
    }

def calculate_ssdeep(filepath):
    """Calcula ssdeep si está disponible."""
    try:
        result = subprocess.run(['ssdeep', filepath], 
                              capture_output=True, text=True, check=True)
        return result.stdout.strip().split(',')[0].strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return "N/A"

def main():
    if len(sys.argv) < 2:
        print("Uso: python3 extract_hashes.py <archivo> [directorio_salida]")
        sys.exit(1)
    
    filepath = sys.argv[1]
    if not os.path.exists(filepath):
        print(f"Error: Archivo no encontrado: {filepath}")
        sys.exit(1)
    
    output_dir = sys.argv[2] if len(sys.argv) > 2 else os.path.dirname(filepath)
    
    print(f"Analizando: {filepath}")
    
    # Calcular hashes
    hashes = calculate_hashes(filepath)
    ssdeep = calculate_ssdeep(filepath)
    
    # Obtener tamaño
    size = os.path.getsize(filepath)
    
    # Imprimir resultados
    print(f"\nHashes de {os.path.basename(filepath)}:")
    print(f"  MD5:    {hashes['md5']}")
    print(f"  SHA1:   {hashes['sha1']}")
    print(f"  SHA256: {hashes['sha256']}")
    print(f"  ssdeep: {ssdeep}")
    print(f"  Tamaño: {size} bytes ({size/1024/1024:.2f} MB)")
    
    # Guardar en archivo
    output_file = os.path.join(output_dir, f"{os.path.basename(filepath)}_hashes.txt")
    with open(output_file, 'w') as f:
        f.write(f"Archivo: {filepath}\n")
        f.write(f"Tamaño: {size} bytes\n")
        f.write(f"MD5:    {hashes['md5']}\n")
        f.write(f"SHA1:   {hashes['sha1']}\n")
        f.write(f"SHA256: {hashes['sha256']}\n")
        f.write(f"ssdeep: {ssdeep}\n")
    
    print(f"\nGuardado en: {output_file}")

if __name__ == '__main__':
    main()
