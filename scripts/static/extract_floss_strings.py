#!/usr/bin/env python3
"""
Extracción de strings ofuscados con FLOSS.
FLOSS (FireEye Layout of Obfuscated Strings) extrae strings ofuscados
que no son detectables por herramientas estándar de strings.
"""
import sys
import subprocess
from pathlib import Path

def extract_floss_strings(filepath):
    """Extrae strings ofuscados usando FLOSS."""
    if not Path(filepath).exists():
        print(f"Error: Archivo no encontrado: {filepath}")
        return None
    
    try:
        # Ejecutar FLOSS
        result = subprocess.run(
            ['floss', filepath],
            capture_output=True,
            text=True,
            timeout=300
        )
        
        if result.returncode != 0:
            print(f"Error ejecutando FLOSS: {result.stderr}")
            return None
        
        return result.stdout
    
    except subprocess.TimeoutExpired:
        print("Error: FLOSS timeout")
        return None
    except FileNotFoundError:
        print("Error: FLOSS no encontrado. Instalar con: pip install floss")
        return None

def main():
    if len(sys.argv) < 2:
        print("Uso: python3 extract_floss_strings.py <archivo>")
        sys.exit(1)
    
    filepath = sys.argv[1]
    print(f"Extrayendo strings FLOSS de: {filepath}")
    
    floss_output = extract_floss_strings(filepath)
    
    if not floss_output:
        sys.exit(1)
    
    # Generar nombre de archivo de salida
    output_file = Path(filepath).stem + '_floss_strings.txt'
    
    # Guardar en archivo
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(f"=== FLOSS Strings ===\n")
        f.write(f"Archivo: {filepath}\n\n")
        f.write(floss_output)
    
    print(f"\nGuardado en: {output_file}")
    
    # Mostrar resumen
    lines = floss_output.split('\n')
    print(f"Total strings: {len([l for l in lines if l.strip()])}")

if __name__ == "__main__":
    main()
