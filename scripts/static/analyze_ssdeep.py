#!/usr/bin/env python3
"""
Fuzzy hashing con ssdeep.
ssdeep permite detectar similitudes entre archivos usando fuzzy hashing,
útil para detectar variantes de malware.
"""
import sys
import subprocess
from pathlib import Path

def calculate_ssdeep(filepath):
    """Calcula hash ssdeep de un archivo."""
    if not Path(filepath).exists():
        print(f"Error: Archivo no encontrado: {filepath}")
        return None
    
    try:
        result = subprocess.run(
            ['ssdeep', filepath],
            capture_output=True,
            text=True,
            timeout=60
        )
        
        if result.returncode != 0:
            print(f"Error ejecutando ssdeep: {result.stderr}")
            return None
        
        return result.stdout.strip()
    
    except subprocess.TimeoutExpired:
        print("Error: ssdeep timeout")
        return None
    except FileNotFoundError:
        print("Error: ssdeep no encontrado. Instalar con: apt-get install ssdeep")
        return None

def compare_ssdeep(filepath1, filepath2):
    """Compara dos archivos usando ssdeep."""
    try:
        result = subprocess.run(
            ['ssdeep', '-a', filepath1, filepath2],
            capture_output=True,
            text=True,
            timeout=60
        )
        
        if result.returncode != 0:
            print(f"Error comparando con ssdeep: {result.stderr}")
            return None
        
        return result.stdout.strip()
    
    except subprocess.TimeoutExpired:
        print("Error: ssdeep timeout")
        return None
    except FileNotFoundError:
        print("Error: ssdeep no encontrado")
        return None

def main():
    if len(sys.argv) < 2:
        print("Uso: python3 analyze_ssdeep.py <archivo1> [archivo2]")
        print("  Si se proporciona un solo archivo, calcula su hash ssdeep")
        print("  Si se proporcionan dos archivos, los compara")
        sys.exit(1)
    
    filepath1 = sys.argv[1]
    
    if len(sys.argv) == 2:
        # Calcular hash ssdeep de un solo archivo
        print(f"Calculando ssdeep de: {filepath1}")
        ssdeep_hash = calculate_ssdeep(filepath1)
        
        if not ssdeep_hash:
            sys.exit(1)
        
        # Guardar en archivo
        output_file = Path(filepath1).stem + '_ssdeep.txt'
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(f"=== ssdeep Hash ===\n")
            f.write(f"Archivo: {filepath1}\n\n")
            f.write(ssdeep_hash)
        
        print(f"\nGuardado en: {output_file}")
        print(f"ssdeep: {ssdeep_hash}")
    
    else:
        # Comparar dos archivos
        filepath2 = sys.argv[2]
        print(f"Comparando ssdeep: {filepath1} vs {filepath2}")
        
        comparison = compare_ssdeep(filepath1, filepath2)
        
        if not comparison:
            sys.exit(1)
        
        # Guardar en archivo
        output_file = f"{Path(filepath1).stem}_vs_{Path(filepath2).stem}_ssdeep.txt"
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(f"=== ssdeep Comparison ===\n")
            f.write(f"Archivo 1: {filepath1}\n")
            f.write(f"Archivo 2: {filepath2}\n\n")
            f.write(comparison)
        
        print(f"\nGuardado en: {output_file}")
        print(comparison)

if __name__ == "__main__":
    main()
