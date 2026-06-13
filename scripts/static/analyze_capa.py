#!/usr/bin/env python3
"""
Análisis de capacidades de malware con CAPA.
CAPA detecta capacidades de malware (persistencia, comunicación, etc.)
basado en reglas de comportamiento.
"""
import sys
import subprocess
from pathlib import Path

def analyze_capa(filepath):
    """Analiza capacidades usando CAPA."""
    if not Path(filepath).exists():
        print(f"Error: Archivo no encontrado: {filepath}")
        return None
    
    try:
        # Ejecutar CAPA
        result = subprocess.run(
            ['capa', filepath],
            capture_output=True,
            text=True,
            timeout=300
        )
        
        if result.returncode != 0:
            print(f"Error ejecutando CAPA: {result.stderr}")
            return None
        
        return result.stdout
    
    except subprocess.TimeoutExpired:
        print("Error: CAPA timeout")
        return None
    except FileNotFoundError:
        print("Error: CAPA no encontrado. Instalar con: pip install capa")
        return None

def main():
    if len(sys.argv) < 2:
        print("Uso: python3 analyze_capa.py <archivo>")
        sys.exit(1)
    
    filepath = sys.argv[1]
    print(f"Analizando capacidades CAPA de: {filepath}")
    
    capa_output = analyze_capa(filepath)
    
    if not capa_output:
        sys.exit(1)
    
    # Generar nombre de archivo de salida
    output_file = Path(filepath).stem + '_capa_analysis.txt'
    
    # Guardar en archivo
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(f"=== CAPA Analysis ===\n")
        f.write(f"Archivo: {filepath}\n\n")
        f.write(capa_output)
    
    print(f"\nGuardado en: {output_file}")
    
    # Mostrar resumen
    lines = capa_output.split('\n')
    print(f"Total líneas de análisis: {len([l for l in lines if l.strip()])}")

if __name__ == "__main__":
    main()
