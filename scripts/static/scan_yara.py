#!/usr/bin/env python3
"""
Escaneo de malware con reglas YARA.
YARA permite detectar malware basado en patrones específicos.
"""
import sys
import subprocess
from pathlib import Path

def scan_yara(filepath, rules_path="/malware_analysis/yara_rules"):
    """Escanea archivo con reglas YARA."""
    if not Path(filepath).exists():
        print(f"Error: Archivo no encontrado: {filepath}")
        return None
    
    if not Path(rules_path).exists():
        print(f"Error: Directorio de reglas YARA no encontrado: {rules_path}")
        return None
    
    try:
        # Buscar archivos de reglas YARA
        rule_files = list(Path(rules_path).glob("*.yar")) + list(Path(rules_path).glob("*.yara"))
        
        if not rule_files:
            print(f"Error: No se encontraron reglas YARA en {rules_path}")
            return None
        
        results = []
        for rule_file in rule_files:
            try:
                result = subprocess.run(
                    ['yara', str(rule_file), filepath],
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                
                if result.stdout.strip():
                    results.append(f"=== Regla: {rule_file.name} ===")
                    results.append(result.stdout)
            
            except subprocess.TimeoutExpired:
                print(f"Timeout escaneando con {rule_file.name}")
                continue
            except Exception as e:
                print(f"Error escaneando con {rule_file.name}: {e}")
                continue
        
        return "\n".join(results) if results else "No se detectaron coincidencias YARA"
    
    except Exception as e:
        print(f"Error ejecutando YARA: {e}")
        return None

def main():
    if len(sys.argv) < 2:
        print("Uso: python3 scan_yara.py <archivo> [ruta_reglas]")
        sys.exit(1)
    
    filepath = sys.argv[1]
    rules_path = sys.argv[2] if len(sys.argv) > 2 else "/malware_analysis/yara_rules"
    
    print(f"Escaneando con YARA: {filepath}")
    print(f"Reglas: {rules_path}")
    
    yara_output = scan_yara(filepath, rules_path)
    
    if not yara_output:
        sys.exit(1)
    
    # Generar nombre de archivo de salida
    output_file = Path(filepath).stem + '_yara_scan.txt'
    
    # Guardar en archivo
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(f"=== YARA Scan ===\n")
        f.write(f"Archivo: {filepath}\n")
        f.write(f"Reglas: {rules_path}\n\n")
        f.write(yara_output)
    
    print(f"\nGuardado en: {output_file}")
    print(yara_output)

if __name__ == "__main__":
    main()
