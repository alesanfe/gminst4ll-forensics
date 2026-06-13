#!/bin/bash
# Script automatizado para ejecutar todas las fases de análisis en VM Ubuntu
# Ejecuta análisis de hashes, PE, strings y YARA en todas las muestras

set -e

# Activar entorno virtual
source /opt/malware-venv/bin/activate

# Directorio de muestras
SAMPLES_DIR="/malware_samples"
SCRIPTS_DIR="/host_scripts/static"
PULSAR_SCRIPTS_DIR="/host_scripts/pulsar"

# Directorio de resultados
RESULTS_DIR="/malware_analysis/results"
mkdir -p "$RESULTS_DIR"

echo "========================================"
echo "Análisis Automatizado de Malware"
echo "========================================"
echo "Directorio de muestras: $SAMPLES_DIR"
echo "Directorio de resultados: $RESULTS_DIR"
echo "========================================"

# Fase 2: Análisis Estático Básico (hashes)
echo ""
echo "========================================"
echo "Fase 2: Análisis Estático Básico (hashes)"
echo "========================================"

python3 "$SCRIPTS_DIR/extract_hashes.py" "$SAMPLES_DIR/pulsar_rat/appy_patched.exe" || echo "Error analizando appy_patched.exe"
python3 "$SCRIPTS_DIR/extract_hashes.py" "$SAMPLES_DIR/rust_executables/appy.exe" || echo "Error analizando appy.exe"
python3 "$SCRIPTS_DIR/extract_hashes.py" "$SAMPLES_DIR/github_c2/Windows_Compatibility_Agent.exe" || echo "Error analizando Windows_Compatibility_Agent.exe"
python3 "$SCRIPTS_DIR/extract_hashes.py" "$SAMPLES_DIR/github_c2/Windows_Compatibility_Agent_Host.exe" || echo "Error analizando Windows_Compatibility_Agent_Host.exe"
python3 "$SCRIPTS_DIR/extract_hashes.py" "$SAMPLES_DIR/github_c2/kamzat.exe" || echo "Error analizando kamzat.exe"
python3 "$SCRIPTS_DIR/extract_hashes.py" "$SAMPLES_DIR/github_c2/postevak.exe" || echo "Error analizando postevak.exe"

# Fase 3: Análisis de Metadatos y Estructura (PE)
echo ""
echo "========================================"
echo "Fase 3: Análisis de Metadatos y Estructura (PE)"
echo "========================================"

python3 "$SCRIPTS_DIR/extract_pe_info.py" "$SAMPLES_DIR/pulsar_rat/appy_patched.exe" || echo "Error analizando appy_patched.exe"
python3 "$SCRIPTS_DIR/extract_pe_info.py" "$SAMPLES_DIR/rust_executables/appy.exe" || echo "Error analizando appy.exe"
python3 "$SCRIPTS_DIR/extract_pe_info.py" "$SAMPLES_DIR/github_c2/Windows_Compatibility_Agent.exe" || echo "Error analizando Windows_Compatibility_Agent.exe"
python3 "$SCRIPTS_DIR/extract_pe_info.py" "$SAMPLES_DIR/github_c2/Windows_Compatibility_Agent_Host.exe" || echo "Error analizando Windows_Compatibility_Agent_Host.exe"
python3 "$SCRIPTS_DIR/extract_pe_info.py" "$SAMPLES_DIR/github_c2/kamzat.exe" || echo "Error analizando kamzat.exe"
python3 "$SCRIPTS_DIR/extract_pe_info.py" "$SAMPLES_DIR/github_c2/postevak.exe" || echo "Error analizando postevak.exe"

# Fase 5: Análisis de Strings y Patrones
echo ""
echo "========================================"
echo "Fase 5: Análisis de Strings y Patrones"
echo "========================================"

python3 "$SCRIPTS_DIR/extract_strings.py" "$SAMPLES_DIR/pulsar_rat/appy_patched.exe" 8 || echo "Error analizando appy_patched.exe"
python3 "$SCRIPTS_DIR/extract_strings.py" "$SAMPLES_DIR/rust_executables/appy.exe" 8 || echo "Error analizando appy.exe"
python3 "$SCRIPTS_DIR/extract_strings.py" "$SAMPLES_DIR/github_c2/Windows_Compatibility_Agent.exe" 8 || echo "Error analizando Windows_Compatibility_Agent.exe"
python3 "$SCRIPTS_DIR/extract_strings.py" "$SAMPLES_DIR/github_c2/Windows_Compatibility_Agent_Host.exe" 8 || echo "Error analizando Windows_Compatibility_Agent_Host.exe"
python3 "$SCRIPTS_DIR/extract_strings.py" "$SAMPLES_DIR/github_c2/kamzat.exe" 8 || echo "Error analizando kamzat.exe"
python3 "$SCRIPTS_DIR/extract_strings.py" "$SAMPLES_DIR/github_c2/postevak.exe" 8 || echo "Error analizando postevak.exe"

# Fase 9: Análisis Profundo Pulsar RAT (solo para appy_patched.exe)
echo ""
echo "========================================"
echo "Fase 9: Análisis Profundo Pulsar RAT"
echo "========================================"

python3 "$PULSAR_SCRIPTS_DIR/pulsar_find_blobs.py" "$SAMPLES_DIR/pulsar_rat/appy_patched.exe" || echo "Error analizando Pulsar RAT"

# Fase 4: Escaneo YARA (si hay reglas disponibles)
echo ""
echo "========================================"
echo "Fase 4: Escaneo YARA"
echo "========================================"

if [ -d "/malware_analysis/yara_rules" ]; then
    python3 "$SCRIPTS_DIR/scan_yara.py" "$SAMPLES_DIR/pulsar_rat/appy_patched.exe" /malware_analysis/yara_rules || echo "Error escaneando appy_patched.exe"
    python3 "$SCRIPTS_DIR/scan_yara.py" "$SAMPLES_DIR/rust_executables/appy.exe" /malware_analysis/yara_rules || echo "Error escaneando appy.exe"
    python3 "$SCRIPTS_DIR/scan_yara.py" "$SAMPLES_DIR/github_c2/Windows_Compatibility_Agent.exe" /malware_analysis/yara_rules || echo "Error escaneando Windows_Compatibility_Agent.exe"
    python3 "$SCRIPTS_DIR/scan_yara.py" "$SAMPLES_DIR/github_c2/Windows_Compatibility_Agent_Host.exe" /malware_analysis/yara_rules || echo "Error escaneando Windows_Compatibility_Agent_Host.exe"
    python3 "$SCRIPTS_DIR/scan_yara.py" "$SAMPLES_DIR/github_c2/kamzat.exe" /malware_analysis/yara_rules || echo "Error escaneando kamzat.exe"
    python3 "$SCRIPTS_DIR/scan_yara.py" "$SAMPLES_DIR/github_c2/postevak.exe" /malware_analysis/yara_rules || echo "Error escaneando postevak.exe"
else
    echo "Directorio de reglas YARA no encontrado, saltando escaneo YARA"
fi

echo ""
echo "========================================"
echo "Análisis Completado"
echo "========================================"
echo "Resultados guardados en: $SAMPLES_DIR"
echo "========================================"
