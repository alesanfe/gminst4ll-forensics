#!/bin/bash
# Análisis de archivos embebidos con binwalk
# Binwalk extrae archivos embebidos dentro de otros archivos

if [ $# -lt 1 ]; then
    echo "Uso: ./analyze_binwalk.sh <archivo>"
    exit 1
fi

FILEPATH="$1"
OUTPUT_DIR="${FILEPATH}_binwalk_extracted"

echo "Analizando con binwalk: $FILEPATH"

# Crear directorio de salida
mkdir -p "$OUTPUT_DIR"

# Análisis de firma
echo "=== Análisis de firma ==="
binwalk "$FILEPATH" > "${FILEPATH}_binwalk_signature.txt"

# Extracción de archivos embebidos
echo "=== Extracción de archivos embebidos ==="
binwalk -e -M "$FILEPATH" -d "$OUTPUT_DIR"

# Análisis de entropía
echo "=== Análisis de entropía ==="
binwalk -E "$FILEPATH" > "${FILEPATH}_binwalk_entropy.txt"

echo "Resultados guardados en:"
echo "  - ${FILEPATH}_binwalk_signature.txt"
echo "  - ${FILEPATH}_binwalk_entropy.txt"
echo "  - $OUTPUT_DIR (archivos extraídos)"
