#!/bin/bash
# Escaneo antivirus con ClamAV
# ClamAV es un antivirus open-source para detectar malware

if [ $# -lt 1 ]; then
    echo "Uso: ./scan_clamav.sh <archivo> [directorio_salida]"
    exit 1
fi

FILEPATH="$1"
OUTPUT_DIR="${2:-.}"

echo "Escaneando con ClamAV: $FILEPATH"

# Actualizar firmas de virus (si no se ha hecho recientemente)
echo "Actualizando firmas de virus..."
freshclam --quiet

# Escanear archivo
echo "=== Escaneo ClamAV ==="
clamscan --infected --bell --verbose "$FILEPATH" > "${FILEPATH}_clamav_scan.txt" 2>&1

# Guardar resultado en directorio de salida
cp "${FILEPATH}_clamav_scan.txt" "$OUTPUT_DIR/"

echo "Resultado guardado en: ${FILEPATH}_clamav_scan.txt"

# Mostrar resumen
if grep -q "Infected files: 0" "${FILEPATH}_clamav_scan.txt"; then
    echo "✅ No se detectaron infecciones"
else
    echo "⚠️ Se detectaron infecciones:"
    grep "Infected files" "${FILEPATH}_clamav_scan.txt"
fi
