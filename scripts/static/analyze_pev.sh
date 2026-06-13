#!/bin/bash
# Análisis PE específico con pev
# PEV (PE Viewer) es una suite de herramientas para análisis de archivos PE

if [ $# -lt 1 ]; then
    echo "Uso: ./analyze_pev.sh <archivo>"
    exit 1
fi

FILEPATH="$1"

echo "Analizando PE con pev: $FILEPATH"

# Verificar si es un archivo PE
if ! file "$FILEPATH" | grep -q "PE32"; then
    echo "Error: El archivo no parece ser un ejecutable PE"
    exit 1
fi

# Análisis general con readpe
echo "=== Análisis general (readpe) ==="
readpe "$FILEPATH" > "${FILEPATH}_pev_readpe.txt"

# Análisis de secciones
echo "=== Análisis de secciones (pescan) ==="
pescan "$FILEPATH" > "${FILEPATH}_pev_pescan.txt"

# Análisis de imports/exports
echo "=== Análisis de imports/exports (peres) ==="
peres "$FILEPATH" > "${FILEPATH}_pev_peres.txt"

# Análisis de recursos
echo "=== Análisis de recursos (pewarn) ==="
pewarn "$FILEPATH" > "${FILEPATH}_pev_pewarn.txt" 2>/dev/null || echo "No se pudo analizar recursos"

echo "Resultados guardados en:"
echo "  - ${FILEPATH}_pev_readpe.txt"
echo "  - ${FILEPATH}_pev_pescan.txt"
echo "  - ${FILEPATH}_pev_peres.txt"
echo "  - ${FILEPATH}_pev_pewarn.txt"
