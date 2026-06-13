#!/bin/bash
# Análisis profundo con radare2
# radare2 es un framework de reverse engineering completo

if [ $# -lt 1 ]; then
    echo "Uso: ./analyze_radare2.sh <archivo>"
    exit 1
fi

FILEPATH="$1"

echo "Analizando con radare2: $FILEPATH"

# Verificar si es un archivo binario
if ! file "$FILEPATH" | grep -q -E "(PE32|ELF|executable)"; then
    echo "Error: El archivo no parece ser un ejecutable"
    exit 1
fi

OUTPUT_DIR="${FILEPATH}_radare2_analysis"
mkdir -p "$OUTPUT_DIR"

# Análisis de información básica
echo "=== Información básica (rabin2) ==="
rabin2 -I "$FILEPATH" > "$OUTPUT_DIR/rabin2_info.txt"

# Análisis de strings
echo "=== Strings (rabin2 -z) ==="
rabin2 -z "$FILEPATH" > "$OUTPUT_DIR/rabin2_strings.txt"

# Análisis de imports
echo "=== Imports (rabin2 -i) ==="
rabin2 -i "$FILEPATH" > "$OUTPUT_DIR/rabin2_imports.txt"

# Análisis de exports
echo "=== Exports (rabin2 -e) ==="
rabin2 -e "$FILEPATH" > "$OUTPUT_DIR/rabin2_exports.txt"

# Análisis de secciones
echo "=== Secciones (rabin2 -S) ==="
rabin2 -S "$FILEPATH" > "$OUTPUT_DIR/rabin2_sections.txt"

# Análisis de símbolos
echo "=== Símbolos (rabin2 -s) ==="
rabin2 -s "$FILEPATH" > "$OUTPUT_DIR/rabin2_symbols.txt"

# Análisis de entradas
echo "=== Entradas (rabin2 -E) ==="
rabin2 -E "$FILEPATH" > "$OUTPUT_DIR/rabin2_entries.txt"

# Análisis de recursos (si es PE)
if file "$FILEPATH" | grep -q "PE32"; then
    echo "=== Recursos (rabin2 -r) ==="
    rabin2 -r "$FILEPATH" > "$OUTPUT_DIR/rabin2_resources.txt" 2>/dev/null || echo "No se pudo analizar recursos"
fi

echo "Resultados guardados en: $OUTPUT_DIR"
echo "Archivos generados:"
ls -la "$OUTPUT_DIR"
