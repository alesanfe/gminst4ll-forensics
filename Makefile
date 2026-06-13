# Makefile para análisis automatizado de malware - GMinst4ll 2.03.rar
# Autor: Malware Analyst
# Fecha: 11 de junio de 2026

# Variables
SAMPLE = malware_samples/GMinst4ll\ 2.03.rar
OUTPUT_DIR = analysis_output
DATE = $(shell date +%Y%m%d_%H%M%S)
REPORT_DIR = $(OUTPUT_DIR)/report_$(DATE)
VAGRANT_CMD = vagrant ssh ubuntu -c
SCRIPTS_DIR = scripts
SCRIPTS_STATIC = $(SCRIPTS_DIR)/static
SCRIPTS_DYNAMIC = $(SCRIPTS_DIR)/dynamic
SCRIPTS_PULSAR = $(SCRIPTS_DIR)/pulsar
SCRIPTS_UTILS = $(SCRIPTS_DIR)/utils
DATA_DIR = data
TOOLS_DIR = tools

# Directorios
.PHONY: all setup clean phases report hashes strings pulsar-patch pulsar-extract

# Objetivo principal: ejecutar todas las fases
all: setup phase1 phase2 phase3 phase4 phase5 phase6 phase7 phase8 phase9 phase10 phase11 phase12 phase13 report

# Configurar entorno
setup:
	@echo "=== Configurando entorno de análisis ==="
	@mkdir -p $(REPORT_DIR)
	@mkdir -p $(REPORT_DIR)/phase1
	@mkdir -p $(REPORT_DIR)/phase2
	@mkdir -p $(REPORT_DIR)/phase3
	@mkdir -p $(REPORT_DIR)/phase4
	@mkdir -p $(REPORT_DIR)/phase5
	@mkdir -p $(REPORT_DIR)/phase6
	@mkdir -p $(REPORT_DIR)/phase7
	@mkdir -p $(REPORT_DIR)/phase8
	@mkdir -p $(REPORT_DIR)/phase9
	@mkdir -p $(REPORT_DIR)/phase10
	@mkdir -p $(REPORT_DIR)/phase11
	@mkdir -p $(REPORT_DIR)/phase12
	@mkdir -p $(REPORT_DIR)/phase13
	@echo "Entorno configurado en $(REPORT_DIR)"

# Fase 1: Análisis Estático - Hashes y Metadatos
phase1:
	@echo "=== Fase 1: Análisis Estático - Hashes y Metadatos ==="
	@echo "Comando: vagrant ssh ubuntu -c 'cd /malware_samples && md5sum \"$(SAMPLE)\" && sha1sum \"$(SAMPLE)\" && sha256sum \"$(SAMPLE)\" && file \"$(SAMPLE)\" && ls -la \"$(SAMPLE)\"'" > $(REPORT_DIR)/phase1/commands.txt
	@$(VAGRANT_CMD) "cd /malware_samples && md5sum '$(SAMPLE)' && sha1sum '$(SAMPLE)' && sha256sum '$(SAMPLE)' && file '$(SAMPLE)' && ls -la '$(SAMPLE)'" > $(REPORT_DIR)/phase1/hashes_metadata.txt 2>&1
	@echo "Comando: vagrant ssh ubuntu -c 'cd /malware_samples && 7z l \"$(SAMPLE)\"'" >> $(REPORT_DIR)/phase1/commands.txt
	@$(VAGRANT_CMD) "cd /malware_samples && 7z l '$(SAMPLE)'" > $(REPORT_DIR)/phase1/rar_structure.txt 2>&1
	@echo "Fase 1 completada"

# Fase 2: Descompresión del RAR Externo
phase2:
	@echo "=== Fase 2: Descompresión del RAR Externo ==="
	@echo "Comando: vagrant ssh ubuntu -c 'cd /home/vagrant && mkdir -p extracted && cp /malware_samples/\"$(SAMPLE)\" extracted/ && cd extracted && 7z x -p4204 -y \"$(SAMPLE)\"'" > $(REPORT_DIR)/phase2/commands.txt
	@$(VAGRANT_CMD) "cd /home/vagrant && mkdir -p extracted && cp /malware_samples/'$(SAMPLE)' extracted/ && cd extracted && 7z x -p4204 -y '$(SAMPLE)'" > $(REPORT_DIR)/phase2/extraction_output.txt 2>&1
	@echo "Comando: vagrant ssh ubuntu -c 'cd /home/vagrant/extracted && ls -la'" >> $(REPORT_DIR)/phase2/commands.txt
	@$(VAGRANT_CMD) "cd /home/vagrant/extracted && ls -la" > $(REPORT_DIR)/phase2/extracted_files.txt 2>&1
	@echo "Fase 2 completada"

# Fase 3: Cracking del RAR Interno
phase3:
	@echo "=== Fase 3: Cracking del RAR Interno ==="
	@echo "Comando: vagrant ssh ubuntu -c 'cd /home/vagrant/extracted && 7z l GMinst4ll\ 2.03.rar'" > $(REPORT_DIR)/phase3/commands.txt
	@$(VAGRANT_CMD) "cd /home/vagrant/extracted && 7z l 'GMinst4ll 2.03.rar'" > $(REPORT_DIR)/phase3/internal_rar_structure.txt 2>&1
	@echo "Comando: vagrant ssh ubuntu -c 'cd /home/vagrant/extracted && rar2john \"GMinst4ll 2.03.rar\" > hash.txt && john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt'" >> $(REPORT_DIR)/phase3/commands.txt
	@$(VAGRANT_CMD) "cd /home/vagrant/extracted && rar2john 'GMinst4ll 2.03.rar' > hash.txt 2>&1 || echo 'rar2john not available'" > $(REPORT_DIR)/phase3/john_cracking.txt 2>&1
	@echo "Fase 3 completada"

# Fase 4: Análisis de Strings y Estructuras
phase4:
	@echo "=== Fase 4: Análisis de Strings y Estructuras ==="
	@echo "Comando: vagrant ssh ubuntu -c 'cd /home/vagrant/extracted && strings GMinst4ll\ 2.03.rar > strings_all.txt'" > $(REPORT_DIR)/phase4/commands.txt
	@$(VAGRANT_CMD) "cd /home/vagrant/extracted && strings 'GMinst4ll 2.03.rar' > strings_all.txt" > $(REPORT_DIR)/phase4/strings_extraction.txt 2>&1
	@echo "Comando: vagrant ssh ubuntu -c 'cd /home/vagrant/extracted && grep -i \"http\" strings_all.txt'" >> $(REPORT_DIR)/phase4/commands.txt
	@$(VAGRANT_CMD) "cd /home/vagrant/extracted && grep -i 'http' strings_all.txt" > $(REPORT_DIR)/phase4/strings_urls.txt 2>&1
	@echo "Comando: vagrant ssh ubuntu -c 'cd /home/vagrant/extracted && grep -i \"C:\\\\\" strings_all.txt'" >> $(REPORT_DIR)/phase4/commands.txt
	@$(VAGRANT_CMD) "cd /home/vagrant/extracted && grep -i 'C:\\' strings_all.txt" > $(REPORT_DIR)/phase4/strings_paths.txt 2>&1
	@echo "Fase 4 completada"

# Fase 5: Análisis de Capacidades (CAPA)
phase5:
	@echo "=== Fase 5: Análisis de Capacidades (CAPA) ==="
	@echo "Comando: vagrant ssh ubuntu -c 'source /opt/malware-venv/bin/activate && cd /home/vagrant/extracted && python3 -m capa GMinst4ll\ 2.03.rar'" > $(REPORT_DIR)/phase5/commands.txt
	@$(VAGRANT_CMD) "source /opt/malware-venv/bin/activate && cd /home/vagrant/extracted && python3 -m capa 'GMinst4ll 2.03.rar'" > $(REPORT_DIR)/phase5/capa_analysis.txt 2>&1
	@echo "Fase 5 completada"

# Fase 6: Análisis de Tráfico de Red (si se crackea)
phase6:
	@echo "=== Fase 6: Análisis de Tráfico de Red ==="
	@echo "Esta fase requiere ejecución dinámica en Windows VM" > $(REPORT_DIR)/phase6/network_analysis.txt
	@echo "Comandos a ejecutar en Windows:" >> $(REPORT_DIR)/phase6/network_analysis.txt
	@echo "- Iniciar Wireshark antes de ejecutar el malware" >> $(REPORT_DIR)/phase6/network_analysis.txt
	@echo "- Capturar tráfico en todas las interfaces" >> $(REPORT_DIR)/phase6/network_analysis.txt
	@echo "- Analizar conexiones salientes, dominios, protocolos" >> $(REPORT_DIR)/phase6/network_analysis.txt
	@echo "Fase 6 completada"

# Fase 7: Análisis de Persistencia (si se crackea)
phase7:
	@echo "=== Fase 7: Análisis de Persistencia ==="
	@echo "Esta fase requiere ejecución dinámica en Windows VM" > $(REPORT_DIR)/phase7/persistence_analysis.txt
	@echo "Comandos a ejecutar en Windows:" >> $(REPORT_DIR)/phase7/persistence_analysis.txt
	@echo "- RegShot para capturar cambios en registro" >> $(REPORT_DIR)/phase7/persistence_analysis.txt
	@echo "- Autoruns para detectar persistencia" >> $(REPORT_DIR)/phase7/persistence_analysis.txt
	@echo "- Process Monitor para monitorear actividad" >> $(REPORT_DIR)/phase7/persistence_analysis.txt
	@echo "Fase 7 completada"

# Fase 8: Análisis de Exfiltración (si se crackea)
phase8:
	@echo "=== Fase 8: Análisis de Exfiltración ==="
	@echo "Esta fase requiere ejecución dinámica en Windows VM" > $(REPORT_DIR)/phase8/exfiltration_analysis.txt
	@echo "Comandos a ejecutar en Windows:" >> $(REPORT_DIR)/phase8/exfiltration_analysis.txt
	@echo "- Monitorizar archivos creados/modificados" >> $(REPORT_DIR)/phase8/exfiltration_analysis.txt
	@echo "- Capturar tráfico de red saliente" >> $(REPORT_DIR)/phase8/exfiltration_analysis.txt
	@echo "- Analizar canales encubiertos (Telegram, Dropbox, etc.)" >> $(REPORT_DIR)/phase8/exfiltration_analysis.txt
	@echo "Fase 8 completada"

# Fase 9: Análisis de Evasión (si se crackea)
phase9:
	@echo "=== Fase 9: Análisis de Evasión ==="
	@echo "Esta fase requiere ejecución dinámica en Windows VM" > $(REPORT_DIR)/phase9/evasion_analysis.txt
	@echo "Comandos a ejecutar en Windows:" >> $(REPORT_DIR)/phase9/evasion_analysis.txt
	@echo "- API Monitor para detectar anti-debugging" >> $(REPORT_DIR)/phase9/evasion_analysis.txt
	@echo "- Process Hacker para detectar anti-VM" >> $(REPORT_DIR)/phase9/evasion_analysis.txt
	@echo "- Analizar checks de entorno" >> $(REPORT_DIR)/phase9/evasion_analysis.txt
	@echo "Fase 9 completada"

# Fase 10: Análisis de Memoria (si se crackea)
phase10:
	@echo "=== Fase 10: Análisis de Memoria ==="
	@echo "Esta fase requiere ejecución dinámica en Windows VM" > $(REPORT_DIR)/phase10/memory_analysis.txt
	@echo "Comandos a ejecutar en Windows:" >> $(REPORT_DIR)/phase10/memory_analysis.txt
	@echo "- WinPmem o DumpIt para capturar memoria" >> $(REPORT_DIR)/phase10/memory_analysis.txt
	@echo "- Volatility3 para analizar dump" >> $(REPORT_DIR)/phase10/memory_analysis.txt
	@echo "- Buscar strings desencriptadas, módulos inyectados" >> $(REPORT_DIR)/phase10/memory_analysis.txt
	@echo "Fase 10 completada"

# Fase 11: Análisis OSINT
phase11:
	@echo "=== Fase 11: Análisis OSINT ==="
	@echo "Comando: vagrant ssh ubuntu -c 'whois pastebin.com'" > $(REPORT_DIR)/phase11/commands.txt
	@$(VAGRANT_CMD) "whois pastebin.com" > $(REPORT_DIR)/phase11/osint_pastebin.txt 2>&1
	@echo "Comando: vagrant ssh ubuntu -c 'whois dropbox.com'" >> $(REPORT_DIR)/phase11/commands.txt
	@$(VAGRANT_CMD) "whois dropbox.com" > $(REPORT_DIR)/phase11/osint_dropbox.txt 2>&1
	@echo "Comando: vagrant ssh ubuntu -c 'whois reddit.com'" >> $(REPORT_DIR)/phase11/commands.txt
	@$(VAGRANT_CMD) "whois reddit.com" > $(REPORT_DIR)/phase11/osint_reddit.txt 2>&1
	@echo "Fase 11 completada"

# Fase 12: Análisis de Detección
phase12:
	@echo "=== Fase 12: Análisis de Detección ==="
	@echo "Comando: vagrant ssh ubuntu -c 'source /opt/malware-venv/bin/activate && cd /home/vagrant/extracted && yara -r /malware_analysis/yara_rules/malware/ GMinst4ll\ 2.03.rar'" > $(REPORT_DIR)/phase12/commands.txt
	@$(VAGRANT_CMD) "source /opt/malware-venv/bin/activate && cd /home/vagrant/extracted && yara -r /malware_analysis/yara_rules/malware/ 'GMinst4ll 2.03.rar'" > $(REPORT_DIR)/phase12/yara_scan.txt 2>&1
	@echo "Comando: vagrant ssh ubuntu -c 'clamscan --infected --bell /home/vagrant/extracted/GMinst4ll\ 2.03.rar'" >> $(REPORT_DIR)/phase12/commands.txt
	@$(VAGRANT_CMD) "clamscan --infected --bell /home/vagrant/extracted/'GMinst4ll 2.03.rar'" > $(REPORT_DIR)/phase12/clamav_scan.txt 2>&1
	@echo "Fase 12 completada"

# Fase 13: Conclusiones y Recomendaciones
phase13:
	@echo "=== Fase 13: Conclusiones y Recomendaciones ==="
	@echo "=== Resumen de Hallazgos ===" > $(REPORT_DIR)/phase13/conclusions.txt
	@echo "Esta fase se completará después de ejecutar todas las fases anteriores" >> $(REPORT_DIR)/phase13/conclusions.txt
	@echo "Fase 13 completada"

# Generar reporte consolidado
report:
	@echo "=== Generando reporte consolidado ==="
	@echo "# Análisis de Malware - Reporte Automatizado" > $(REPORT_DIR)/consolidated_report.md
	@echo "" >> $(REPORT_DIR)/consolidated_report.md
	@echo "Fecha: $(DATE)" >> $(REPORT_DIR)/consolidated_report.md
	@echo "Muestra: $(SAMPLE)" >> $(REPORT_DIR)/consolidated_report.md
	@echo "" >> $(REPORT_DIR)/consolidated_report.md
	@echo "## Resumen de Fases" >> $(REPORT_DIR)/consolidated_report.md
	@echo "" >> $(REPORT_DIR)/consolidated_report.md
	@for phase in phase1 phase2 phase3 phase4 phase5 phase6 phase7 phase8 phase9 phase10 phase11 phase12 phase13; do \
		echo "### $$phase" >> $(REPORT_DIR)/consolidated_report.md; \
		echo '```' >> $(REPORT_DIR)/consolidated_report.md; \
		cat $(REPORT_DIR)/$$phase/*.txt >> $(REPORT_DIR)/consolidated_report.md 2>/dev/null || echo "No data" >> $(REPORT_DIR)/consolidated_report.md; \
		echo '```' >> $(REPORT_DIR)/consolidated_report.md; \
		echo "" >> $(REPORT_DIR)/consolidated_report.md; \
	done
	@echo "Reporte consolidado generado en $(REPORT_DIR)/consolidated_report.md"

# Limpiar directorios de análisis
clean:
	@echo "=== Limpiando directorios de análisis ==="
	@rm -rf $(OUTPUT_DIR)
	@echo "Directorios limpiados"

# Ayuda
help:
	@echo "Makefile para análisis automatizado de malware - GMinst4ll 2.03.rar"
	@echo ""
	@echo "Objetivos:"
	@echo "  all        - Ejecutar todas las fases de análisis"
	@echo "  setup      - Configurar entorno de análisis"
	@echo "  phase1     - Análisis Estático - Hashes y Metadatos"
	@echo "  phase2     - Descompresión del RAR Externo"
	@echo "  phase3     - Cracking del RAR Interno"
	@echo "  phase4     - Análisis de Strings y Estructuras"
	@echo "  phase5     - Análisis de Capacidades (CAPA)"
	@echo "  phase6     - Análisis de Tráfico de Red"
	@echo "  phase7     - Análisis de Persistencia"
	@echo "  phase8     - Análisis de Exfiltración"
	@echo "  phase9     - Análisis de Evasión"
	@echo "  phase10    - Análisis de Memoria"
	@echo "  phase11    - Análisis OSINT"
	@echo "  phase12    - Análisis de Detección"
	@echo "  phase13    - Conclusiones y Recomendaciones"
	@echo "  report     - Generar reporte consolidado"
	@echo "  clean      - Limpiar directorios de análisis"
	@echo "  help       - Mostrar esta ayuda"
	@echo ""
	@echo "Scripts de análisis:"
	@echo "  hashes     - Calcular hashes de archivos (usa scripts/static/extract_hashes.py)"
	@echo "  strings    - Extraer strings de archivos (usa scripts/static/extract_strings.py)"
	@echo "  pulsar-patch - Parchear Pulsar RAT para saltar anti-VM (usa scripts/pulsar/pulsar_patch.py)"
	@echo "  pulsar-extract - Extraer configuración C2 de Pulsar RAT (usa scripts/pulsar/pulsar_extract_c2.py)"

# Objetivos para scripts de análisis
hashes:
	@echo "=== Calculando hashes de archivos ==="
	@$(VAGRANT_CMD) "cd /malware_samples && python3 $(SCRIPTS_STATIC)/extract_hashes.py 'TREZ_cor 4.52.3.exe'"

strings:
	@echo "=== Extrayendo strings de archivos ==="
	@$(VAGRANT_CMD) "cd /malware_samples && python3 $(SCRIPTS_STATIC)/extract_strings.py 'TREZ_cor 4.52.3.exe' 8"

pulsar-patch:
	@echo "=== Parcheando Pulsar RAT ==="
	@$(VAGRANT_CMD) "cd /home/vagrant/beket_extracted2 && python3 $(SCRIPTS_PULSAR)/pulsar_patch.py"

pulsar-extract:
	@echo "=== Extrayendo configuración C2 de Pulsar RAT ==="
	@$(VAGRANT_CMD) "cd /home/vagrant/beket_extracted2 && python3 $(SCRIPTS_PULSAR)/pulsar_extract_c2.py"
