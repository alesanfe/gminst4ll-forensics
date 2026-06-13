# Scripts de Análisis de Malware

Este directorio contiene scripts organizados por categoría para el análisis de malware GMinst4ll y Pulsar RAT.

## Estructura de Directorios

### `dynamic/` - Análisis Dinámico
Scripts para ejecución de malware en VM Windows y análisis de dumps de memoria.

- `dynamic_analysis.ps1` - Protocolo completo de análisis dinámico (pre/post ejecución)
- `run_and_dump.ps1` - Ejecuta malware y crea dump de memoria con ProcDump
- `analyze_dump.ps1` - Analiza dump de memoria buscando IPs, dominios y strings C2
- `analyze_cleaned.ps1` - Analiza dump de memoria parcheado
- `analyze_cleaned_blobs.ps1` - Analiza blobs de datos en dump limpio
- `download_dump.ps1` - Descarga dump de memoria desde VM
- `get_crash_log.ps1` - Obtiene logs de crash de aplicación
- `backup.ps1` - Crea backup de archivos de análisis
- `restore_clean.ps1` - Restaura versión limpia de archivos
- `send_patched.ps1` - Envía ejecutable parcheado a VM
- `send_patched_winrm.ps1` - Envía ejecutable parcheado vía WinRM

### `pulsar/` - Análisis Pulsar RAT
Scripts específicos para extracción de configuración C2 y parcheo de Pulsar RAT.

- `pulsar_extract_c2.py` - Extrae y descifra blobs AES-GCM de Pulsar RAT
- `pulsar_find_blobs.py` - Busca blobs cifrados en el binario
- `pulsar_patch.py` - Parchea ejecutable para saltar checks anti-VM
- `pulsar_patch_win.py` - Parcheo específico para Windows
- `pulsar_find_antivm.py` - Identifica checks anti-VM
- `pulsar_key_trace.py` - Rastrea clave AES en memoria
- `pulsar_map.py` - Mapea estructura del binario
- `pulsar_cctor_il.py` - Analiza IL de static constructors
- `pulsar_cctor_target.py` - Identifica objetivos de .cctor
- `pulsar_extract_cleaned.py` - Extrae datos de versión parcheada
- `pulsar_us_raw.py` - Extrae heap #US sin procesar

### `static/` - Análisis Estático
Scripts para análisis estático de ejecutables .NET y binarios PE.

- `dnfile_inspect.py` - Inspección básica de archivos .NET con dnfile
- `extract_hashes.py` - Calcula MD5, SHA1, SHA256 y ssdeep de archivos
- `extract_strings.py` - Extrae strings con filtros para análisis de malware (URLs, IPs, rutas, registry)
- `extract_pe_info.py` - Extrae información detallada de archivos PE (secciones, imports, exports)

### `utils/` - Utilidades
Scripts de utilidad general para el flujo de trabajo.

- `make_b64.py` - Convierte archivos a base64
- `transfer_via_vagrant.py` - Transfiere archivos vía Vagrant

## Uso

### Análisis Dinámico
```powershell
# En VM Windows
cd C:\malware_samples
..\scripts\dynamic\dynamic_analysis.ps1 -Sample "appy.exe" -RunSeconds 120
```

### Análisis Pulsar RAT
```bash
# En VM Linux
python3 scripts/pulsar/pulsar_extract_c2.py
python3 scripts/pulsar/pulsar_patch.py
```

## Requisitos

- Python 3.x con librerías: dnfile, pycryptodome
- PowerShell 5.1+ para scripts .ps1
- ProcDump para dumps de memoria
- VM Windows con herramientas de análisis instaladas
