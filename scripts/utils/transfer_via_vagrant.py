#!/usr/bin/env python3
"""
Transfiere appy_patched.exe a la VM Windows via vagrant winrm.
Ejecutar desde Ubuntu (donde está el Vagrantfile).
"""
import subprocess, base64, os, sys

VAGRANT_DIR = "/home/vagrant/malware_analysis"  # en Ubuntu
SRC_B64     = "/tmp/appy_patched.b64"
DST_WIN     = r"C:\malware_samples\beket_extracted\appy_patched.exe"

with open(SRC_B64, 'r') as f:
    b64_data = f.read().strip()

total_len = len(b64_data)
print(f"B64 total: {total_len} chars")

CHUNK = 15000  # caracteres por chunk (WinRM tolera ~16KB)

def winrm(cmd):
    result = subprocess.run(
        ["vagrant", "winrm", "windows", "-s", "powershell", "-c", cmd],
        cwd=VAGRANT_DIR,
        capture_output=True, text=True
    )
    return result.stdout.strip(), result.stderr.strip(), result.returncode

# Inicializar archivo destino vacio
out, err, rc = winrm(f"[System.IO.File]::WriteAllBytes('{DST_WIN}', [byte[]]@()); Write-Host 'init_ok'")
print(f"Init: {out} {err}")

# Enviar chunks
n_chunks = (total_len + CHUNK - 1) // CHUNK
for i in range(n_chunks):
    chunk = b64_data[i*CHUNK:(i+1)*CHUNK]
    # Comando PS: decodificar chunk y hacer append al archivo
    ps_cmd = (
        f"$b = '{chunk}';"
        f"$bytes = [Convert]::FromBase64String("
        f"[Convert]::ToBase64String([Convert]::FromBase64String($b)));"
        # Trick: usar los bytes raw del chunk (no es b64 de b64, es directo)
        # Mejor: escribir el chunk como string y luego convertir desde b64
    )
    # Simplificar: el chunk YA es b64, solo hay que hacer FromBase64 y append
    ps_cmd = (
        f"$chunk='{chunk}';"
        f"$pos={i*CHUNK};"
        f"$b=[System.Text.Encoding]::ASCII.GetBytes($chunk);"
        f"$raw=[Convert]::FromBase64CharArray([char[]]$chunk,0,$chunk.Length);"
        f"$fs=[System.IO.File]::OpenWrite('{DST_WIN}');"
        f"$fs.Seek(0,[System.IO.SeekOrigin]::End)|Out-Null;"
        f"$fs.Write($raw,0,$raw.Length);"
        f"$fs.Close();"
        f"Write-Host 'chunk_{i}_ok'"
    )
    out, err, rc = winrm(ps_cmd)
    if "chunk_{}_ok".format(i) in out:
        sys.stdout.write(f"\r  Chunk {i+1}/{n_chunks} OK")
        sys.stdout.flush()
    else:
        print(f"\n  ERROR chunk {i}: out={out} err={err}")
        sys.exit(1)

print()
# Verificar tamaño
out, err, rc = winrm(f"(Get-Item '{DST_WIN}').Length")
print(f"Tamaño remoto: {out.strip()} bytes")
print("Transferencia completada.")
