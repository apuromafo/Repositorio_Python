"""
Script para descargar paquete .deb de frida-server para iPhone según versión local y arquitectura detectada.

Requisitos:
- Python 3
- paramiko (para conexión SSH y detección arquitectura/remota)
- frida CLI instalado localmente
"""

import paramiko
import subprocess
import sys
import getpass
import urllib.request
import os
import platform
import re

FRIDA_GITHUB_RELEASES = "https://github.com/frida/frida/releases/download"

def detect_environment():
    system = platform.system().lower()
    if 'microsoft' in platform.release().lower() or (os.path.exists('/proc/version') and 'microsoft' in open('/proc/version').read().lower()):
        return 'wsl'
    elif system == 'windows':
        return 'windows'
    else:
        return 'linux'

def get_local_frida_version():
    try:
        result = subprocess.run(['frida', '--version'], capture_output=True, text=True, check=True)
        return result.stdout.strip()
    except Exception as e:
        print(f"[Error] Al obtener versión local de frida: {e}")
        sys.exit(1)

def execute_ssh_command(ssh, command, silent_err=False):
    try:
        stdin, stdout, stderr = ssh.exec_command(command)
        out = stdout.read().decode().strip()
        err = stderr.read().decode().strip()
        if err and not silent_err:
            print(f"[Debug] STDERR ejecutando `{command}`: {err}")
        return out, err
    except Exception as e:
        if not silent_err:
            print(f"[Error] Al ejecutar remoto `{command}`: {e}")
        return '', str(e)

def detect_architecture(ssh):
    comandos = ['uname -m', 'arch']
    arch = None
    for cmd in comandos:
        out, err = execute_ssh_command(ssh, cmd, silent_err=True)
        if out:
            arch = out.strip()
            print(f"[Info] Arquitectura detectada usando `{cmd}`: {arch}")
            break
    if not arch:
        print("[Warn] No se pudo detectar arquitectura remota, se usará 'arm64' por defecto")
        return 'arm64'
    map_arch = {
        'arm64': 'arm64',
        'aarch64': 'arm64',
        'armv7': 'armv7',
        'armv7l': 'armv7',
        'armv8': 'arm64',
        'i386': 'x86',
        'x86_64': 'x86_64',
        'iphone9,1': 'arm64',
    }
    arch_frida = map_arch.get(arch.lower(), 'arm64')
    print(f"[Info] Arquitectura traducida para frida-server: {arch_frida}")
    return arch_frida

def generate_frida_deb_url(version, arch):
    url = f"{FRIDA_GITHUB_RELEASES}/{version}/frida_{version}_iphoneos-{arch}.deb"
    return url

def download_frida_deb(version, arch, save_path):
    url = generate_frida_deb_url(version, arch)
    print(f"[Info] Descargando {url} ...")
    try:
        urllib.request.urlretrieve(url, save_path)
        print(f"[Info] Descarga completada y guardada en: {save_path}")
        return True
    except Exception as e:
        print(f"[Error] Descarga automática falló: {e}")
        # Pedir enlace manual al usuario
        while True:
            url_manual = input("Ingresa manualmente la URL del paquete .deb o 'q' para salir: ").strip()
            if url_manual.lower() == 'q':
                print("Descarga cancelada por el usuario.")
                return False
            try:
                urllib.request.urlretrieve(url_manual, save_path)
                print(f"[Info] Descarga completada y guardada en: {save_path}")
                return True
            except Exception as e2:
                print(f"[Error] No se pudo descargar desde la URL ingresada: {e2}")

def main():
    print("=== Descargador interactivo de paquete frida-server .deb para iPhone ===")
    env = detect_environment()
    print(f"[Info] Entorno detectado: {env.upper()}\n")

    ip = input("IP del iPhone (para detectar arquitectura): ").strip()
    username = input("Usuario SSH (ej: mobile): ").strip()
    password = getpass.getpass("Contraseña SSH: ")

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=username, password=password)
    except Exception as e:
        print(f"[Error] Conexión SSH fallida: {e}")
        sys.exit(1)

    local_version = get_local_frida_version()
    print(f"[Info] Versión local de frida cliente: {local_version}")

    arch = detect_architecture(ssh)
    ssh.close()

    default_filename = f"frida_{local_version}_iphoneos-{arch}.deb"
    print(f"Por defecto se guardará como: {default_filename}")

    save_path = input(f"Introduce ruta completa donde guardar el paquete (Enter para '{default_filename}'): ").strip()
    if not save_path:
        save_path = default_filename

    if os.path.exists(save_path):
        overwrite = input(f"Archivo '{save_path}' ya existe. ¿Sobrescribir? (s/n): ").strip().lower()
        if overwrite != 's':
            print("Descarga cancelada por usuario.")
            sys.exit(0)

    if not download_frida_deb(local_version, arch, save_path):
        print("Error en descarga. Abortando.")
        sys.exit(1)

    print("\n[Terminado] El paquete .deb está listo para que lo instales a tu gusto en el iPhone.\n")
    print("Ejemplo instalación manual vía SSH:\n")
    print(f"scp {save_path} {username}@{ip}:/tmp/frida.deb")
    print(f"ssh {username}@{ip} sudo dpkg -i /tmp/frida.deb\n")

if __name__ == '__main__':
    main()
