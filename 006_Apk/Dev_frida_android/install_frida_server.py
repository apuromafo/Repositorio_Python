# install_frida_server.py
import os
import subprocess
import requests
from urllib.parse import urljoin
import lzma  # Para descomprimir archivos .xz

def check_adb_installed():
    """Verifica si adb está instalado en el sistema."""
    try:
        result = subprocess.run(['adb', 'version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode == 0:
            print("[+] ADB está instalado.")
            return True
        else:
            print("[-] ADB no está instalado o no se encuentra en el PATH.")
            return False
    except Exception as e:
        print(f"[-] Error al verificar ADB: {e}")
        return False

def list_connected_devices():
    """Lista los dispositivos conectados mediante adb."""
    try:
        result = subprocess.run(['adb', 'devices'], stdout=subprocess.PIPE, text=True)
        lines = result.stdout.strip().split('\n')
        if len(lines) <= 1:
            print("[-] No hay dispositivos conectados.")
            return []
        devices = [line.split('\t')[0] for line in lines[1:] if 'device' in line]
        if devices:
            print(f"[+] Dispositivos conectados: {', '.join(devices)}")
            return devices
        else:
            print("[-] No hay dispositivos conectados.")
            return []
    except Exception as e:
        print(f"[-] Error al listar dispositivos: {e}")
        return []

def get_device_architecture(device):
    """Obtiene la arquitectura del dispositivo conectado."""
    try:
        result = subprocess.run(['adb', '-s', device, 'shell', 'getprop', 'ro.product.cpu.abi'], 
                                stdout=subprocess.PIPE, text=True)
        architecture = result.stdout.strip()
        if architecture:
            print(f"[+] Arquitectura del dispositivo ({device}): {architecture}")
            return architecture
        else:
            print(f"[-] No se pudo obtener la arquitectura del dispositivo ({device}).")
            return None
    except Exception as e:
        print(f"[-] Error al obtener la arquitectura del dispositivo ({device}): {e}")
        return None

def is_adb_running_as_root(device):
    """Verifica si adbd ya está ejecutándose como root en el dispositivo."""
    try:
        result = subprocess.run(['adb', '-s', device, 'shell', 'id'], stdout=subprocess.PIPE, text=True)
        if "uid=0(root)" in result.stdout:
            print(f"[+] ADB ya está ejecutándose como root en el dispositivo ({device}).")
            return True
        else:
            print(f"[-] ADB no está ejecutándose como root en el dispositivo ({device}).")
            return False
    except Exception as e:
        print(f"[-] Error al verificar si ADB está ejecutándose como root en el dispositivo ({device}): {e}")
        return False

def enable_adb_root(device):
    """Habilita el modo root en el dispositivo."""
    try:
        result = subprocess.run(['adb', '-s', device, 'root'], stdout=subprocess.PIPE, text=True)
        if "restarting adbd as root" in result.stdout:
            print(f"[+] ADB root habilitado en el dispositivo ({device}).")
            return True
        else:
            print(f"[-] No se pudo habilitar ADB root en el dispositivo ({device}).")
            return False
    except Exception as e:
        print(f"[-] Error al habilitar ADB root en el dispositivo ({device}): {e}")
        return False

def download_frida_server(version, architecture):
    """Descarga el archivo frida-server correspondiente a la versión y arquitectura."""
    base_url = f"https://github.com/frida/frida/releases/download/{version}/"
    filename = f"frida-server-{version}-android-{architecture}.xz"
    url = urljoin(base_url, filename)
    
    try:
        print(f"[+] Descargando frida-server desde: {url}")
        response = requests.get(url, stream=True)
        if response.status_code == 200:
            with open(filename, 'wb') as file:
                for chunk in response.iter_content(chunk_size=8192):
                    file.write(chunk)
            print(f"[+] Descarga completada: {filename}")
            return filename
        else:
            print(f"[-] No se pudo descargar frida-server. Código de estado: {response.status_code}")
            return None
    except Exception as e:
        print(f"[-] Error al descargar frida-server: {e}")
        return None

def decompress_xz(file_path):
    """Descomprime un archivo .xz y devuelve el nombre del archivo descomprimido."""
    try:
        output_file = file_path.replace('.xz', '')
        with lzma.open(file_path, 'rb') as f_in, open(output_file, 'wb') as f_out:
            f_out.write(f_in.read())
        print(f"[+] Archivo descomprimido: {output_file}")
        return output_file
    except Exception as e:
        print(f"[-] Error al descomprimir el archivo: {e}")
        return None

def push_frida_server(device, local_path, remote_path):
    """Sube el archivo frida-server al dispositivo."""
    try:
        print(f"[+] Subiendo frida-server al dispositivo ({device})...")
        subprocess.run(['adb', '-s', device, 'push', local_path, remote_path], check=True)
        print(f"[+] frida-server subido exitosamente a {remote_path}.")
        return True
    except Exception as e:
        print(f"[-] Error al subir frida-server al dispositivo ({device}): {e}")
        return False

def set_frida_permissions(device, remote_path):
    """Asigna permisos de ejecución al archivo frida-server en el dispositivo."""
    try:
        print(f"[+] Asignando permisos al archivo frida-server en el dispositivo ({device})...")
        subprocess.run(['adb', '-s', device, 'shell', 'chmod', '777', remote_path], check=True)
        print(f"[+] Permisos asignados correctamente a {remote_path}.")
        return True
    except Exception as e:
        print(f"[-] Error al asignar permisos al archivo frida-server en el dispositivo ({device}): {e}")
        return False

def start_frida_server(device, remote_path):
    """Inicia frida-server en segundo plano en el dispositivo."""
    try:
        print(f"[+] Iniciando frida-server en el dispositivo ({device})...")
        
        # Comando para iniciar frida-server con nohup y redirección de salidas
        command = f'nohup {remote_path} > /dev/null 2>&1 &'
        
        # Ejecutar el comando en el dispositivo
        subprocess.run(['adb', '-s', device, 'shell', command], check=True)
        print(f"[+] frida-server iniciado correctamente en segundo plano.")
        
        # Verificar si frida-server está ejecutándose
        result = subprocess.run(
            ['adb', '-s', device, 'shell', 'ps | grep frida-server'],
            stdout=subprocess.PIPE,
            text=True
        )
        if "frida-server" in result.stdout:
            print("[+] frida-server está ejecutándose correctamente.")
        else:
            print("[-] No se pudo verificar que frida-server esté ejecutándose.")
            return False
        
        return True
    except Exception as e:
        print(f"[-] Error al iniciar frida-server en el dispositivo ({device}): {e}")
        return False

def main():
    print("[*] Iniciando validación del entorno...")
    
    # Paso 1: Verificar ADB
    if not check_adb_installed():
        print("[-] La validación no puede continuar sin ADB.")
        return
    
    # Paso 2: Listar dispositivos conectados
    devices = list_connected_devices()
    if not devices:
        print("[-] La validación no puede continuar sin dispositivos conectados.")
        return
    
    # Paso 3: Obtener la arquitectura de cada dispositivo
    for device in devices:
        architecture = get_device_architecture(device)
        if not architecture:
            continue
        
        # Paso 4: Verificar si ADB ya está ejecutándose como root
        if not is_adb_running_as_root(device):
            # Intentar habilitar ADB root si no está en modo root
            if not enable_adb_root(device):
                continue
        
        # Paso 5: Descargar la versión correcta de frida-server
        frida_version = "16.7.11"  # Versión de Frida instalada
        compressed_file = download_frida_server(frida_version, architecture)
        if not compressed_file:
            continue
        
        # Paso 6: Descomprimir el archivo .xz
        decompressed_file = decompress_xz(compressed_file)
        if not decompressed_file:
            continue
        
        # Paso 7: Subir frida-server al dispositivo
        remote_frida_path = "/data/local/tmp/frida-server"
        if not push_frida_server(device, decompressed_file, remote_frida_path):
            continue
        
        # Paso 8: Asignar permisos al archivo frida-server
        if not set_frida_permissions(device, remote_frida_path):
            continue
        
        # Paso 9: Preguntar si se desea iniciar frida-server
        start_server = input("[?] ¿Deseas iniciar frida-server? (s/n): ").strip().lower()
        if start_server == 's':
            if not start_frida_server(device, remote_frida_path):
                print("[-] No se pudo iniciar frida-server.")
            else:
                print("[+] frida-server iniciado correctamente.")
        else:
            print("[+] Omitiendo inicio de frida-server.")

if __name__ == "__main__":
    main()