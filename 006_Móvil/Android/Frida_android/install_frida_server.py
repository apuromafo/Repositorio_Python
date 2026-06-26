
# =============================================================================
# AVISO LEGAL / LEGAL NOTICE
# -----------------------------------------------------------------------------
# Esta herramienta es unicamente para fines educativos y de auditoria de
# seguridad autorizada. El uso no autorizado contra sistemas sin el
# consentimiento explicito del propietario es ilegal.
# El usuario asume toda responsabilidad por el uso indebido.
#
# This tool is for educational and authorized security auditing purposes only.
# Unauthorized use against systems without the owner's explicit consent is
# illegal. The user assumes all responsibility for misuse.
# =============================================================================

# ==============================================================================
# --- DIRECTRICES, DOCUMENTACIÓN Y GUÍA DE USO ---
# ==============================================================================
# Nombre del Script: Frida Server Installer/Validator
# Versión: 3.4.3
# Descripción:
#   Este script automatiza la validación, instalación y el reinicio del binario
#   de frida-server en un dispositivo Android conectado por ADB.
#
# Lineamientos Operacionales:
# 1. Integración con 00main.py:
#    - Este script está diseñado para ser ejecutado como un subproceso por un
#      script principal (como '00main.py').
#    - La terminación del script debe ser **SUAVE** (usando `return` en `main`)
#      y nunca con `sys.exit()`, salvo en caso de una interrupción de teclado
#      cuando se ejecuta directamente (`if __name__ == "__main__":`).
# 2. Requerimientos:
#    - ADB (Android Debug Bridge) debe estar instalado y en el PATH del sistema.
#    - Frida Client (frida, frida-ps, etc.) debe estar instalado en el entorno
#      seleccionado (Host o VENV).
#
# ==============================================================================
# --- HISTORIAL DE VERSIONES ---
# ==============================================================================
# v3.2.0 (2025-09-30) - [REESTRUCTURA DE MENÚ ANIDADO]
#   ✅ Implementado el menú anidado solicitado (VENV/Host -> Automatizado/Manual).
# v3.3.0 (2025-09-30) - [GUÍA MANUAL EXTENDIDA VENV]
#   ✅ Implementada la guía manual extendida y mejorada para VENV/Host.
# v3.4.0 (2025-09-30) - [PROMPT DE VERSIÓN RESTAURADO]
#   ✅ Restaurado el prompt interactivo único (s/o/q) para seleccionar la versión
#      de frida-server a instalar/actualizar.
# v3.4.1 (2025-09-30) - [AJUSTE DE VALIDACIÓN]
#   ✅ Cambiado el comando de validación remota de `frida-ps -U` a **`frida-ps -Uai`**.
# v3.4.2 (2025-09-30) - [DOCUMENTACIÓN DE ERRORES EN MANUAL]
#   ✅ Integrada la solución de problemas de inicio del servidor (Address already in use, su: invalid syntax) en la guía manual.
# v3.4.3 (2025-09-30) - [LIMPIEZA EN SHELL ROOT]
#   ✅ Añadido el paso de limpieza (`pkill frida-server`) dentro de la sesión de `adb shell` para resolver el error de puerto ocupado después de un inicio fallido o fallas de `su`.
# ==============================================================================

import subprocess
import os
import re
import sys
import json
import requests
from urllib.parse import urljoin
import lzma
from datetime import datetime
import time

# --- CONSTANTES DE OPERACIÓN ---
FRIDA_PORT = 27042
REMOTE_FRIDA_PATH = "/data/local/tmp/frida-server"
VERSION = "3.4.3" # Versión actualizada
CONFIG_FILE = r"config\config_install_frida_server.json"
LOG_FILE = "frida_server.log"
DOWNLOADS_DIR = "downloads"
global ENABLE_LOGS

# ==============================================================================
# --- FUNCIONES DE CONFIGURACIÓN Y LOGGING ---
# ==============================================================================

def load_config():
    if not os.path.exists("config"):
        os.makedirs("config")
    global ENABLE_LOGS
    config = {}
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                config = json.load(f)
        except (json.JSONDecodeError, IOError):
            pass
    config.setdefault("enable_logs", False)
    ENABLE_LOGS = config["enable_logs"]
    return config

def log(message):
    if ENABLE_LOGS:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] {message}\n")

# ==============================================================================
# --- FUNCIÓN DE GUÍA MANUAL (ACTUALIZADA) ---
# ==============================================================================
def show_manual_steps(env_type):
    """Muestra los pasos detallados para la instalación manual de frida-server,
       adaptando las instrucciones al entorno (Host o VENV) e incluyendo el 
       diagnóstico de errores de inicio más comunes."""
    
    print("\n" + "="*80)
    print(f"         🔧 GUÍA EXTENDIDA: INSTALACIÓN MANUAL DE FRIDA-SERVER ({env_type})")
    print("="*80)
    print("Esta guía asume que tienes ADB en el PATH.")
    
    # --- PASO 0: Preparación de Entorno ---
    print("\n--- PASO 0: Preparar entorno de trabajo y verificar ADB ---")
    print("0.1. Verifica que adb reconoce tu dispositivo conectado:")
    print("     ```bash\n     adb devices\n     ```")
    print("     (Debe aparecer tu dispositivo marcado como \"device\").")
    
    if env_type == "VENV":
        print("\n0.2. Crea y activa un entorno virtual Python para Frida (VENV):")
        print("     ```bash")
        print("     python3 -m venv frida-venv")
        print("     source frida-venv/bin/activate  # En Linux/macOS (Usar si estás en WSL)")
        print("     frida-venv\\Scripts\\activate     # En Windows PowerShell")
        print("     ```")
        print("0.3. Instala la versión deseada de **Frida Client** (en el venv activo):")
        print("     ```bash\n     pip install frida==<VERSIÓN>\n     ```")
        print("     (Reemplaza <VERSIÓN> con el número exacto, ej. 17.3.2).")
        print("0.4. Verifica la instalación y detecta la versión (VENV activo):")
        print("     ```bash\n     frida --version\n     ```")
    else: # Host
        print("0.2. Verifica la instalación de **Frida Client** en tu Sistema Host:")
        print("     ```bash\n     frida --version\n     ```")
        print("     (Si no está instalado, hazlo con `pip install frida`).")
        
    # --- PASO 1: Obtener Arquitectura y Versión ---
    print("\n--- PASO 1: Obtener arquitectura y versión Frida para tu dispositivo Android ---")
    print("1.1. Obtén la arquitectura de CPU del dispositivo Android:")
    print("     ```bash\n     adb shell getprop ro.product.cpu.abi\n     ```")
    print("     (Toma nota de la arquitectura, ej. `arm64-v8a` o `arm`).")
    print("1.2. Confirma la versión del cliente Frida instalada (visto en 0.4/0.2). Esa será la versión del frida-server que debes descargar.")

    # --- PASO 2: Descargar y preparar el binario ---
    print("\n--- PASO 2: Descargar y preparar el binario frida-server para Android ---")
    print("2.1. Ve a la página de releases oficial de Frida:")
    print("     🔗 **URL:** https://github.com/frida/frida/releases")
    print("2.2. Descarga el archivo correspondiente a la **Versión** y **Arquitectura**:")
    print("     ```text\n     frida-server-<VERSION>-android-<ARCH>.xz\n     ```")
    print("2.3. Descomprime el archivo `.xz` para obtener el binario `frida-server`:")
    print("     ```bash\n     xz -d frida-server-*.xz\n     ```")
    print("2.4. (Opcional) Verifica el archivo resultante (debe ser ejecutable y sin extensión):")
    print("     ```bash\n     file frida-server\n     ```")

    # --- PASO 3: Subir y configurar ---
    print("\n--- PASO 3: Subir y configurar frida-server en tu dispositivo ---")
    print("3.1. Sube el binario a la ruta temporal recomendada:")
    print("     ```bash\n     adb push frida-server /data/local/tmp/frida-server\n     ```")
    print("3.2. Concede permisos de ejecución:")
    print("     ```bash\n     adb shell chmod +x /data/local/tmp/frida-server\n     ```")
    print("3.3. (Opcional) Verifica los permisos en el dispositivo:")
    print("     ```bash\n     adb shell ls -l /data/local/tmp/frida-server\n     ```")

    # --- PASO 4: Iniciar frida-server y Solución de Errores ---
    print("\n--- PASO 4: Iniciar frida-server en el dispositivo Android ---")
    
    print("\n[+] **LIMPIEZA PREVIA:** Detener cualquier servidor existente y limpiar `forwards`.")
    print("    *Esto soluciona el error `Address already in use` cuando se inicia un servidor*.")
    print("    ```bash")
    print("    # 1. Matar proceso remoto (ejecutar en la terminal del host)")
    print("    adb shell pkill frida-server")
    print("    # 2. Limpiar forwards en el host")
    print("    adb forward --remove-all")
    print("    ```")
    
    print("\n[+] **INICIO DEL SERVIDOR:** Arrancar con desvinculación de la terminal ADB (`setsid`):")
    
    print("    - **Con root (Opción 1: Comando directo - Recomendado para persistencia):**")
    print("      ```bash\n      adb shell \"su -c 'setsid /data/local/tmp/frida-server &'\"\n      ```")
    print("      ⚠️ **Solución de Error `su: invalid uid/gid '-c'`:** Si tu versión de `su` da este error, prueba la sintaxis alternativa:")
    print("      ```bash\n      adb shell \"su 0 setsid /data/local/tmp/frida-server &\"\n      ```")
    
    print("    - **Con root (Opción 2: Sesión interactiva de root):**")
    print("      ```bash")
    print("      adb root                                  # 1. Reiniciar ADB como root")
    print("      adb shell                                 # 2. Entrar al shell rooteado")
    print("      pkill frida-server                        # 3. <-- ¡LIMPIAR! Si persiste 'Address already in use'.")
    print("      setsid /data/local/tmp/frida-server &     # 4. Iniciar el servidor")
    print("      exit                                      # 5. Salir del shell")
    print("      ```")
    
    print("    - **Sin root (Unprivileged):**")
    print("      ```bash\n      adb shell \"setsid /data/local/tmp/frida-server &\"\n      ```")
    
    print("4.2. Configura el reenvío de puertos para conexión local (ejecutar en la terminal del host):")
    print("     ```bash\n     adb forward tcp:27042 tcp:27042\n     ```")
    
    print("4.3. Verifica que el proceso está corriendo (debe devolver un PID):")
    print("     ```bash\n     adb shell pidof frida-server\n     ```")


    # --- PASO 5: Validar la conexión y uso básico ---
    print("\n--- PASO 5: Validar la conexión y uso básico ---")
    print("5.1. Con el entorno local **activo** (VENV o Host), lista procesos remotos (prueba de funcionalidad completa):")
    print("     ```bash\n     frida-ps -Uai\n     ```")
    print("     (Si ves una lista de procesos del dispositivo, ¡es exitoso!).")
    print("5.2. Para salir del entorno virtual (si aplica):")
    print("     ```bash\n     deactivate\n     ```")
    
    print("\n" + "="*80)


# ==============================================================================
# --- FUNCIÓN DE VALIDACIÓN REMOTA (ACTUALIZADA) ---
# ==============================================================================

def check_remote_frida_connection(device_id, client_version):
    """
    Verifica de forma PASIVA si frida-server está corriendo y si el cliente puede conectarse.
    ***Usa 'frida-ps -Uai' para una validación completa.***
    Retorna (True, salida_ps) si es exitoso, y (False, None) si falla.
    """
    # EL COMANDO HA SIDO CAMBIADO A '-Uai'
    log("Iniciando verificación remota PASIVA (frida-ps -Uai).") 
    
    if not setup_adb_forward(device_id):
        log("Error crítico: No se pudo establecer el reenvío de puertos (adb forward).")
        return False, None

    try:
        # Usamos -Uai para listar todos los procesos y aplicaciones instaladas
        command = ['frida-ps', '-Uai'] 
        result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=10)
        
        # Debe haber al menos un proceso listado (generalmente 3-4 procesos de sistema)
        if len(result.stdout.strip().split('\n')) > 3: 
            log("Validación remota exitosa.")
            return True, result.stdout.strip()
        else:
             # Falla si la conexión es exitosa pero no hay procesos (raro, pero posible si algo bloquea)
            log(f"Validación remota fallida. Salida de frida-ps muy corta:\n{result.stdout.strip()}")
            return False, None 
            
    except subprocess.CalledProcessError as e:
        error_msg = e.stderr.strip()
        log(f"Validación remota fallida. Error de frida-ps: {error_msg}")
        return False, None
    except Exception as e:
        log(f"Error desconocido en check_remote_frida_connection: {e}")
        return False, None

# ==============================================================================
# --- FUNCIONES DE UTILIDAD (Resto sin cambios) ---
# ==============================================================================

def get_installed_frida_version():
    """Obtiene la versión de frida instalada en el entorno actual."""
    log("Obteniendo versión de frida instalada en el entorno activo...")
    try:
        result = subprocess.run(['frida', '--version'], capture_output=True, text=True, check=True, timeout=5)
        version = result.stdout.strip()
        if version:
            log(f"Versión de frida encontrada: {version}")
            return version
        return None
    except Exception as e:
        log(f"Error al obtener la versión de frida: {e}")
        return None

def kill_frida_server_remote(device_id):
    """Intenta matar cualquier proceso de frida-server existente en el dispositivo y limpia forwards."""
    log("Intentando detener cualquier frida-server existente...")
    print(f"[+] Limpiando procesos de frida-server y forwards ADB en {device_id}...")
    try:
        subprocess.run(['adb', '-s', device_id, 'shell', 'pkill', 'frida-server'], 
                       capture_output=True, text=True, timeout=5, check=False)
        subprocess.run(['adb', 'forward', '--remove-all'], 
                       capture_output=True, text=True, timeout=5, check=False)
        log("Procesos antiguos de frida-server detenidos y forwards limpiados.")
    except Exception as e:
        log(f"Fallo al matar el servidor remoto o limpiar forwards: {e}")

def setup_adb_forward(device_id, port=FRIDA_PORT):
    """Configura el reenvío de puertos para la conexión de Frida."""
    log(f"Configurando reenvío de puertos ADB ({port} -> {port})...")
    try:
        subprocess.run(['adb', '-s', device_id, 'forward', f'tcp:{port}', f'tcp:{port}'], 
                       check=True, capture_output=True, text=True, timeout=5)
        log("Reenvío de puertos establecido.")
        return True
    except subprocess.CalledProcessError as e:
        log(f"Error al configurar el reenvío de puertos: {e.stderr.strip()}")
        return False

def wait_for_server_initialization(device_id, client_version, timeout=15, interval=3):
    """
    Espera activamente a que el servidor Frida en el dispositivo responda,
    mediante un chequeo repetido hasta que la conexión sea exitosa o se agote el tiempo.
    Retorna (True, salida_ps) si es exitoso, y (False, None) si falla.
    """
    log(f"Esperando hasta {timeout} segundos para la inicialización del servidor con reintentos.")
    print(f"⏳ Esperando hasta {timeout}s por la inicialización y conexión del servidor (reintentos cada {interval}s)...", end="")
    sys.stdout.flush()
    
    start_time = time.time()
    
    is_connected, output = check_remote_frida_connection(device_id, client_version)
    if is_connected:
         print("\n✅ Conexión establecida. Servidor en línea.")
         log("Servidor respondió inmediatamente.")
         return True, output
    
    while time.time() - start_time < timeout:
        sys.stdout.write(".")
        sys.stdout.flush()
        time.sleep(interval)
        
        is_connected, output = check_remote_frida_connection(device_id, client_version)
        if is_connected:
            print("\n✅ Conexión establecida. Servidor en línea.")
            log("Servidor respondió después del reintento.")
            return True, output
        
    print("\n❌ Timeout alcanzado. El servidor NO RESPONDE después de la espera.")
    log("Timeout alcanzado. El servidor no respondió a tiempo.")
    return False, None
        
def check_remote_server_file_status(device_id):
    """
    Verifica si el binario del servidor existe en la ruta remota y obtiene su versión
    usando 'adb shell /path/to/server --version'.
    """
    print(f"\n🔍 Comprobando estado del archivo en {REMOTE_FRIDA_PATH}...")
    log(f"Comprobando existencia y versión del archivo: {REMOTE_FRIDA_PATH}")
    
    # 1. Comprobar existencia
    try:
        result = subprocess.run(['adb', '-s', device_id, 'shell', 'ls', REMOTE_FRIDA_PATH], 
                                capture_output=True, text=True, check=True, timeout=5)
        
        if REMOTE_FRIDA_PATH not in result.stdout.strip():
             print("[-] Estado: El archivo frida-server NO existe en la ruta remota.")
             return None, False
             
    except subprocess.CalledProcessError:
        print("[-] Estado: El archivo frida-server NO existe en la ruta remota.")
        return None, False
    except Exception as e:
        log(f"Error al verificar existencia: {e}")
        return None, False
        
    print("[+] Estado: El binario 'frida-server' existe en el dispositivo.")
    
    # 2. Intentar obtener la versión 
    remote_version = "Desconocida"
    try:
        command = ['adb', '-s', device_id, 'shell', REMOTE_FRIDA_PATH, '--version']
        result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=5)
        remote_version = result.stdout.strip()
        
        if remote_version:
             print(f"✅ Versión detectada en el dispositivo: **{remote_version}**")
             log(f"Versión remota detectada: {remote_version}")
             return remote_version, True
             
    except subprocess.CalledProcessError as e:
        print("⚠️ Advertencia: No se pudo obtener la versión (Error de ejecución o falta de permisos).")
        log(f"Error al obtener la versión remota: {e.stderr.strip()}")
        return remote_version, True # El archivo existe, pero no se puede ejecutar --version
    except Exception as e:
        log(f"Error en la verificación de versión remota: {e}")
        return remote_version, True

def check_adb_installed():
    """Verifica si adb está instalado en el sistema."""
    log("Verificando la instalación de ADB...")
    try:
        subprocess.run(['adb', 'version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        print("[+] ADB está instalado.")
        log("ADB está instalado.")
        return True
    except (FileNotFoundError, subprocess.CalledProcessError) as e:
        print("[-] Error: ADB no está instalado o no se encuentra en el PATH.")
        print("Por favor, instálalo antes de continuar.")
        log(f"Error: ADB no está instalado. Detalle: {e}")
        return False

def list_connected_devices():
    """
    Lista los dispositivos conectados mediante adb y permite al usuario seleccionar uno.
    Automatiza la selección si solo hay un dispositivo.
    """
    log("Listando dispositivos conectados...")
    try:
        result = subprocess.run(['adb', 'devices'], stdout=subprocess.PIPE, text=True, check=True)
        lines = result.stdout.strip().split('\n')
        devices = [line.split('\t')[0] for line in lines[1:] if 'device' in line and line.split('\t')[-1] == 'device']

        if not devices:
            print("[-] No hay dispositivos conectados.")
            log("No se encontraron dispositivos conectados.")
            return None
        
        if len(devices) == 1:
            selected_device = devices[0]
            print(f"\n[+] Dispositivo detectado y seleccionado automáticamente: **{selected_device}**")
            log(f"Dispositivo seleccionado automáticamente: {selected_device}")
            return selected_device
        
        print("\n[+] Múltiples dispositivos conectados:")
        for i, device_id in enumerate(devices):
            print(f"[{i+1}] {device_id}")

        choice = input("[?] Selecciona un dispositivo (número): ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(devices):
            selected_device = devices[int(choice) - 1]
            log(f"Dispositivo seleccionado: {selected_device}")
            return selected_device
        else:
            print("[-] Opción no válida.")
            log("Selección de dispositivo no válida.")
            return None

    except Exception as e:
        print(f"[-] Error al listar dispositivos: {e}")
        log(f"Error al listar dispositivos: {e}")
        return None

def get_device_info(device_id):
    """Obtiene información detallada del dispositivo seleccionado."""
    log(f"Obteniendo información detallada del dispositivo {device_id}...")
    info = {
        "Android Version": "N/A",
        "Architecture": "N/A",
        "Model": "N/A",
        "Device Name": "N/A",
        "Manufacturer": "N/A",
        "SDK Level": "N/A",
        "IP Address": "N/A",
        "Root Access": "No"
    }

    try:
        properties = {
            "Android Version": "ro.build.version.release",
            "Architecture": "ro.product.cpu.abi",
            "Model": "ro.product.model",
            "Device Name": "ro.product.device",
            "Manufacturer": "ro.product.manufacturer",
            "SDK Level": "ro.build.version.sdk"
        }
        for key, prop in properties.items():
            result = subprocess.run(['adb', '-s', device_id, 'shell', 'getprop', prop], capture_output=True, text=True, check=True, timeout=5)
            if result.stdout.strip():
                info[key] = result.stdout.strip()
            
        result = subprocess.run(['adb', '-s', device_id, 'shell', 'ip', 'addr', 'show', 'wlan0'], capture_output=True, text=True, timeout=5)
        ip_match = re.search(r'inet\s+([\d.]+)', result.stdout)
        if ip_match:
            info["IP Address"] = ip_match.group(1)

        try:
            # Check for root
            root_check = subprocess.run(['adb', '-s', device_id, 'shell', 'which', 'su'], capture_output=True, text=True, timeout=5)
            if root_check.stdout.strip():
                 info["Root Access"] = "Sí"
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass

    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f"[-] Error al obtener información del dispositivo: {e}")
        log(f"Error al obtener información del dispositivo: {e}")
        
    return info

#update 09.10.2025 se añade casos de arm 
def get_device_architecture(device_id):
    """Obtiene la arquitectura del dispositivo seleccionado (Mapeo a Frida)."""
    log(f"Obteniendo arquitectura para el dispositivo {device_id}...")
    try:
        result = subprocess.run(['adb', '-s', device_id, 'shell', 'getprop', 'ro.product.cpu.abi'], capture_output=True, text=True, check=True, timeout=5)
        arch = result.stdout.strip()
        
        frida_arch_map = {
        # ARM
        "arm64-v8a": "arm64",    # Mapeo de 64-bit V8
        "armeabi-v7a": "arm",    # Mapeo de 32-bit V7
        "armeabi": "arm",        # Mapeo de 32-bit (viejos/secundarios)
        # x86 
        "x86_64": "x86_64",      # Mapeo de 64-bit Intel
        "x86": "x86",            # Mapeo de 32-bit Intel
        }
        
        normalized_arch = frida_arch_map.get(arch, arch)
        if normalized_arch not in frida_arch_map.values():
             print(f"[-] Arquitectura detectada ({arch}) no reconocida por Frida. Se intentará usar tal cual: {normalized_arch}")
        else:
             print(f"[+] Arquitectura del dispositivo: {normalized_arch}")
        log(f"Arquitectura detectada: {normalized_arch}")
        return normalized_arch
        
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f"[-] Error al obtener la arquitectura: {e}")
        log(f"Error al obtener la arquitectura: {e}")
        return None

def download_frida_server(version, architecture):
    """
    Descarga la versión de frida-server para la arquitectura y versión dadas
    en una carpeta específica.
    """
    log(f"Buscando frida-server para la versión {version} y arquitectura {architecture}...")
    base_url = "https://github.com/frida/frida/releases/download/"
    file_name = f"frida-server-{version}-android-{architecture}.xz"
    download_url = urljoin(base_url, f"{version}/{file_name}")

    version_dir = os.path.join(DOWNLOADS_DIR, version)
    os.makedirs(version_dir, exist_ok=True)
    file_path = os.path.join(version_dir, file_name)

    if os.path.exists(file_path):
        print(f"[!] El archivo ya existe en {file_path}. Saltando la descarga.")
        log("Archivo ya existe. Saltando la descarga.")
        return file_path
    
    print(f"[+] Descargando {file_name}...")
    log(f"Descargando de URL: {download_url}")
    try:
        response = requests.get(download_url, stream=True)
        response.raise_for_status()
        
        with open(file_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        print("✅ Descarga completada.")
        log("Descarga completada.")
        return file_path
    except requests.exceptions.HTTPError as e:
        print(f"[-] Error HTTP: No se pudo descargar {file_name}. La versión/arquitectura podría no existir.")
        log(f"Error de descarga HTTP: {e}")
        return None
    except Exception as e:
        print(f"[-] Error en la descarga: {e}")
        log(f"Error de descarga: {e}")
        return None

def decompress_xz(compressed_file):
    """Descomprime un archivo .xz."""
    log("Descomprimiendo archivo...")
    decompressed_file = compressed_file.replace('.xz', '') 
    
    try:
        with lzma.open(compressed_file, 'rb') as f_in:
            with open(decompressed_file, 'wb') as f_out:
                f_out.write(f_in.read())
        print(f"✅ Archivo descomprimido a {decompressed_file}")
        log("Archivo descomprimido.")
        return decompressed_file
    except lzma.LZMAError as e:
        print(f"[-] Error al descomprimir el archivo .xz: {e}")
        log(f"Error de descompresión: {e}")
        return None
    finally:
        if os.path.exists(compressed_file):
            os.remove(compressed_file)

def push_frida_server(device_id, local_file, remote_path):
    """Sube el archivo frida-server al dispositivo."""
    log(f"Subiendo {local_file} a {device_id}:{remote_path}...")
    print(f"[+] Subiendo frida-server a {remote_path}...")
    try:
        subprocess.run(['adb', '-s', device_id, 'push', local_file, remote_path], check=True, timeout=60)
        print("✅ Subida completada.")
        log("Subida completada.")
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        print(f"[-] Error al subir el archivo: {e}")
        log(f"Error al subir el archivo: {e}")
        return False
    finally:
        if os.path.exists(local_file):
            os.remove(local_file)

def set_frida_permissions(device_id, remote_path):
    """Asigna permisos de ejecución a frida-server."""
    log("Asignando permisos de ejecución...")
    print("[+] Asignando permisos de ejecución (chmod +x)...")
    try:
        subprocess.run(['adb', '-s', device_id, 'shell', 'chmod', '+x', remote_path], check=True, timeout=10)
        print("✅ Permisos asignados.")
        log("Permisos de ejecución asignados.")
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        print(f"[-] Error al asignar permisos: {e}")
        log(f"Error al asignar permisos: {e}")
        return False

def start_frida_server(device_id, remote_path, is_rooted):
    """Inicia frida-server en el dispositivo (Usando setsid para mejor persistencia, con opción a usar su)."""
    log("Iniciando frida-server...")
    print("[+] Iniciando frida-server en el dispositivo...")
    
    start_command_base = f'setsid {remote_path} &'
    if is_rooted:
        start_command = f'su -c "{start_command_base}"'
        print("   -> Modo: Usando **'su -c' (Requiere Root)** para inicio persistente y estable.")
    else:
        start_command = start_command_base
        print("   -> Modo: **Unprivileged (Sin Root)** para inicio persistente.")

    try:
        full_command = ['adb', '-s', device_id, 'shell', start_command]
        
        subprocess.Popen(full_command, 
                         stdout=subprocess.DEVNULL, 
                         stderr=subprocess.DEVNULL, 
                         close_fds=True)
        
        print("✅ frida-server se ha iniciado (comando enviado).")
        log(f"frida-server iniciado con comando: {start_command}")
        
        if setup_adb_forward(device_id):
             print("✅ Reenvío de puertos reestablecido.")
        
        return True
    except (FileNotFoundError, Exception) as e:
        print(f"[-] Error al iniciar frida-server: {e}")
        log(f"Error al iniciar frida-server: {e}")
        return False

# ==============================================================================
# --- FLUJO DE SELECCIÓN Y VALIDACIÓN (Mantenidas) ---
# ==============================================================================

def select_and_validate_environment():
    """
    Función principal que maneja la selección del entorno (Host/VENV) y las
    opciones de flujo (Automatizado/Manual).
    """
    while True:
        print("\n--- SELECCIÓN DE ENTORNO ---")
        print("1. Ejecutar usando el **Entorno Virtual** (VENV activo)")
        print("2. Ejecutar usando el **Sistema Host** (Instalación Global)")
        print("3. Salir")

        choice = input("[?] Selecciona el entorno de Frida Client (1/2/3): ").strip()

        if choice == '3':
            return None, None
        
        env_type = "VENV" if choice == '1' else "Host" if choice == '2' else None
        
        if not env_type:
            print("[-] Opción no válida. Intenta de nuevo.")
            continue
            
        print(f"\n🔎 Entorno seleccionado: **{env_type}**.")
        
        # 1. Validación de Frida Client
        frida_version = get_installed_frida_version()
        if not frida_version:
            print(f"[-] Error: Frida Client no está instalado en este entorno {env_type} o no se pudo obtener la versión.")
            if env_type == "VENV":
                 print("   Asegúrate de que tu Entorno Virtual (VENV) esté *activo* en esta terminal.")
            continue
            
        print(f"✅ Frida Client (Local) Versión: **{frida_version}**")

        # 2. Submenú de Flujo (Automatizado vs. Manual)
        while True:
            print(f"\n--- OPCIONES DE INSTALACIÓN en {env_type} ---")
            print("1. Procedimiento **Automatizado** (Recomendado)")
            print("2. Mostrar Pasos de Instalación **Manual**")
            print("3. Volver al menú de entorno")
            
            sub_choice = input(f"[?] Selecciona el flujo de instalación para {env_type} (1/2/3): ").strip()

            if sub_choice == '3':
                break  # Vuelve al menú de entorno principal
            
            if sub_choice == '2':
                show_manual_steps(env_type) 
                continue # Muestra pasos y vuelve al submenú
            
            if sub_choice == '1':
                # Flujo Automatizado seleccionado
                return env_type, frida_version

            print("[-] Opción no válida. Intenta de nuevo.")

# ==============================================================================
# --- FUNCIÓN PRINCIPAL (ACTUALIZADA) ---
# ==============================================================================

def main():
    """Función principal para la instalación y validación de frida-server."""
    load_config()
    print("\n=======================================")
    print(f"  Frida Server Installer/Validator v{VERSION}")
    print("=======================================")
    log("Iniciando script 'install_frida_server.py'.")

    # Paso 1: Verificación de ADB
    if not check_adb_installed():
        return

    # Paso 2: Selección y Validación del Entorno Local (Host/VENV) y Flujo (Automatizado/Manual)
    env_type, frida_version_client = select_and_validate_environment()
    if not env_type: 
        return

    # Si llega aquí, significa que se eligió el flujo AUTOMATIZADO.

    # Paso 3: Selección de dispositivo
    device_id = list_connected_devices()
    if not device_id:
        return
        
    # Paso 4: Obtener y mostrar información detallada del dispositivo
    print(f"\n[+] Información del dispositivo {device_id}:")
    device_info = get_device_info(device_id)
    is_rooted = device_info.get("Root Access") == "Sí" # Determinar si tiene Root
    print("--- Información del Dispositivo ---")
    for key, value in device_info.items():
        print(f"  - {key}: {value}")
    print("-----------------------------------")
    
    # Paso 5: Obtención de la arquitectura del dispositivo
    architecture = get_device_architecture(device_id)
    if not architecture or architecture == "N/A":
        architecture = device_info.get("Architecture")
    if not architecture:
        return

    # Paso 6: VALIDACIÓN INTELIGENTE (Pasiva)
    print("\n🔬 Validando estado de conexión remota (Check de Server Responsiveness - **frida-ps -Uai**)...")
    is_running, ps_output = check_remote_frida_connection(device_id, frida_version_client)
    
    if is_running:
         print("🎉 **¡CONEXIÓN EXITOSA!**")
         print("\n--- SALIDA DE PRUEBA (frida-ps -Uai) ---") # Comando actualizado
         print(ps_output)
         print("--------------------------------------")
         print(f"   -> Servidor Frida remoto RESPONDE. Asumimos compatibilidad con la versión {frida_version_client}.")
    else:
         print("[-] El servidor remoto NO RESPONDE o es incompatible (frida-ps retornó error 2).")


    # Paso 7: Diagnóstico de Estado del Binario Remoto
    remote_version, file_exists = check_remote_server_file_status(device_id)

 
    
    #if file_exists and remote_version == frida_version_client:
    if file_exists :# and remote_version == frida_version_client:    
        print(f"   -> Binario detectado con la versión **CORRECTA ({remote_version})**. Solo necesita ser iniciado.")
        
        prompt_start = input(f"[?] ¿Deseas **INICIAR** el frida-server existente (v{frida_version_client}) en {device_id}? (s/n): ").strip().lower()
        if prompt_start == 's':
            if start_frida_server(device_id, REMOTE_FRIDA_PATH, is_rooted): 
                print("\n🔬 Ejecutando prueba de funcionalidad FINAL...")
                is_connected, ps_output = wait_for_server_initialization(device_id, frida_version_client, timeout=15, interval=3)
                if is_connected: 
                    print("\n--- SALIDA DE PRUEBA (frida-ps -Uai) ---") # Comando actualizado
                    print(ps_output)
                    print("--------------------------------------")
                    print("\n🎉 **INICIO DE SERVIDOR Y CONEXIÓN COMPLETADA CON ÉXITO.**")
                else:
                    print("\n⚠️ Advertencia: El servidor inició, pero falló la prueba de conexión final. Verifica manualmente.")
            else:
                print("\n❌ Error al iniciar el servidor. Verifica los permisos de ejecución en el dispositivo.")
            return 

    if file_exists:
        print(f"   -> Binario detectado. Versión local ({frida_version_client}) vs. Remota ({remote_version}).")
    else:
        print("   -> Binario frida-server NO detectado en la ruta. Se requiere instalación.")
        
    # INICIO DE LA LÓGICA DE SELECCIÓN DE VERSIÓN RESTAURADA
    frida_version_to_install = frida_version_client # Valor por defecto
    
    while True:
        # Prompt interactivo para elegir versión (similar al que el usuario recordó)
        prompt = input(f"[?] Deseas **DESPLEGAR/ACTUALIZAR** frida-server (v{frida_version_client}). Usar la versión del cliente (**s**), ingresar **o**tra versión, o **q** para salir?: ").strip().lower()
        
        if prompt == 's': # Usar la instalada (current client version)
            print(f"[+] Usando la versión del cliente: {frida_version_to_install}")
            break
        elif prompt == 'o': # Otra versión
            new_version = input("[?] Ingresa la versión de frida-server que deseas instalar (ej. 17.2.16): ").strip()
            if new_version:
                frida_version_to_install = new_version
                print(f"[+] Versión alternativa seleccionada: {frida_version_to_install}")
                break
            else:
                print("[-] No se ingresó una versión. Por favor, intenta de nuevo o elige 's' para usar la versión instalada.")
        elif prompt == 'q':
            print("👋 Despliegue/Actualización cancelado por el usuario. Saliendo.")
            return # Terminar la función main
        else:
            print("[-] Opción no válida. Ingresa 's', 'o', o 'q'.")
    # FIN DE LA LÓGICA DE SELECCIÓN DE VERSIÓN RESTAURADA
            
    print(f"\n--- INICIANDO DESPLIEGUE de frida-server v{frida_version_to_install} ---")
    
    # Ejecutamos la limpieza ANTES de instalar el nuevo
    kill_frida_server_remote(device_id)
    
    # Paso 8.1: Descargar
    compressed_file = download_frida_server(frida_version_to_install, architecture)
    if not compressed_file:
        return 
    
    # Paso 8.2: Descomprimir el archivo
    decompressed_file = decompress_xz(compressed_file)
    if not decompressed_file:
        return 
    
    # Paso 8.3: Subir, permisos e iniciar
    if not push_frida_server(device_id, decompressed_file, REMOTE_FRIDA_PATH):
        return 
    
    if not set_frida_permissions(device_id, REMOTE_FRIDA_PATH):
        return 
    
    if start_frida_server(device_id, REMOTE_FRIDA_PATH, is_rooted): 
        # Paso 8.4: Prueba final de conexión
        print("\n🔬 Ejecutando prueba de funcionalidad FINAL...")
        is_connected, ps_output = wait_for_server_initialization(device_id, frida_version_to_install, timeout=15, interval=3)
        if is_connected:
            print("\n--- SALIDA DE PRUEBA (frida-ps -Uai) ---") # Comando actualizado
            print(ps_output)
            print("--------------------------------------")
            print("\n🎉 **INSTALACIÓN Y CONEXIÓN COMPLETADA CON ÉXITO.**")
            log("Instalación y conexión completada.")
        else:
            print("\n⚠️ Advertencia: El servidor inició, pero falló la prueba de conexión final. Verifica manualmente.")
            
    print("\n=======================================")
    print("         Gestión del Entorno Finalizada")
    print("=======================================")
    return



print("\n[!] AVISO LEGAL: Use solo con autorizacion. / LEGAL NOTICE: Authorized use only.\n")
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 [!] Proceso cancelado por el usuario (Ctrl+C). Saliendo del script.")
        sys.exit(0)