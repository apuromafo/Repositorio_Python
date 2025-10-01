#!/usr/bin/env python3
# coding: utf-8
"""
Herramienta de apoyo para instalar, validar y gestionar dispositivos con ADB Tools 
de forma multi-plataforma (Windows/Linux/WSL/macOS), manteniendo el enfoque en el VENV.
"""
__description__ = 'Instalador, Validador y Gestor de Dispositivos ADB multi-plataforma'
__author__ = 'Apuromafo'
__version__ = '3.8.0' # Versión actualizada con gestión de dispositivos ADB
__date__ = '2025-09-30'

import os
import requests
import zipfile
import sys
import platform
import subprocess
import shutil
import json
import time 
from datetime import datetime
from pathlib import Path

# Bloque condicional para importar módulos específicos de Windows
winreg = None
if platform.system() == "Windows":
    try:
        import winreg
    except ImportError:
        pass

# --- CONSTANTES ---
ADB_BASE_URL = "https://dl.google.com/android/repository/"
ADB_URL_WINDOWS = ADB_BASE_URL + "platform-tools-latest-windows.zip"
ADB_URL_LINUX = ADB_BASE_URL + "platform-tools-latest-linux.zip"
ADB_URL_MACOS = ADB_BASE_URL + "platform-tools-latest-darwin.zip"
ADB_DIR_NAME = "platform-tools"
LOG_FILE_NAME = "adb_validator.log"

# ==============================================================================
# --- CLASE DE CONFIGURACIÓN Y ESTADO (v3.6.0) ---
# ==============================================================================

class AdbConfig:
    """Clase para gestionar el estado y la configuración de la aplicación."""
    
    def __init__(self):
        # Rutas y configuración interna
        self._CONFIG_FILE = Path(r"config/config_adb.json")
        self.DEFAULT_WINDOWS_PATH = Path(r"C:\Users\pente\Documents\Movil\herramientas\adb")
        
        # Atributos de estado
        self.os_type: str = self._get_os_type()
        self.adb_root_path: Path = self.DEFAULT_WINDOWS_PATH
        self.enable_logs: bool = False
        
        # Cargar configuración al inicio
        self._load()

    def _get_os_type(self) -> str:
        """Determina y retorna el tipo de sistema operativo (Windows, Linux, WSL, Darwin, Otro)."""
        current_os = platform.system()
        if current_os == "Linux" and "microsoft" in platform.release().lower():
            return "WSL"
        elif current_os == "Linux":
            return "Linux"
        elif current_os == "Windows":
            return "Windows"
        elif current_os == "Darwin":
            return "Darwin" # macOS
        else:
            return "Otro"

    def _load(self):
        """Carga la configuración o establece valores por defecto."""
        
        self._CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)

        config_data = {"adb_root_path": str(self.DEFAULT_WINDOWS_PATH), "enable_logs": False}
        
        if self._CONFIG_FILE.exists():
            try:
                with open(self._CONFIG_FILE, "r") as f:
                    loaded_config = json.load(f)
                    config_data.update(loaded_config)
            except Exception:
                log(f"Advertencia: Error al cargar {self._CONFIG_FILE}. Usando valores por defecto.")
                print(f"[-] Advertencia: Error al cargar {self._CONFIG_FILE}. Usando valores por defecto.")

        # Set attributes from loaded data
        try:
            self.adb_root_path = Path(config_data.get("adb_root_path", str(self.DEFAULT_WINDOWS_PATH)))
        except ValueError:
            self.adb_root_path = self.DEFAULT_WINDOWS_PATH
            
        self.enable_logs = config_data.get("enable_logs", False)
        
        # Override default path for UNIX-like systems if the path is still the Windows default
        if self.os_type in ["Linux", "WSL", "Darwin"] and self.adb_root_path == self.DEFAULT_WINDOWS_PATH:
            self.adb_root_path = Path.home() / "adb_tools"
            self.save() 
            
    def save(self) -> bool:
        """Guarda la configuración."""
        try:
            self._CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
            config_data = {
                "adb_root_path": str(self.adb_root_path),
                "enable_logs": self.enable_logs
            }
            with open(self._CONFIG_FILE, "w") as f:
                json.dump(config_data, f, indent=4)
            log("Configuración guardada.")
            return True
        except Exception as e:
            print(f"[-] Error al guardar la configuración: {e}")
            log(f"Error al guardar la configuración: {e}")
            return False

    def toggle_logging(self) -> str:
        """Alterna el estado de los logs (activado/desactivado)."""
        self.enable_logs = not self.enable_logs
        self.save()
        status = "ACTIVADOS" if self.enable_logs else "DESACTIVADOS"
        print(f"\n✅ Logging de eventos ha sido **{status}**.")
        log(f"Logging toggled to: {status}")
        return status
        
# Inicialización global de la configuración
CONFIG = AdbConfig()

# ==============================================================================
# --- FUNCIONES DE LOGGING Y UTILIDAD (GENERAL) ---
# ==============================================================================

def log(message: str, level: str = "INFO"):
    """Escribe un mensaje en el archivo de log si los logs están habilitados."""
    if CONFIG.enable_logs:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            log_path = Path(LOG_FILE_NAME)
            log_path.parent.mkdir(parents=True, exist_ok=True)

            with open(log_path, "a", encoding="utf-8") as f:
                f.write(f"[{timestamp}] [{level}] {message}\n")
        except Exception as e:
            print(f"[-] Error al escribir log: {e}")

def is_venv_active() -> bool:
    """Verifica si el script se está ejecutando dentro de un entorno virtual activo."""
    return (hasattr(sys, 'real_prefix') or 
            (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix))

def find_venv_root() -> Path | None:
    """Intenta localizar una carpeta VENV estándar (venv o .venv) en el directorio actual."""
    current_dir = Path.cwd()
    possible_venv_paths = [current_dir / 'venv', current_dir / '.venv']
    
    for path in possible_venv_paths:
        if CONFIG.os_type == "Windows" and (path / 'Scripts').is_dir():
            log(f"VENV encontrado en: {path}")
            return path
        elif CONFIG.os_type in ["Linux", "WSL", "Darwin"] and (path / 'bin').is_dir():
            log(f"VENV encontrado en: {path}")
            return path
            
    return None

def get_venv_paths(venv_root_override: Path | None = None) -> tuple[Path, Path]:
    """Calcula las rutas relevantes para la instalación de ADB en VENV."""
    venv_root = venv_root_override if venv_root_override else Path(sys.prefix)
    
    if CONFIG.os_type == "Windows":
        binary_dir = venv_root / "Scripts"
    elif CONFIG.os_type in ["Linux", "WSL", "Darwin"]:
        binary_dir = venv_root / "bin"
    else:
        binary_dir = venv_root / ADB_DIR_NAME
        
    return venv_root, binary_dir

def print_venv_activation_guide():
    """Imprime los comandos de activación del VENV."""
    print("\n--- GUÍA DE ACTIVACIÓN DEL VENV ---")
    print("Asegúrate de ejecutar el comando desde el directorio padre del VENV:")
    print("  - **Windows:** `.venv\\Scripts\\activate` (PowerShell/CMD)")
    print("  - **Linux/WSL/macOS:** `source venv/bin/activate` (Bash/Zsh)")
    print("-----------------------------------")

def get_adb_download_url(os_type: str) -> str:
    """Retorna la URL de descarga más apropiada para el SO."""
    if os_type == "Darwin":
        return ADB_URL_MACOS
    if os_type in ["Linux", "WSL"]:
        return ADB_URL_LINUX
    return ADB_URL_WINDOWS

def extract_zip(zip_path: Path, target_dir: Path) -> bool:
    """Extrae el contenido de un zip a un directorio, manejando errores."""
    try:
        with zipfile.ZipFile(str(zip_path), 'r') as zip_ref:
            zip_ref.extractall(str(target_dir)) 
        log(f"Descompresión exitosa en: {target_dir}")
        return True
    except Exception as e:
        print(f"❌ Error al extraer ZIP: {e}")
        log(f"Error al extraer ADB ZIP: {e}", "ERROR")
        return False

def download_adb_tools(url: str, target_dir: Path) -> Path | None:
    """Descarga el ZIP de ADB Tools."""
    print(f"[*] Descargando ADB Tools desde {url}...")
    zip_filename = target_dir / "platform-tools-latest.zip"
    target_dir.mkdir(parents=True, exist_ok=True)
    log(f"Iniciando descarga a: {zip_filename}")

    try:
        response = requests.get(url, stream=True, timeout=15)
        response.raise_for_status() 

        with open(zip_filename, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        
        print(f"🎉 Descarga completada. Archivo guardado en: {zip_filename}")
        log("Descarga completada.")
        return zip_filename
    except requests.exceptions.Timeout:
        print("❌ Error de descarga: La conexión expiró.")
        log("Error de descarga: Timeout.", "ERROR")
        return None
    except requests.exceptions.ConnectionError:
        print("❌ Error de descarga: Problema de conexión (DNS/Ruta/SSL).")
        log("Error de descarga: ConnectionError.", "ERROR")
        return None
    except requests.exceptions.RequestException as e:
        print(f"❌ Error de descarga: No se pudo acceder a la URL o la conexión falló. {e}")
        log(f"Error de descarga ADB: {e}", "ERROR")
        return None
    except IOError as e:
        print(f"❌ Error de E/S al guardar el archivo: {e}")
        log(f"Error de E/S al guardar ZIP: {e}", "ERROR")
        return None

# ==============================================================================
# --- FUNCIONES DE ADB (COMANDO, VALIDACIÓN E INSTALACIÓN) ---
# ==============================================================================

def run_adb_command(command: str, error_msg="Error al ejecutar comando ADB") -> tuple[str, str, int]:
    """
    Ejecuta un comando del sistema y devuelve (stdout, stderr, returncode).
    Utilizado por todas las funciones de gestión de dispositivos.
    """
    try:
        log(f"Ejecutando comando ADB: {command}")
        # Usamos shell=True por la naturaleza de ADB en PATH
        process = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            encoding='utf-8',
            check=False 
        )
        if process.returncode != 0 and process.stderr.strip():
            # Solo loggear ERROR si hay un returncode distinto de 0 Y hay algo en stderr
            log(f"{error_msg}. Comando: '{command}'. STDERR: {process.stderr.strip()}", "ERROR")
        
        return process.stdout.strip(), process.stderr.strip(), process.returncode
    except FileNotFoundError:
        log(f"ERROR: Comando ADB no encontrado: '{command.split()[0]}'", "CRITICAL")
        # No imprimir el error aquí, ya que se maneja en check_adb_connectivity si es necesario
        return "", f"Comando no encontrado: {command.split()[0]}", 127
    except Exception as e:
        log(f"Excepción al ejecutar comando ADB: {e}", "CRITICAL")
        return "", str(e), 1


def validate_adb(adb_command: str) -> bool:
    """
    Verifica si el comando 'adb' responde correctamente, usando el comando/ruta provisto.
    Retorna True si la validación es exitosa.
    """
    
    print(f"\n🔬 Verificando instalación de ADB con comando: '{adb_command}'...")
    log(f"Iniciando validación con comando: {adb_command}")
    
    # Uso la nueva función run_adb_command
    stdout, stderr, returncode = run_adb_command(f"{adb_command} version", "Error al ejecutar adb version")
    
    is_venv = "bin" in adb_command or "Scripts" in adb_command # Asume que si tiene bin o Scripts es VENV
    
    if returncode == 0 and "Android Debug Bridge" in stdout:
        print("✅ ¡ADB fue encontrado y responde correctamente!")
        print(f"  Entorno: {'VENV activo' if is_venv_active() else 'PATH del Sistema/Ruta específica'}")
        print("------------------------------")
        print(stdout.strip())
        print("------------------------------")
        log("Validación ADB exitosa.")
        return True
    else:
        print(f"❌ El comando '{adb_command}' NO se encontró o no responde.")
        if is_venv and not is_venv_active():
            print("\n🚨 **ADVERTENCIA:** ADB se instaló, pero la validación falló.")
            print("    **RAZÓN:** El VENV no está activo. ¡Actívalo para usar ADB!")
            print_venv_activation_guide()
        else:
            print(f"  Detalles del Error:\n{stderr.strip()}")
            log(f"Fallo de validación ADB: {stderr.strip()}", "ERROR")
        return False

# --- FLUJOS DE INSTALACIÓN ESPECÍFICOS (manteniendo la lógica del usuario) ---

def _copy_adb_binaries(source_dir: Path, target_dir: Path, os_type: str) -> bool:
    """Función auxiliar para copiar binarios y aplicar permisos UNIX si es necesario."""
    try:
        target_dir.mkdir(parents=True, exist_ok=True)
        print(f"[*] Moviendo binarios de ADB a {target_dir}...")
        
        for f in os.listdir(str(source_dir)):
            s = source_dir / f
            d = target_dir / f
            
            if s.is_dir():
                shutil.copytree(str(s), str(d), dirs_exist_ok=True)
            else:
                shutil.copy2(str(s), str(d))
                # Dar permisos de ejecución en sistemas UNIX
                if os_type in ["Linux", "Darwin"] and s.name in ("adb", "fastboot"):
                     d.chmod(0o755)
                     
        return True
    except Exception as e:
        print(f"❌ Error copiando archivos a {target_dir}: {e}")
        log(f"Error copiando binarios ADB: {e}", "ERROR")
        return False

def install_in_venv_windows(venv_root_path: Path) -> bool:
    """Instala ADB Tools en el VENV en Windows. Copia a 'Scripts'."""
    scripts_dir = venv_root_path / "Scripts"
    temp_dir = venv_root_path / "adb_temp_extract"
    adb_exec = scripts_dir / "adb.exe"

    if temp_dir.exists(): shutil.rmtree(str(temp_dir))
    temp_dir.mkdir()
    
    download_url = get_adb_download_url(CONFIG.os_type)
    zip_path = download_adb_tools(download_url, temp_dir)
    
    if not zip_path or not extract_zip(zip_path, temp_dir):
        shutil.rmtree(str(temp_dir), ignore_errors=True)
        return False
        
    source_dir = temp_dir / ADB_DIR_NAME
    
    try:
        if not _copy_adb_binaries(source_dir, scripts_dir, CONFIG.os_type):
             return False
        
        print(f"🎉 Archivos de ADB copiados con éxito en la carpeta 'Scripts' del VENV.")
        
        print("\n*** VALIDANDO DESPUÉS DE LA INSTALACIÓN AUTOMÁTICA ***")
        return validate_adb(str(adb_exec))
        
    finally:
        if temp_dir.exists():
            shutil.rmtree(str(temp_dir), ignore_errors=True)
            print(f"[*] Directorio temporal limpiado.")

def install_in_venv_linux_or_wsl(venv_root_path: Path) -> bool:
    """Instala ADB Tools en el VENV en Linux/WSL. Copia a 'bin' y da permisos."""
    _, bin_dir = get_venv_paths(venv_root_path)
    temp_dir = venv_root_path / "adb_temp_extract"
    adb_exec = bin_dir / "adb"

    if temp_dir.exists(): shutil.rmtree(str(temp_dir))
    temp_dir.mkdir()
    
    download_url = get_adb_download_url(CONFIG.os_type)
    zip_path = download_adb_tools(download_url, temp_dir)
    
    if not zip_path or not extract_zip(zip_path, temp_dir):
        shutil.rmtree(str(temp_dir), ignore_errors=True)
        return False
        
    source_dir = temp_dir / ADB_DIR_NAME

    try:
        if not _copy_adb_binaries(source_dir, bin_dir, CONFIG.os_type):
             return False
        
        print(f"🎉 Archivos de ADB copiados con éxito en la carpeta 'bin' del VENV.")
        
        print("\n*** VALIDANDO DESPUÉS DE LA INSTALACIÓN AUTOMÁTICA ***")
        return validate_adb(str(adb_exec))
        
    finally:
        if temp_dir.exists():
            shutil.rmtree(str(temp_dir), ignore_errors=True)
            print(f"[*] Directorio temporal limpiado.")

def install_in_venv_macos(venv_root_path: Path) -> bool:
    """Instala ADB Tools en el VENV en macOS. Copia a 'bin' y da permisos."""
    return install_in_venv_linux_or_wsl(venv_root_path)


def install_in_host():
    """Instala ADB Tools en el sistema HOST (Global)."""
    
    install_root_path = CONFIG.adb_root_path
    final_target_dir = CONFIG.adb_root_path / ADB_DIR_NAME
    
    print(f"[*] **MODO HOST DETECTADO ({CONFIG.os_type}):** ADB se instalará en: {final_target_dir}")
    log(f"Instalación HOST a {final_target_dir}")
    
    temp_download_dir = install_root_path / "adb_temp_download"
    if temp_download_dir.exists(): shutil.rmtree(str(temp_download_dir))
    temp_download_dir.mkdir(parents=True, exist_ok=True)
    
    download_url = get_adb_download_url(CONFIG.os_type)
    zip_path = download_adb_tools(download_url, temp_download_dir)
    
    if not zip_path:
        shutil.rmtree(str(temp_download_dir), ignore_errors=True)
        print("❌ Instalación abortada debido a error de descarga.")
        return

    print("[*] Descomprimiendo y moviendo archivos...")
    final_install_path = None
    extracted_dir = None
    
    try:
        if not extract_zip(zip_path, temp_download_dir):
            return 
        
        extracted_dir = temp_download_dir / ADB_DIR_NAME
        
        if final_target_dir.exists():
            shutil.rmtree(str(final_target_dir))
        
        # Mover la carpeta extraída (platform-tools) al install_root_path
        shutil.move(str(extracted_dir), str(install_root_path)) 
        final_install_path = install_root_path / ADB_DIR_NAME
        print(f"🎉 Descarga y descompresión completada en: {final_install_path}")
        
        # Dar permisos de ejecución en UNIX/macOS (si no se dieron antes)
        if CONFIG.os_type in ("Linux", "WSL", "Darwin"):
            adb_exec = final_install_path / "adb"
            if adb_exec.exists():
                adb_exec.chmod(0o755)
        
        show_host_manual_install(final_install_path) 
        
        print("\n*** VALIDANDO DESPUÉS DE LA INSTALACIÓN AUTOMÁTICA ***")
        validate_adb("adb") # Valida el comando global

    except Exception as e:
        print(f"❌ Error durante la extracción o movimiento de archivos: {e}")
        log(f"Error en install_in_host: {e}", "ERROR")
    finally:
        if temp_download_dir.exists():
            shutil.rmtree(str(temp_download_dir), ignore_errors=True)
            
    if not final_install_path:
        print("❌ Instalación abortada.")


# ==============================================================================
# --- GESTIÓN Y DETECCIÓN DE DISPOSITIVOS ADB ---
# ==============================================================================

def check_adb_connectivity() -> bool:
    """Verifica si el comando 'adb' responde correctamente (conectividad básica)."""
    # Intentamos la conectividad básica.
    print("⏳ Verificando accesibilidad de ADB...")
    stdout, _, returncode = run_adb_command("adb version", "Error al verificar la versión de ADB")

    if returncode == 0 and "Android Debug Bridge" in stdout:
        log(f"ADB Verificado: {stdout.splitlines()[0]}")
        return True
    
    # Si falla, notificamos
    print("\n========================================================")
    print("❌ ADB NO DETECTADO o no está accesible desde el PATH/VENV.")
    print("========================================================")
    print("Antes de gestionar dispositivos, valida o instala ADB (Opciones 1 o 2).")
    log("Fallo la verificación de conectividad de ADB.", "WARNING")
    return False

def get_connected_devices():
    """
    Obtiene una lista de tuplas (device_id, status) de los dispositivos conectados.
    """
    stdout, _, returncode = run_adb_command("adb devices", "Fallo al listar dispositivos")
    
    devices = []
    if returncode != 0:
        return devices

    lines = stdout.splitlines()
    for line in lines[1:]:
        parts = line.split()
        if len(parts) == 2:
            device_id, status = parts
            if status != 'offline': 
                 devices.append((device_id, status))
            
    log(f"Dispositivos detectados: {[d[0] for d in devices]}")
    return devices

def get_root_status(device_id):
    """
    Verifica si el dispositivo tiene acceso root.
    """
    print(f"   🔎 Verificando estado de root en el dispositivo {device_id}...")
    
    # 1. Intentar el comando 'su -c id'
    stdout, _, _ = run_adb_command(f"adb -s {device_id} shell su -c id", "Error en el comando root check")
    
    if "uid=0(root)" in stdout:
        log(f"Dispositivo {device_id} ES ROOT (su -c id exitoso).")
        print("   Status: ✅ ROOT detectado (Acceso 'su').")
        return True
    
    # 2. Intentar 'id' normal (para ver si es shell o system)
    stdout, _, _ = run_adb_command(f"adb -s {device_id} shell id", "Error en el comando id check")
    # El usuario normal es 'shell' (uid=2000) o 'system' (uid=1000)
    if "uid=2000(shell)" in stdout or "uid=1000(system)" in stdout:
        log(f"Dispositivo {device_id} NO ES ROOT (uid={stdout.split('(')[0].split('=')[1]}).")
        print("   Status: ❌ No Root (Usuario 'shell' o 'system').")
        return False
        
    log(f"El estado de root para {device_id} es indeterminado, asumiendo No Root.")
    print("   Status: ❓ Root Indeterminado (Asumiendo No Root).")
    return False

def restart_adb_server():
    """Detiene y reinicia el demonio del servidor ADB."""
    print("\n🛠️ Reiniciando servidor ADB...")
    # Detener
    stdout, stderr, returncode = run_adb_command("adb kill-server", "Error al detener el servidor ADB")
    if returncode != 0 and stderr:
        print(f"❌ Error al intentar detener el servidor ADB. Detalle: {stderr}")

    # Iniciar
    stdout, stderr, returncode = run_adb_command("adb start-server", "Error al iniciar el servidor ADB")
    if returncode == 0:
        print("✅ Servidor ADB reiniciado con éxito.")
        log("Servidor ADB reiniciado con éxito.")
        return True
    else:
        print(f"❌ Fallo al iniciar el servidor ADB. Por favor, revisa manualmente. Error: {stderr}")
        log("Fallo al iniciar el servidor ADB.", "CRITICAL")
        return False

def select_device(devices):
    """Permite al usuario seleccionar un dispositivo de una lista."""
    print("\n--- SELECCIÓN DE DISPOSITIVO ---")
    
    # 1. Mostrar dispositivos y su estado root
    device_details = []
    for i, (device_id, status) in enumerate(devices):
        is_rooted = get_root_status(device_id) 
        root_label = "✅ ROOT" if is_rooted else "❌ No Root"
        device_details.append((device_id, status, is_rooted))
        print(f"[{i+1}] ID: {device_id} | Estado: {status.upper()} | Tipo: {root_label}")

    while True:
        choice = input("👉 Elige el número del dispositivo a usar (o 'R' para Reiniciar ADB, 'C' para Cancelar): ").strip()
        
        if choice.upper() == 'R':
            if restart_adb_server():
                print("\n🔄 Volviendo a la detección de dispositivos...")
                return None, None 
            else:
                continue 
        elif choice.upper() == 'C':
            return False, False # Señal de cancelación

        try:
            index = int(choice) - 1
            if 0 <= index < len(device_details):
                device_id, status, is_rooted = device_details[index]
                if status.upper() != 'DEVICE':
                    print(f"⚠️ Dispositivo {device_id} está en estado '{status.upper()}'. Debe estar en estado 'device' para continuar.")
                    continue

                print(f"\n✅ Dispositivo seleccionado: {device_id} (Root: {'Sí' if is_rooted else 'No'})")
                return device_id, is_rooted
            else:
                print("❌ Selección fuera de rango. Intenta de nuevo.")
        except ValueError:
            print("❌ Entrada no válida. Ingresa el número del dispositivo, 'R' o 'C'.")
            
    return None, None # Fallback

def adb_device_main():
    """
    Función principal para gestionar la conexión ADB y la selección de dispositivos.
    Devuelve (device_id, is_rooted) si tiene éxito, o (None, None) si falla/se cancela.
    """
    if not check_adb_connectivity():
        return None, None 

    while True:
        devices = get_connected_devices()
        
        if not devices:
            print("\n⚠️ No se detectaron dispositivos conectados, o están en estado 'offline'.")
            choice = input("¿Deseas reiniciar el servidor ADB (R) o volver al menú (C)? ").strip().upper()
            if choice == 'R':
                if not restart_adb_server():
                    print("No se pudo reiniciar el servidor. Volviendo al menú.")
                    return None, None
                continue 
            elif choice == 'C':
                print("👋 Cancelado por el usuario.")
                return None, None
            else:
                print("Opción no válida. Volviendo a comprobar.")
                time.sleep(1)
                continue

        elif len(devices) == 1:
            device_id, status = devices[0]
            
            print("\n--- DISPOSITIVO ÚNICO DETECTADO ---")
            
            if status.upper() == 'UNAUTHORIZED':
                print(f"ID: {device_id} | Estado: ⚠️ UNAUTHORIZED")
                print("\n⚠️ Estado: **UNAUTHORIZED**. Por favor, acepta la ventana emergente de Debugging USB en el dispositivo.")
                input("Presiona ENTER después de aceptar la autorización en el dispositivo...")
                time.sleep(2) 
                continue 
            
            if status.upper() == 'DEVICE':
                is_rooted = get_root_status(device_id)
                root_label = "✅ ROOT" if is_rooted else "❌ No Root"
                print(f"ID: {device_id} | Estado: {status.upper()} | Tipo: {root_label}")
                
                choice = input("\nUsar este dispositivo (S) o volver al menú de gestión (R para reiniciar/C para cancelar)? ").strip().upper()
                if choice == 'S':
                    log(f"Selección automática del único dispositivo: {device_id}, Root: {is_rooted}")
                    return device_id, is_rooted
                elif choice == 'R':
                    if not restart_adb_server():
                        print("No se pudo reiniciar el servidor. Saliendo.")
                        return None, None
                    continue
                else:
                    print("👋 Cancelado por el usuario.")
                    return None, None
            else:
                print(f"\n⚠️ El dispositivo está en estado '{status.upper()}'. No apto para Frida.")
                return None, None

        else: # Más de un dispositivo
            result = select_device(devices)
            if result is None: # Reinicio de ADB, continuar el bucle
                 continue
            elif result is False: # Cancelación
                 return None, None
            
            device_id, is_rooted = result
            if device_id:
                return device_id, is_rooted
            else:
                # Si select_device retorna (None, None) después de la gestión, salimos
                return None, None
        
        break 

    return None, None

def menu_adb_device_management():
    """Menú para gestionar la conexión y el estado de los dispositivos ADB."""
    print("\n" + "#"*50)
    print("### GESTIÓN DE DISPOSITIVOS ANDROID (ADB) ###")
    print("#"*50)
    print("Este módulo comprueba el estado de la conexión, detecta dispositivos")
    print("y verifica si tienen acceso ROOT (necesario para la instalación de Frida-Server).")
    
    device_id, is_rooted = adb_device_main()
    
    if device_id:
        print("\n========================================================")
        print("✅ Dispositivo listo para el siguiente paso (Instalación de Frida-Server).")
        print(f"   ID: {device_id}")
        print(f"   ROOT: {'SÍ' if is_rooted else 'NO'}")
        print("========================================================")
    else:
        print("\n========================================================")
        print("❌ No se seleccionó o detectó un dispositivo funcional.")
        print("========================================================")
    
    input("\nPresiona ENTER para volver al Menú Principal...")


# ==============================================================================
# --- GUÍAS MANUALES ---
# ==============================================================================

def show_venv_manual_install(venv_path: Path, os_name: str):
    """Muestra la guía de instalación manual para VENV."""
    ruta_binarios_adb = get_venv_paths(venv_path)[1]
    
    print("\n--------------------------------------------------")
    print(f"--- GUÍA MANUAL DE INSTALACIÓN ADB EN VENV ({os_name}) ---")
    print("1. Descarga el paquete 'platform-tools' de Google específico para tu SO.")
    print("2. Descomprime el archivo ZIP.")
    print(f"3. Copia **el contenido** de la carpeta 'platform-tools' (adb, fastboot, etc.)")
    print(f"  directamente a la carpeta de binarios de tu VENV:")
    print(f"  -> `{ruta_binarios_adb}`") 
    if os_name == "Windows":
        print("4. Asegúrate de que tu VENV esté activo (`.\\Scripts\\activate`).")
    else:
        print("4. Asegúrate de que tu VENV esté activo (`source bin/activate`).")
        print("5. **macOS/Linux:** Otorga permisos de ejecución a los binarios (`chmod +x adb fastboot`).")
    print("6. En una terminal con el VENV activo, ejecuta 'adb version' para verificar.")
    print("--------------------------------------------------")
    
def show_host_manual_install(ruta_adb_final: Path | None = None):
    """Muestra la guía de instalación manual para HOST."""
    os_type = CONFIG.os_type
    ruta_adb_sugerida = ruta_adb_final if ruta_adb_final else CONFIG.adb_root_path / ADB_DIR_NAME 
    
    print("\n--------------------------------------------------")
    print(f"--- GUÍA MANUAL DE INSTALACIÓN ADB EN HOST ({os_type}) ---\n-")
    print("1. Descarga el paquete 'platform-tools' de Google específico para tu SO.")
    print(f"2. Descomprime el archivo ZIP en una ubicación permanente, como: **{ruta_adb_sugerida}**")
    print("3. **Añade la ruta completa** de la carpeta que contiene ADB (ej: platform-tools) a tu variable de entorno **PATH**.")
    
    if os_type == "Windows":
        print("    (Usa 'Editar las variables de entorno del sistema' y añade la ruta anterior.)")
    else:
        print(f"    (Edita ~/.bashrc o ~/.zshrc y añade: `export PATH=\"$PATH:{ruta_adb_sugerida}\"`")
        print("4. **macOS/Linux:** Otorga permisos de ejecución a los binarios (`chmod +x adb fastboot`).")
        
    print("5. **IMPORTANTE:** Cierra y vuelve a abrir tu terminal (o recarga el perfil) para que los cambios surtan efecto.")
    print("--------------------------------------------------\n-")


# ==============================================================================
# --- MENÚS MODULARES ---
# ==============================================================================

def configurar_ruta_host():
    """Permite al usuario cambiar la ruta de instalación por defecto del HOST."""
    
    print("\n--- CONFIGURACIÓN DE RUTA DE INSTALACIÓN (HOST) ---")
    print(f"La ruta actual de instalación para HOST es: **{CONFIG.adb_root_path}**")
    
    new_path_str = input(f"[?] Introduce la nueva ruta absoluta o presiona Enter para mantener la actual: ").strip()
    
    if new_path_str:
        try:
            expanded_path = Path(os.path.expanduser(new_path_str))
            
            if not expanded_path.is_absolute():
                print("❌ La ruta debe ser absoluta. Cancelando el cambio.")
                return

            if CONFIG.os_type in ["Linux", "WSL", "Darwin"] and not expanded_path.exists():
                print("⚠️ Creando directorios: Asegúrate de que la ruta sea correcta.")
                expanded_path.mkdir(parents=True, exist_ok=True)

            CONFIG.adb_root_path = expanded_path
            if CONFIG.save():
                print(f"🎉 Configuración guardada. Nueva ruta de instalación: {CONFIG.adb_root_path}")
                log(f"Ruta de HOST cambiada a: {CONFIG.adb_root_path}")
            else:
                print("❌ No se pudo guardar la nueva ruta. Manteniendo la anterior.")
        except Exception as e:
            print(f"❌ Error al procesar la ruta: {e}")
    else:
        print("Mantenida la ruta de instalación actual.")

def menu_venv():
    """Menú de gestión para el Entorno Virtual."""
    os_name = CONFIG.os_type
    venv_path = None
    venv_status = "NO ENCONTRADO"
    
    if is_venv_active():
        venv_path = Path(sys.prefix)
        venv_status = "ACTIVO"
    else:
        found = find_venv_root()
        if found:
            venv_path = found
            venv_status = "DETECTADO (Inactivo)"
    
    while True:
        print("\n" + "~"*40)
        print(f"--- Menú VENV ({os_name}) ---")
        print(f"  Estado VENV: {venv_status}")
        print("~"*40)
        print("1) Instalar ADB automáticamente")
        print("2) Mostrar guía de instalación manual")
        print("3) Validar instalación de ADB")
        print("4) Volver al Menú Principal")
        print("5) Salir del script")
        choice = input("Elija opción: ").strip()

        if choice == "1":
            if venv_path is None:
                print("❌ Debe activar o crear un entorno virtual válido primero.")
                print_venv_activation_guide()
                continue
            
            success = False
            if os_name == "Windows":
                success = install_in_venv_windows(venv_path)
            elif os_name in ("Linux", "WSL"):
                success = install_in_venv_linux_or_wsl(venv_path)
            elif os_name == "Darwin":
                success = install_in_venv_macos(venv_path)
            else:
                print(f"❌ Instalación venv no soportada en {os_name}.")

            if not success:
                 print("⚠️ La instalación falló o la validación inicial no fue exitosa.")

        elif choice == "2":
            if venv_path:
                show_venv_manual_install(venv_path, os_name)
            else:
                print("❌ No se pudo determinar carpeta venv para la guía.")
            
        elif choice == "3":
            if venv_path:
                _, bin_dir = get_venv_paths(venv_path)
                exec_name = "adb.exe" if os_name == "Windows" else "adb"
                adb_exec = bin_dir / exec_name
                
                if adb_exec.exists():
                    validate_adb(str(adb_exec))
                else:
                    print(f"❌ adb no encontrado en {bin_dir}. Intente instalar primero.")
            else:
                print("❌ No se pudo localizar venv para validar.")
            
        elif choice == "4":
            break
        elif choice == "5":
            print("\n👋 Saliendo del script. ¡Hasta la próxima!")
            sys.exit(0)
        else:
            print("❌ Opción inválida.")

def menu_host():
    """Menú de gestión para el Sistema Global (Host)."""
    os_name = CONFIG.os_type
    while True:
        print("\n" + "~"*40)
        print(f"--- Menú HOST ({os_name}) ---")
        print("~"*40)
        print("1) Instalar/Actualizar ADB automáticamente")
        print("2) Mostrar guía de instalación manual")
        print("3) Validar instalación de ADB (Global PATH)")
        print("4) Volver al Menú Principal")
        choice = input("Elija opción: ").strip()
        
        if choice == "1":
            install_in_host()
        elif choice == "2":
            show_host_manual_install()
        elif choice == "3":
            validate_adb("adb")
        elif choice == "4":
            break
        else:
            print("❌ Opción inválida.")

def mostrar_menu_configuracion_y_avanzado():
    """Muestra el menú anidado para la configuración y opciones avanzadas."""
    
    while True:
        logging_status = "ON" if CONFIG.enable_logs else "OFF"
        print("\n--- MENÚ DE OPCIONES AVANZADAS ---")
        print(f"1. Toggle Logging (Actual: {logging_status})")
        print("2. Configurar Ruta de Instalación HOST")
        print("3. Retornar al Menú Principal")

        config_choice = input("[?] Selecciona una opción (1/2/3): ").strip()
        if config_choice == '1':
            CONFIG.toggle_logging()
        elif config_choice == '2':
            configurar_ruta_host()
        elif config_choice == '3':
            break
        else:
            print("❌ Opción no válida.")


def mostrar_menu_principal_v2():
    """Muestra el menú principal solicitado por el usuario y maneja la navegación."""

    os_type = CONFIG.os_type
    is_active = is_venv_active()
    
    # Determinar el estado para mostrar en el menú
    venv_root_status = "Inactivo"
    if is_active:
        venv_root_status = "ACTIVO"
    elif find_venv_root():
        venv_root_status = "Detectado"

    while True:
        log("Mostrando menú principal v2.")
        print("\n" + "-"*60)
        print(f" Adb Environment Setup Tool - versión {__version__}")
        print("-"*60)
        print(f"  Sistema: ({os_type}, VENV: {venv_root_status})")
        #TODO print("  Meta VENV: El script se ejecuta en un venv activo para el siguiente paso.")
        print("\n Opciones:")
        print("1. Instalar/Actualizar en un Entorno Virtual (Experimental)  ")
        print("2. Instalar/Actualizar en un Entorno HOST (Sistema Global)")
        print("3. **Gestionar Dispositivos ADB y Estado Root**")
        print("4. Opciones Avanzadas (Configuración de Rutas, Logging)")
        print("5. Salir del script")
        print("-"*60)

        choice = input("[?] Selecciona una opción (1-5): ").strip()

        if choice == '1':
            menu_venv()
        elif choice == '2':
            menu_host()
        elif choice == '3':
            menu_adb_device_management()
        elif choice == '4':
            mostrar_menu_configuracion_y_avanzado()
        elif choice == '5':
            print("\n👋 Saliendo del script. ¡Hasta la próxima!")
            log("Usuario salió del script.")
            break
        else:
            print("❌ Opción no válida. Por favor, elige una opción del 1 al 5.")

def principal():
    """Función principal para inicializar y comenzar el menú."""
    
    if CONFIG.os_type == "Windows":
        # Intenta configurar la codificación de salida para evitar problemas con emojis
        os.system('chcp 65001 >nul') 
    
    try:
        # Siempre muestra el menú principal al inicio
        mostrar_menu_principal_v2()
            
    except KeyboardInterrupt:
        print("\n\n👋 Proceso cancelado por el usuario (Ctrl+C). Saliendo del script.")
        log("Proceso cancelado por el usuario (Ctrl+C).")
        sys.exit(0)

if __name__ == "__main__":
    principal()
