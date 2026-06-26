# -*- coding: utf-8 -*-

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

# 03_download_scanner.py
# Versión: 2.0.2 (Corrección: Mostrar la versión a descargar en el prompt)
# Objetivo: Gestiona la descarga, descompresión y localización del ejecutable de SonarScanner
#           en el directorio base del proyecto (BASE_DIR).

import os
import platform
import requests
import re
import zipfile
import shutil
import subprocess
import sys
from requests.exceptions import RequestException
from pathlib import Path
from typing import Optional, Tuple
import urllib3
import json
import fnmatch

# Ignorar warnings de SSL no verificados (útil en entornos corporativos)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ===================================================
# 📌 CONSTANTES Y STRINGS CENTRALIZADOS (MODIFICADO)
# ===================================================

BASE_DIR: Optional[Path] = None
SCANNER_FOLDER_NAME: str = "" # Variable global para guardar el nombre de la carpeta detectada/descargada.

CONSTANTS = {
    "MAX_DIR_SEARCH": 4, 
    "SCANNER_PREFIX": 'sonar-scanner-', 
    "INSTALL_FOLDER": 'sonarscan', 
    "VERSION_URL": "https://raw.githubusercontent.com/SonarSource/sonarqube-scan-action/master/sonar-scanner-version",
    "WINDOWS_EXECUTABLE": "sonar-scanner.bat",
    "UNIX_EXECUTABLE": "sonar-scanner",
}

STRINGS = {
    # General messages
    "TITLE": "\n-----------------------------------------------------\n🚀 [Paso 3: Verificación y Descarga de SonarScanner]\n-----------------------------------------------------",
    "INFO_START": "--- INICIO DE 03_download_scanner.py ---",
    "SUCCESS_END": "\n[✓] 03_download_scanner.py finalizado con éxito.",
    "ERROR_END": "\n[❌] 03_download_scanner.py finalizado con errores funcionales (descarga fallida, etc.).",
    "INFO_OPERATION_CANCELED": "\n[👋] Proceso de descarga cancelado por el usuario (o por el sistema).",
    "ERROR_CRITICAL": "\n[❌] Error crítico en 03_download_scanner.py: {error}",
    
    # BASE_DIR and Scanner Check
    "INFO_SEARCHING_SCANNER": "[+] Buscando carpeta '{prefix}*' dentro de '{install_folder}' o en {max_levels} niveles superiores...", 
    "ERROR_SCANNER_NOT_FOUND_BASE": "[⚠️] No se encontró ninguna carpeta '{prefix}*' en la ruta o sus superiores.",
    "WARNING_MULTIPLE_VERSIONS": "[⚠️] Múltiples versiones detectadas. Se utiliza por defecto la primera: {version}",
    "INFO_BASE_DIR_FOUND": "    Ubicación del Proyecto (BASE_DIR): {base_dir}",
    "INFO_SCANNER_ALREADY_EXISTS": "\n[✓] El SonarScanner ya está instalado en: {base_dir}/{install_folder}/{scanner_folder_name}", 
    
    # [CORRECCIÓN CLAVE]: Se añade {latest_version} para informar en el prompt.
    "PROMPT_RE_DOWNLOAD": "[?] ¿Desea descargar e instalar la versión {latest_version} (y reemplazar la actual)? (s/N): ", 
    "INFO_PROCEEDING_DOWNLOAD_NEW": "\n[i] Procediendo con la descarga e instalación en: {base_dir}/{install_folder}", 
    
    # Version and Download
    "INFO_FETCHING_LATEST_VERSION": "[i] Consultando la última versión de SonarScanner CLI...",
    "SUCCESS_LATEST_VERSION": "[✓] Última versión requerida: {version} (URL: {url})",
    "ERROR_FETCH_VERSION": "[❌] Error al obtener la última versión desde GitHub: {error}",
    "INFO_DOWNLOADING": "[i] Descargando '{version_name}' a '{destination_path}'...",
    "ERROR_DOWNLOAD": "[❌] Error durante la descarga: {error}",
    "SUCCESS_DOWNLOAD": "[✓] Descarga completada. Archivo ZIP en: {path}",
    
    # Extraction and Cleanup
    "INFO_EXTRACTING": "[i] Extrayendo archivos en: {destination_path}",
    "SUCCESS_EXTRACTION": "[✓] Extracción y limpieza del ZIP completadas.",
    "ERROR_EXTRACTION": "[❌] Error al extraer el archivo ZIP o al limpiar: {error}",
    "INFO_CLEANING_OLD": "[i] Limpiando carpeta antigua: {old_path}",
    "WARNING_CLEANUP_FAILED": "[⚠️] Advertencia: Falló la limpieza de la carpeta antigua: {error}",
    "ERROR_ZIP_NOT_FOUND": "[❌] Error: Archivo ZIP no encontrado en {path} después de la descarga.",
    
    # Installation and Path
    "ERROR_EXECUTABLE_NOT_FOUND": "[❌] ERROR: No se encontró el ejecutable esperado en: {executable_path}",
    "INFO_SETTING_PERMISSIONS": "[i] Estableciendo permisos de ejecución (chmod 755) para {executable_path}",
    "WARNING_CHMOD_FAILED": "[⚠️] Advertencia: No se pudieron establecer permisos de ejecución: {error}",
    "INFO_SCANNER_INSTALLED": "\n[✓] SonarScanner CLI instalado correctamente en: {install_path}",
    
    # Path Suggestion
    "INFO_ADD_TO_PATH": "\n[i] Para usar 'sonar-scanner' desde cualquier ubicación, añada el siguiente directorio al PATH del sistema:",
    "PATH_BIN_FOLDER": "    -> {bin_path}",
    "WARNING_SETX_FAILED": "[⚠️] Advertencia: Falló el intento automático de añadir al PATH de Windows (setx): {error}",
}

# ===================================================
# --- Lógica de Detección de BASE_DIR (sin cambios) ---
# ===================================================

def seleccionar_version_scanner(initial_dir: Path) -> bool:
    """
    Busca una carpeta de SonarScanner existente para determinar el BASE_DIR del proyecto.
    (La implementación completa está arriba en la conversación).
    """
    global BASE_DIR, SCANNER_FOLDER_NAME
    scanner_prefix = CONSTANTS["SCANNER_PREFIX"]
    install_folder = CONSTANTS["INSTALL_FOLDER"]
    current_dir = initial_dir
    scanners_encontrados = {} 
    
    print(STRINGS["INFO_SEARCHING_SCANNER"].format(
        prefix=scanner_prefix, 
        install_folder=install_folder,
        max_levels=CONSTANTS['MAX_DIR_SEARCH']
    ))

    # Búsqueda en niveles superiores...
    for i in range(CONSTANTS["MAX_DIR_SEARCH"] + 1):
        sonarscan_dir = current_dir / install_folder
        
        if sonarscan_dir.is_dir():
            encontrados_en_nivel = [
                d.name for d in sonarscan_dir.iterdir()
                if d.is_dir() and d.name.startswith(scanner_prefix)
            ]
            
            if encontrados_en_nivel:
                scanners_encontrados[current_dir] = encontrados_en_nivel
        
        if current_dir == current_dir.parent:
            break
        current_dir = current_dir.parent

    opciones_validas = []
    for ruta_padre, nombres in scanners_encontrados.items():
        for nombre in nombres:
            opciones_validas.append((ruta_padre, nombre))

    if not opciones_validas:
        return False

    ruta_padre_final, SCANNER_FOLDER_NAME = opciones_validas[0]
    BASE_DIR = ruta_padre_final
    version = SCANNER_FOLDER_NAME.replace(scanner_prefix, '')
    
    if len(opciones_validas) > 1:
        print(STRINGS["WARNING_MULTIPLE_VERSIONS"].format(version=version))
    
    print(STRINGS["INFO_BASE_DIR_FOUND"].format(base_dir=BASE_DIR))
    return True

# ===================================================
# --- Funciones de Descarga y Utilidad (Versión Completa) ---
# ===================================================

def _get_latest_version_url() -> Optional[Tuple[str, str, str]]:
    """Consulta GitHub y extrae la versión limpia usando Regex."""
    print(STRINGS["INFO_FETCHING_LATEST_VERSION"])
    version_url = CONSTANTS["VERSION_URL"]
    
    try:
        response = requests.get(version_url, verify=False, timeout=10)
        response.raise_for_status()
        content = response.text

        # 🔍 EXTRACCIÓN CON REGEX: Buscamos el valor tras 'sonar-scanner-version='
        match = re.search(r'sonar-scanner-version=(.*)', content)
        if not match:
            # Si el archivo volviera al formato antiguo de solo texto, usamos el contenido base
            version_number = content.strip().split('\n')[0]
        else:
            version_number = match.group(1).strip()
        
        # Determinar sufijo según OS
        os_name = platform.system().lower()
        if os_name == 'windows':
            zip_suffix = "windows-x64" # Cambiado a x64 para coincidir con la nueva nomenclatura de Sonar
        elif os_name == 'darwin':
            zip_suffix = "macosx-x64"
        else:
            zip_suffix = "linux-x64"
            
        # Construir nombre del ZIP y URL
        # Nota: La estructura de carpetas de SonarSource usa sonar-scanner-cli-VERSION...
        zip_name = f"sonar-scanner-cli-{version_number}-{zip_suffix}.zip"
        download_url = f"https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/{zip_name}"

        print(STRINGS["SUCCESS_LATEST_VERSION"].format(version=version_number, url=download_url))
        return zip_name, download_url, version_number

    except Exception as e:
        print(STRINGS["ERROR_FETCH_VERSION"].format(error=e))
        return None

def _clean_old_scanner(old_path: Path) -> None:
    # ... (Lógica de shutil.rmtree para limpieza) ...
    if old_path.is_dir():
        print(STRINGS["INFO_CLEANING_OLD"].format(old_path=old_path))
        try:
            shutil.rmtree(old_path)
        except OSError as e:
            print(STRINGS["WARNING_CLEANUP_FAILED"].format(error=e))
            
def _download_and_extract(download_url: str, zip_name: str, install_base_dir: Path) -> Optional[str]:
    # ... (Lógica de requests.get para descargar y zipfile para extraer) ...
    zip_path = install_base_dir / zip_name
    install_base_dir.mkdir(parents=True, exist_ok=True)
    
    print(STRINGS["INFO_DOWNLOADING"].format(version_name=zip_name, destination_path=zip_path))
    try:
        response = requests.get(download_url, stream=True, verify=False, timeout=60)
        response.raise_for_status()
        with open(zip_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk: f.write(chunk)
        print(STRINGS["SUCCESS_DOWNLOAD"].format(path=zip_path))
    except RequestException as e:
        print(STRINGS["ERROR_DOWNLOAD"].format(error=e))
        return None
    except IOError as e:
        print(STRINGS["ERROR_DOWNLOAD"].format(error=f"Error de IO al guardar: {e}"))
        return None
        
    if not zip_path.is_file():
        print(STRINGS["ERROR_ZIP_NOT_FOUND"].format(path=zip_path))
        return None
        
    extracted_folder_name = ""
    print(STRINGS["INFO_EXTRACTING"].format(destination_path=install_base_dir))
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            if zip_ref.namelist():
                extracted_folder_name = zip_ref.namelist()[0].split(os.sep)[0]
            zip_ref.extractall(install_base_dir)
        
        zip_path.unlink()
        print(STRINGS["SUCCESS_EXTRACTION"])
        return extracted_folder_name
        
    except zipfile.BadZipFile:
        print(STRINGS["ERROR_EXTRACTION"].format(error="El archivo ZIP está dañado."))
        return None
    except Exception as e:
        print(STRINGS["ERROR_EXTRACTION"].format(error=e))
        return None
        
def _sugerir_y_agregar_al_path(bin_path: Path) -> None:
    sistema_os = platform.system().lower()
    if sistema_os == 'windows':
        try:
            command = ['setx', 'PATH', f'"%PATH%;{bin_path}"']
            # CAMBIO: Usamos 'errors="replace"' o detectamos el encoding local
            # También quitamos capture_output si no vamos a procesar el texto realmente
            result = subprocess.run(
                command, 
                check=False, 
                text=True, 
                encoding='cp850', # Encoding estándar de la consola CMD en español
                errors='replace',  # Si falla un carácter, lo reemplaza en lugar de lanzar excepción
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                timeout=5
            )
            
            if result.returncode == 0:
                print("[✓] Intento automático de añadir al PATH (setx) completado. Puede requerir una nueva terminal.")
                print(STRINGS["PATH_BIN_FOLDER"].format(bin_path=bin_path))
                return
            else:
                error_output = result.stderr.strip() or result.stdout.strip()
                print(STRINGS["WARNING_SETX_FAILED"].format(error=error_output))
        except Exception as e:
            print(STRINGS["WARNING_SETX_FAILED"].format(error=e))

    # Fallback si no es Windows o si setx falló
    print(STRINGS["INFO_ADD_TO_PATH"])
    print(STRINGS["PATH_BIN_FOLDER"].format(bin_path=bin_path))

def _finalize_installation(install_base_dir: Path, scanner_folder_name: str) -> bool:
    # ... (Lógica de permisos de ejecución y PATH) ...
    bin_path = install_base_dir / scanner_folder_name / 'bin' 
    sistema_os = platform.system().lower()
    executable_name = CONSTANTS["WINDOWS_EXECUTABLE"] if sistema_os == 'windows' else CONSTANTS["UNIX_EXECUTABLE"]
    executable_path = bin_path / executable_name
    
    if not executable_path.is_file():
        print(STRINGS["ERROR_EXECUTABLE_NOT_FOUND"].format(executable_path=executable_path))
        return False

    if sistema_os != 'windows':
        print(STRINGS["INFO_SETTING_PERMISSIONS"].format(executable_path=executable_path))
        try:
            os.chmod(executable_path, 0o755)
        except Exception as e:
            print(STRINGS["WARNING_CHMOD_FAILED"].format(error=e))
            
    _sugerir_y_agregar_al_path(bin_path)

    print(STRINGS["INFO_SCANNER_INSTALLED"].format(install_path=install_base_dir / scanner_folder_name))
    return True

# ===================================================
# --- Función Principal (CON EL CAMBIO CLAVE) ---
# ===================================================

def download_sonar_scanner() -> bool:
    """
    Función principal que gestiona la detección de BASE_DIR, la verificación
    y la descarga/actualización del SonarScanner.
    """
    global BASE_DIR, SCANNER_FOLDER_NAME
    print(STRINGS["TITLE"])
    
    initial_dir = Path(__file__).parent.resolve()
    scanner_found = seleccionar_version_scanner(initial_dir)
    install_folder = CONSTANTS["INSTALL_FOLDER"]
    
    old_scanner_folder = SCANNER_FOLDER_NAME 
    
    # 2. Obtener la URL de la última versión
    latest_version_info = _get_latest_version_url() 
    if latest_version_info is None:
        return False
        
    zip_name, download_url, version_number = latest_version_info # <--- Versión disponible
    
    # 1. Decidir la ruta de instalación
    if scanner_found:
        install_base_dir = BASE_DIR / install_folder 
        print(STRINGS["INFO_SCANNER_ALREADY_EXISTS"].format(
            base_dir=BASE_DIR, 
            install_folder=install_folder,
            scanner_folder_name=SCANNER_FOLDER_NAME
        ))
        
        # Preguntar si quiere actualizar, USANDO LA VARIABLE DE VERSIÓN
        try:
            # CORRECCIÓN: Formatear la pregunta con la versión encontrada
            prompt_formatted = STRINGS["PROMPT_RE_DOWNLOAD"].format(latest_version=version_number)
            respuesta = input(prompt_formatted).strip().lower()
        except EOFError:
            respuesta = 'n'
            
        if respuesta not in ("s", "si"):
            print(STRINGS["INFO_OPERATION_CANCELED"])
            return True 
            
    else:
        # Si no se encontró, se prepara la instalación
        BASE_DIR = initial_dir
        install_base_dir = BASE_DIR / install_folder 
        print(STRINGS["INFO_PROCEEDING_DOWNLOAD_NEW"].format(base_dir=BASE_DIR, install_folder=install_folder))

    # 3. Limpiar versiones antiguas (si el usuario eligió actualizar)
    if scanner_found and old_scanner_folder:
        _clean_old_scanner(install_base_dir / old_scanner_folder) 

    # 4. Descargar y extraer
    new_scanner_folder_name = _download_and_extract(download_url, zip_name, install_base_dir) 
    if new_scanner_folder_name is None:
        return False

    # 5. Finalizar la instalación (permisos y PATH)
    if not _finalize_installation(install_base_dir, new_scanner_folder_name):
        return False

    return True

# --- Bloque de ejecución principal para independencia ---


print("\n[!] AVISO LEGAL: Use solo con autorizacion. / LEGAL NOTICE: Authorized use only.\n")
if __name__ == "__main__":
    try:
        print(STRINGS["INFO_START"])
        
        test_passed = download_sonar_scanner()
        
        if test_passed:
            print(STRINGS["SUCCESS_END"])
            sys.exit(0)
        else:
            print(STRINGS["ERROR_END"])
            sys.exit(1)
            
    except KeyboardInterrupt:
        print(STRINGS["INFO_OPERATION_CANCELED"])
        sys.exit(0)
    except Exception as e:
        print(STRINGS["ERROR_CRITICAL"].format(error=e), file=sys.stderr)
        sys.exit(1)