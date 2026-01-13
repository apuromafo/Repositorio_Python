# 03_download_scanner.py
# Versión: 1.0.7 (Corrección: Uso de rutas absolutas y manejo de UnicodeDecodeError en setx)
# Gestiona la descarga, descompresión y localización del ejecutable de SonarScanner.

import os
import platform
import configparser
import requests
import re
import zipfile
import shutil
import subprocess
from requests.exceptions import RequestException
from pathlib import Path
from typing import Optional
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from urllib.parse import urlparse

# --- Configuración ---
VERSION_URL = "https://raw.githubusercontent.com/SonarSource/sonarqube-scan-action/master/sonar-scanner-version"
CONFIG_FILE = "config.ini"
DEFAULT_SONAR_URL = "http://localhost:9000"
DEFAULT_SONAR_TOKEN = "squ_DEMO_TOKEN"
DESTINATION_FOLDER = "sonarscan"
WINDOWS_EXECUTABLE = "sonar-scanner.bat"
UNIX_EXECUTABLE = "sonar-scanner"

# --- Funciones de Utilidad ---

def _get_config_value(section, key, default):
    """Lee la configuración desde config.ini o usa el valor por defecto."""
    try:
        config = configparser.ConfigParser()
        config.read(CONFIG_FILE)
        # Buscar la clave de forma insensible a mayúsculas
        if section in config and key.lower() in [k.lower() for k in config.options(section)]:
            actual_key = next(k for k in config.options(section) if k.lower() == key.lower())
            return config.get(section, actual_key).strip()
        return default
    except Exception:
        return default

def _get_system_info():
    """Retorna el sistema operativo y la arquitectura en un formato compatible con SonarSource."""
    sistema = platform.system().lower()
    maquina = platform.machine().lower()

    if 'amd64' in maquina or 'x86_64' in maquina:
        arch = 'x64'
    elif 'arm64' in maquina or 'aarch64' in maquina:
        arch = 'arm64'
    else:
        arch = maquina

    if sistema == 'windows':
        return 'windows', arch
    elif sistema == 'linux':
        return 'linux', arch
    elif sistema == 'darwin': 
        return 'macosx', arch
    
    return sistema, arch

def obtener_version_sonarqube(url, token):
    """Obtiene la versión de SonarQube desde la API (Función informativa)."""
    headers = {'Authorization': f'Bearer {token}'}
    try:
        print("[+] Conectando a SonarQube...")
        # Aumentamos el timeout y añadimos 'verify=False' solo si usa HTTP o se ignora la verificación SSL (aunque no es recomendado en prod)
        response = requests.get(f'{url}/api/server/version', headers=headers, timeout=5, verify=True)
        response.raise_for_status()
        version = response.text.strip()
        print(f"[✓] Versión detectada: {version}")
        return version
    except requests.exceptions.RequestException as e:
        # e.__class__.__name__ muestra el tipo de error (ConnectionError, NameResolutionError, etc.)
        print(f"[✗] Error al conectar con SonarQube: {e.__class__.__name__}({urlparse(url).netloc}): {e}")
        return None

def obtener_datos_scanner_desde_version_file():
    """Descarga y parsea el archivo de configuración de versiones de GitHub."""
    try:
        print(f"[+] Leyendo archivo de configuración desde: {VERSION_URL}")
        response = requests.get(VERSION_URL, timeout=10)
        response.raise_for_status()
        print("[✓] Datos del scanner cargados correctamente.")
        return response.text
    except RequestException as e:
        print(f"[✗] Error al descargar la lista de versiones del scanner: {e}")
        return None

def seleccionar_url_descarga(scanner_data):
    """Selecciona la URL de descarga correcta según el sistema."""
    sistema_os, arch = _get_system_info()
    
    # Expresión regular robusta para capturar vX.Y.Z.B o solo X.Y.Z.B
    version_match = re.search(r'v?([\d\.]+)', scanner_data)
    
    if not version_match:
        print("[✗] No se pudo encontrar la versión estable en el archivo de configuración.")
        return None, None
        
    version = version_match.group(1).strip()
    print(f"[i] Versión estable detectada: {version}")

    base_url = "https://binaries.sonarsource.com/Distribution/sonar-scanner-cli"
    
    if sistema_os == 'windows':
        # Formato Windows: sonar-scanner-cli-X.Y.Z.B-windows-x64.zip
        url_descarga = f"{base_url}/sonar-scanner-cli-{version}-{sistema_os}-{arch}.zip"
    elif sistema_os in ['linux', 'macosx']:
        # Formato Unix: sonar-scanner-cli-X.Y.Z.B.zip (genérico)
        url_descarga = f"{base_url}/sonar-scanner-cli-{version}.zip" 
    else:
        print(f"[✗] Sistema operativo '{sistema_os}' no soportado directamente.")
        return None, None
        
    return url_descarga, version

def descargar_archivo(url, ruta_completa):
    """Descarga el archivo a la ruta especificada."""
    try:
        print(f"[+] Descargando desde: {url}")
        # Intentar la descarga con un límite de tiempo
        response = requests.get(url, stream=True, timeout=30)
        response.raise_for_status()
        
        # Escribir el archivo
        with open(ruta_completa, 'wb') as file:
            for chunk in response.iter_content(chunk_size=8192):
                file.write(chunk)
        
        print(f"[✓] Descarga exitosa: {ruta_completa.name}")
        return True
    except RequestException as e:
        print(f"[✗] Error durante la descarga: {e}")
        return False

def _extraer_zip(zip_path: Path, destination_dir: Path) -> Optional[Path]:
    """
    Descomprime un ZIP, identifica la carpeta raíz interna y retorna su ruta.
    
    Args:
        zip_path: Ruta al archivo ZIP.
        destination_dir: Carpeta donde se extrae el contenido (e.g., 'sonarscan').
        
    Returns:
        Path a la carpeta raíz extraída
        o None si falla.
    """
    try:
        print(f"[+] Descomprimiendo: {zip_path.name}...")
        
        # 1. Crear un directorio temporal para la extracción
        temp_extract_dir = destination_dir / "temp_extract_scanner"
        temp_extract_dir.mkdir(exist_ok=True)
        
        # 2. Descomprimir el contenido en el temporal
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(temp_extract_dir)

        # 3. Identificar el nombre de la carpeta raíz dentro del ZIP
        root_folders = [d for d in temp_extract_dir.iterdir() if d.is_dir()]

        if not root_folders:
            print("[✗] Error: No se encontró la carpeta raíz del scanner dentro del ZIP.")
            shutil.rmtree(temp_extract_dir, ignore_errors=True)
            return None

        # Asumimos que la primera y principal carpeta es la raíz del scanner
        extracted_root_path_in_temp = root_folders[0] 
        extracted_root_name = extracted_root_path_in_temp.name
        
        # 4. Mover la carpeta raíz al nivel superior (a 'sonarscan')
        final_root_path = destination_dir / extracted_root_name
        
        if final_root_path.exists():
            shutil.rmtree(final_root_path)

        # Movemos la carpeta principal del scanner
        shutil.move(extracted_root_path_in_temp, destination_dir) 
        
        # 5. Limpiar el directorio temporal
        shutil.rmtree(temp_extract_dir, ignore_errors=True)
        
        print(f"[✓] Descompresión exitosa en: {final_root_path}")
        return final_root_path
        
    except Exception as e:
        print(f"[✗] Error al descomprimir el archivo: {e}")
        return None

def _agregar_a_path_windows(bin_path_relative: Path):
    """Intenta agregar la ruta al PATH del usuario usando setx (solo Windows)."""
    # 1. Convertir a ruta absoluta y asegurar el formato de Windows
    # Usamos .resolve() para obtener la ruta absoluta real
    bin_path_absolute = bin_path_relative.resolve()
    new_path_entry = str(bin_path_absolute)
    
    print("\n[⚠️] Intentando modificar la variable PATH de USUARIO (setx)...")
    
    try:
        # El comando setx PATH "nueva_ruta;%PATH%" es la forma correcta de anexar la ruta del usuario.
        # Desactivamos la captura de salida para evitar el UnicodeDecodeError reportado.
        print(f"[>] Ejecutando: setx PATH \"{new_path_entry};%PATH%\"")
        
        subprocess.run(
            ['setx', 'PATH', f'{new_path_entry};%PATH%'], 
            check=True,
            capture_output=False, # Evita el UnicodeDecodeError al no leer stdout/stderr
            text=False, # No es necesario el modo texto si no se captura la salida
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        print("[✓] setx ejecutado exitosamente.")
        print("    -> **¡ATENCIÓN!** El cambio NO aplica a esta terminal de PowerShell.")
        print("    -> Abre una NUEVA terminal para que 'sonar-scanner' esté disponible globalmente.")
        
    except subprocess.CalledProcessError as e:
        print(f"[✗] setx falló (Error en el sistema).")
        print(f"[i] Por favor, agrega esta ruta *absoluta* manualmente a tu variable PATH de Usuario/Sistema:")
        print(f"    -> {new_path_entry}")
        # Opcional: imprimir el error si lo hubo, pero puede contener caracteres problemáticos.
        # print(f"Detalles del error (si aplica): {e.stderr.decode('utf-8', errors='ignore')}") 
    except Exception as e:
        print(f"[✗] Error inesperado al intentar usar setx: {e}")


def _sugerir_y_agregar_al_path(executable_path: Path):
    """Pregunta al usuario si desea añadir el directorio 'bin' del scanner al PATH."""
    sistema_os = platform.system().lower()
    bin_path = executable_path.parent
    
    # Obtener la ruta absoluta para la visualización y uso en setx
    bin_path_absolute = bin_path.resolve()
    
    print("\n---------------------------------------------------------------------------------")
    print(f"🎉 Éxito: El ejecutable se encuentra en: {executable_path}")
    print(f"🚀 Sugerencia: Para poder ejecutar 'sonar-scanner' desde cualquier lugar,")
    print(f"necesitas añadir la carpeta 'bin' al PATH del sistema/usuario.")
    print(f"Ruta *ABSOLUTA* a agregar: {bin_path_absolute}")
    
    try:
        respuesta = input("¿Deseas intentar añadir esta ruta al PATH AHORA? (s/N): ").lower()
    except EOFError:
        respuesta = 'n' # Manejo si la entrada es redireccionada

    if respuesta == 's' or respuesta == 'si':
        if sistema_os == 'windows':
            # Llamamos a la función de Windows con la ruta relativa para que ella la resuelva a absoluta
            _agregar_a_path_windows(bin_path) 
        else: # Linux/macOS
            print("\n[i] Para sistemas Unix (Linux/macOS), la modificación permanente es compleja y se recomienda manual.")
            print("Por favor, ejecuta el siguiente comando o añádelo a tu ~/.bashrc o ~/.zshrc:")
            # Se corrige el SyntaxWarning al no escapar el $
            print(f"\n   echo 'export PATH=\"{bin_path_absolute}:$PATH\"' >> ~/.bashrc (o el archivo de tu shell)")
            print("\nLuego, ejecuta 'source ~/.bashrc' o abre una nueva terminal.")
    else:
        print("[i] Entendido. Puedes agregar la ruta manualmente más tarde.")
    print("---------------------------------------------------------------------------------")


def download_sonar_scanner() -> Optional[Path]:
    """
    Función principal para descargar y configurar el scanner.
    Retorna la ruta completa al ejecutable de SonarScanner si es exitoso.
    """
    print(f"\n\n=== INFO: DESCARGA Y EXTRACCIÓN AUTOMÁTICA DE SONARSCANNER ===")
    
    # Configuración base
    sonar_url = _get_config_value('SonarQube', 'url', DEFAULT_SONAR_URL)
    sonar_token = _get_config_value('SonarQube', 'sonar.token', DEFAULT_SONAR_TOKEN)
    sistema_os = platform.system().lower()
    
    # 1. Conexión a SonarQube (Informativo, no bloqueante)
    obtener_version_sonarqube(sonar_url, sonar_token)

    # 2. Obtener datos de la versión del scanner
    scanner_data = obtener_datos_scanner_desde_version_file()
    if not scanner_data:
        return None

    # 3. Seleccionar URL de descarga
    url_descarga, version = seleccionar_url_descarga(scanner_data)
    if not url_descarga:
        print("[✗] No se encontró una URL de descarga compatible con tu sistema.")
        return None

    # 4. Preparar rutas de descarga y extracción
    carpeta_destino = Path(DESTINATION_FOLDER)
    carpeta_destino.mkdir(exist_ok=True)
    nombre_archivo_zip = Path(url_descarga).name
    ruta_completa_zip = carpeta_destino / nombre_archivo_zip

    # 5. Descargar el archivo si no existe
    if ruta_completa_zip.exists():
        print(f"[i] El archivo ZIP ya existe: {ruta_completa_zip}. Saltando la descarga.")
    else:
        if not descargar_archivo(url_descarga, ruta_completa_zip):
            return None

    # 6. Descomprimir y obtener la ruta raíz
    extracted_root_path = _extraer_zip(ruta_completa_zip, carpeta_destino)
    
    if not extracted_root_path:
        return None

    # 7. Construir la ruta final del ejecutable
    if sistema_os == 'windows':
        executable_path = extracted_root_path / "bin" / WINDOWS_EXECUTABLE
    else:
        executable_path = extracted_root_path / "bin" / UNIX_EXECUTABLE
        
    # 8. Validar y retornar la ruta
    if executable_path.is_file():
        # En sistemas UNIX (Linux/macOS), asegurar permisos de ejecución
        if sistema_os != 'windows':
            try:
                os.chmod(executable_path, 0o755)
            except Exception as e:
                print(f"[⚠️] Advertencia: No se pudieron establecer permisos de ejecución: {e}")
                
        # 9. Sugerir y/o intentar añadir al PATH
        _sugerir_y_agregar_al_path(executable_path)
        
        return executable_path
    else:
        print(f"[✗] ERROR: No se encontró el ejecutable esperado en: {executable_path}")
        return None
    
# --- Función de prueba si se ejecuta solo ---
if __name__ == "__main__":
    scanner_path = download_sonar_scanner()
    if scanner_path:
        print(f"\n[i] Ruta al scanner (para referencia): {scanner_path}")
    else:
        print(f"\n[✗] La descarga y configuración del scanner falló.")