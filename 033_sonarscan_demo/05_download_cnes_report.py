
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

# 05_download_cnes_report.py
# Versión: 2.1.0 (Corrección para independencia y validación completa del JAR CNES)
# Objetivo: Validar la versión local del JAR de CNES, descargar/actualizar si es necesario y limpiar versiones antiguas.

import os
import re
import requests
import sys
import configparser
import shutil
from pathlib import Path
from typing import Optional, Tuple, List
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Configuración y Constantes ---
REPOSITORIO_URL = "https://api.github.com/repos/cnescatlab/sonar-cnes-report/releases/latest"
NOMBRE_JAR_LOCAL = "sonar-cnes-report-*.jar"
CONFIG_INI = "config.ini"
SONAR_SECTION = "SonarQube"
BASE_DIR = Path(os.getcwd())

# ----------------------------------------------------
# CORRECCIÓN CLAVE: Lógica para asegurar config.ini
# ----------------------------------------------------
def _ensure_config_ini_exists() -> bool:
    """
    Crea config.ini con valores por defecto si no existe. 
    Esto es crucial para la independencia del script al asegurar que 'ruta_jar' pueda leerse.
    """
    if not os.path.exists(CONFIG_INI):
        print(f"[i] Creando '{CONFIG_INI}' por defecto. Por favor, edítelo con valores reales si es necesario.")
        
        default_ini_content = f"""[{SONAR_SECTION}]
# Coloque el Token de SonarQube aquí
sonar.token = squ_XX
# Coloque la URL de su instancia de SonarQube
url = https://tu-sitio.sonarqube.cl
nombrereporte = Analisis de Codigo
# El nombre de archivo del JAR local (necesario para la validación inicial)
ruta_jar = sonar-cnes-report-5.0.2.jar
ruta_plantilla = plantillas\\code-analysis-template.docx
"""
        try:
            with open(CONFIG_INI, 'w', encoding='utf-8') as f:
                f.write(default_ini_content)
            return True
        except Exception as e:
            print(f"[❌] Error al crear config.ini: {e}", file=sys.stderr)
            return False
    return True

def _leer_config_ini() -> Optional[str]:
    """Lee y retorna la ruta_jar de config.ini, o None en caso de error/ausencia."""
    # NO es necesario verificar la existencia aquí si se llama a _ensure_config_ini_exists antes.
    try:
        config = configparser.ConfigParser()
        config.read(CONFIG_INI) 
        if SONAR_SECTION in config:
            return config.get(SONAR_SECTION, 'ruta_jar', fallback='').strip()
    except Exception as e:
        print(f"[⚠️] Advertencia: Error al leer 'ruta_jar' de config.ini: {e}", file=sys.stderr)
    return None


# ----------------------------------------------------
# Funciones de Utilidad para Versión y Descarga
# ----------------------------------------------------

def obtener_version_local(ruta_jar: Path) -> Optional[str]:
    """Obtiene la versión del archivo JAR local basándose en su nombre."""
    try:
        # Se verifica si el archivo existe antes de intentar obtener la versión
        if not ruta_jar.is_file():
            return None
        match = re.search(r"sonar-cnes-report-(\d+\.\d+\.\d+)\.jar", ruta_jar.name)
        return match.group(1) if match else None
    except Exception:
        return None

def obtener_version_remota() -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Obtiene la última versión disponible del JAR en GitHub.
    Retorna: (version_str_corta, version_str_completa, url_descarga)
    """
    try:
        response = requests.get(REPOSITORIO_URL, timeout=10)
        response.raise_for_status()
        data = response.json()
        
        tag_name = data.get('tag_name', '').lstrip('v') # Ej: '5.0.2'
        
        # Buscar el JAR en los assets
        jar_asset = next((asset for asset in data.get('assets', []) if asset['name'].endswith('.jar')), None)
        
        if jar_asset:
            # tag_name: '5.0.2', full_name: 'sonar-cnes-report-5.0.2.jar', url: '...'
            nombre_archivo_completo = jar_asset['name']
            url_descarga = jar_asset['browser_download_url']
            return tag_name, nombre_archivo_completo, url_descarga
        else:
            print("[❌] Error: No se encontró el archivo JAR en los assets de la última versión de GitHub.")
            return None, None, None
            
    except requests.RequestException as e:
        print(f"[❌] Error de conexión a GitHub: {e}", file=sys.stderr)
    except Exception as e:
        print(f"[❌] Error al procesar la respuesta de GitHub: {e}", file=sys.stderr)
    return None, None, None


def descargar_nueva_version(url_descarga: str, ruta_destino_completa: Path) -> bool:
    """Descarga el archivo desde la URL a la ruta de destino."""
    print(f"\n⬇️ Descargando JAR a: {ruta_destino_completa}")
    try:
        with requests.get(url_descarga, stream=True, timeout=300) as r:
            r.raise_for_status()
            with open(ruta_destino_completa, 'wb') as f:
                shutil.copyfileobj(r.raw, f)
        print("[✓] Descarga completada.")
        return True
    except requests.RequestException as e:
        print(f"[❌] Error al descargar el archivo: {e}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"[❌] Error al guardar el archivo: {e}", file=sys.stderr)
        return False

def eliminar_versiones_antiguas(directorio: str, version_a_conservar: str):
    """Elimina otros archivos JAR que no coincidan con la versión a conservar."""
    print(f"\n🧹 Buscando versiones antiguas en '{directorio}' para eliminar...")
    try:
        for item in Path(directorio).glob(NOMBRE_JAR_LOCAL):
            nombre_completo = item.name
            # Si el nombre completo no contiene la versión exacta, se considera antiguo
            if version_a_conservar not in nombre_completo:
                print(f"[i] Eliminando versión antigua: {nombre_completo}")
                os.remove(item)
        print("[✓] Limpieza de versiones antiguas completada.")
    except Exception as e:
        print(f"[❌] Error durante la limpieza de archivos: {e}", file=sys.stderr)


# ----------------------------------------------------
# Lógica Principal
# ----------------------------------------------------

def main_download_cnes_report() -> bool:
    """
    Función principal para validar y descargar el JAR de reporte CNES.
    """
    print("\n\n🔎 [Paso 5: Validación y Descarga del JAR CNES]")
    print("Verificando la disponibilidad y versión del generador de reportes...")

    # 1. Asegurar que config.ini existe
    if not _ensure_config_ini_exists():
        return False

    # 2. Leer la ruta del JAR desde config.ini
    jar_file_name = _leer_config_ini()
    if not jar_file_name:
        print(f"[❌] No se pudo obtener 'ruta_jar' de '{CONFIG_INI}'. El script no puede continuar.")
        return False

    ruta_local_completa = BASE_DIR / jar_file_name
    
    # Obtener la versión local (del archivo en disco, o None si no existe)
    version_local = obtener_version_local(ruta_local_completa)
    
    # 3. Obtener la versión remota
    print(f"[i] Consultando última versión en GitHub...")
    version_remota_corta, version_remota_completa, url_descarga = obtener_version_remota()

    if not version_remota_corta:
        print("[❌] No se pudo obtener la versión remota. El script no puede continuar.")
        return False

    # 4. Comparación y lógica de descarga
    
    # Caso 1: Archivo local no existe
    if version_local is None:
        print(f"[⚠️] El archivo local '{ruta_local_completa.name}' no fue encontrado. Se requiere descarga.")
        needs_download = True
    
    # Caso 2: Versión local es más antigua
    elif version_local < version_remota_corta:
        print(f"[⚠️] ¡Nueva versión disponible! Local: {version_local} < Remota: {version_remota_corta}")
        needs_download = True
    
    # Caso 3: Versión local es la misma o más nueva (poco probable, pero posible)
    else:
        print(f"[✓] Versión local ({version_local}) está actualizada (Remota: {version_remota_corta}).")
        return True # Ya está actualizado, terminar.

    # 5. Descarga (Solo si needs_download es True)
    if needs_download:
        
        # Determinar la carpeta de destino (generalmente el directorio base)
        ruta_destino_dir = BASE_DIR
        ruta_destino_completa = ruta_destino_dir / version_remota_completa

        print("\n---------------------------------------------------------")
        print(f"Versión más reciente: {version_remota_completa}")
        print(f"Ruta de destino recomendada: {ruta_destino_completa.resolve()}")
        print("---------------------------------------------------------")

        # Bucle interactivo para la descarga
        while True:
            respuesta = input(
                f"¿Confirmas la descarga de la nueva versión? (s/n): "
            ).strip().lower()

            if respuesta == "s":
                # Intentar crear el directorio si no existe (no debería fallar para BASE_DIR)
                ruta_destino_dir.mkdir(parents=True, exist_ok=True)
                
                if descargar_nueva_version(url_descarga, ruta_destino_completa):
                    # Actualizar config.ini para reflejar el nuevo nombre del JAR
                    try:
                        config = configparser.ConfigParser()
                        config.read(CONFIG_INI)
                        if SONAR_SECTION not in config:
                            config[SONAR_SECTION] = {}
                        config[SONAR_SECTION]['ruta_jar'] = version_remota_completa
                        with open(CONFIG_INI, 'w', encoding='utf-8') as configfile:
                            config.write(configfile)
                        print(f"[✓] Éxito: '{CONFIG_INI}' actualizado con 'ruta_jar = {version_remota_completa}'.")
                    except Exception as e:
                        print(f"[❌] Advertencia: No se pudo actualizar {CONFIG_INI} automáticamente: {e}", file=sys.stderr)

                    # Preguntar por la limpieza
                    eliminar = input(f"\n¿Deseas eliminar otras versiones antiguas en la carpeta '{ruta_destino_dir.name}'? (s/n): ").strip().lower()
                    if eliminar == "s":
                        eliminar_versiones_antiguas(str(ruta_destino_dir), version_remota_completa)
                    else:
                        print("Las versiones antiguas se conservarán.")
                    
                    print("\n[✓] Paso 5 completado con éxito. Continúa con el Paso 6 (Generación de Reporte).")
                    return True
                
                else:
                    # La descarga falló
                    print("[❌] Falló la descarga del JAR. Terminando.")
                    return False
            
            elif respuesta == "n":
                print("[❌] Descarga omitida por el usuario. El reporte podría fallar si el JAR necesario no está disponible o es antiguo.")
                return False 
            else:
                print("Respuesta no válida. Por favor, introduce 's' o 'n'.")
            
    # Si la lógica llegó aquí por un error no contemplado, o si needs_download fue False (manejado arriba)
    return False


print("\n[!] AVISO LEGAL: Use solo con autorizacion. / LEGAL NOTICE: Authorized use only.\n")
if __name__ == "__main__":
    import sys
    try:
        print("\n--- INICIO DE 05_download_cnes_report.py ---")
        
        if main_download_cnes_report():
            print("\n[✓] 05_download_cnes_report.py finalizado con éxito.")
            sys.exit(0)
        else:
            # Si retorna False (descarga fallida, JAR no encontrado o rechazada por usuario)
            print("\n[❌] 05_download_cnes_report.py finalizado con errores funcionales (descarga/verificación fallida).")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n[👋] Proceso de descarga cancelado por el usuario.")
        sys.exit(0)
    except Exception as e:
        # Captura errores críticos (red, IO, etc.)
        print(f"\n[❌] Error crítico en 05_download_cnes_report.py: {e}", file=sys.stderr)
        sys.exit(1)