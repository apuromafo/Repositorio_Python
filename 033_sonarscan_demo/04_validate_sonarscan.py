# 04_validate_sonarscan.py
# Versión: 6.5.0 (CORRECCIÓN DE RUTAS Y CONFIG.INI)
# Objetivo: Validar API de SonarQube y ejecución del scanner usando la ruta del proyecto.

import subprocess
import os
import platform
import configparser
import requests
import sys
from pathlib import Path
import urllib3

# Desactivar avisos de certificados inseguros
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Configuración de Rutas ---
# Ahora buscamos el config.ini en la misma carpeta que el script
BASE_DIR = Path(__file__).parent.resolve()
CONFIG_INI_PATH = BASE_DIR / "config.ini"

def leer_configuracion():
    """Lee URL y Token desde el config.ini en la raíz."""
    config = configparser.ConfigParser()
    print(f"[i] Leyendo configuración desde: {CONFIG_INI_PATH}")
    
    if not CONFIG_INI_PATH.exists():
        print(f"[❌] Error: No se encuentra el archivo {CONFIG_INI_PATH}")
        return None, None

    try:
        config.read(CONFIG_INI_PATH, encoding='utf-8')
        url = config.get("SonarQube", "url", fallback="").strip()
        token = config.get("SonarQube", "sonar.token", fallback="").strip()
        return url, token
    except Exception as e:
        print(f"[❌] Error al leer config.ini: {e}")
        return None, None

def buscar_ejecutable_scanner():
    """Busca el ejecutable dentro de la carpeta 'sonarscan' local."""
    executable = "sonar-scanner.bat" if platform.system().lower() == 'windows' else "sonar-scanner"
    
    # 1. Intentar usar el comando directo (si el paso 02 funcionó, esto debería bastar)
    try:
        subprocess.run([executable, "-v"], capture_output=True, shell=True)
        return executable
    except:
        pass

    # 2. Fallback: Buscar en la carpeta local sonarscan/
    print("[i] El comando global no responde, buscando en carpeta local...")
    folder_sonarscan = BASE_DIR / "sonarscan"
    if folder_sonarscan.exists():
        for item in folder_sonarscan.iterdir():
            if item.is_dir() and "sonar-scanner-" in item.name:
                full_path = item / "bin" / executable
                if full_path.exists():
                    return str(full_path)
    return None

def validar_api(url, token):
    """Prueba la conexión con el servidor."""
    if not url:
        print("[❌] URL no configurada en config.ini")
        return False

    print(f"\n[+] Probando conexión a: {url}")
    try:
        # Validar Versión (Conectividad básica)
        api_version = f"{url.rstrip('/')}/api/server/version"
        res = requests.get(api_version, verify=False, timeout=10)
        if res.status_code == 200:
            print(f"✅ Conexión establecida. Versión de Sonar: {res.text}")
        else:
            print(f"❌ Error de conexión. Código: {res.status_code}")
            return False

        # Validar Token (Autenticación)
        if token:
            print("[+] Validando Token de acceso...")
            api_auth = f"{url.rstrip('/')}/api/authentication/validate"
            res_auth = requests.get(api_auth, auth=(token, ''), verify=False, timeout=10)
            if res_auth.status_code == 200 and "true" in res_auth.text.lower():
                print("✅ Token válido y autenticado.")
                return True
            else:
                print(f"❌ Token inválido o expirado (Código {res_auth.status_code})")
                return False
        else:
            print("⚠️ No hay token para validar.")
            return True

    except Exception as e:
        print(f"❌ Error de red: {e}")
        return False

def main():
    print(f"\n{'='*60}\n🚀 PASO 04: VALIDACIÓN DE SCANNER Y API\n{'='*60}")
    
    # 1. Verificar Configuración
    url, token = leer_configuracion()
    if not url:
        print("[❌] Abortando: Falta configuración crítica.")
        return

    # 2. Verificar Ejecutable
    scanner_cmd = buscar_ejecutable_scanner()
    if scanner_cmd:
        print(f"✅ Scanner detectado: {scanner_cmd}")
        try:
            res = subprocess.check_output([scanner_cmd, "-v"], shell=True, text=True)
            version = res.split('\n')[0]
            print(f"   -> {version}")
            cli_ok = True
        except:
            print("❌ Error al ejecutar el scanner detectado.")
            cli_ok = False
    else:
        print("❌ No se encontró 'sonar-scanner' en el PATH ni en la carpeta local.")
        cli_ok = False

    # 3. Verificar API
    api_ok = validar_api(url, token)

    if cli_ok and api_ok:
        print(f"\n{'='*60}\n[✓] TODO LISTO: Puedes proceder al escaneo.\n{'='*60}")
    else:
        print(f"\n{'='*60}\n[❌] FALLÓ LA VALIDACIÓN: Revisa los errores arriba.\n{'='*60}")

if __name__ == "__main__":
    main()