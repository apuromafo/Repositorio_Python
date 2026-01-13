# 04_validate_sonarscan.py 
# Versión: 6.0.0 (Minimalista. Solo CLI -v y API desde config.ini. Sin tocar properties.)
# Objetivo: Validar conectividad al servidor SonarQube (API) y disponibilidad del scanner CLI (-v).

import subprocess
import os
import platform
import configparser
import requests
import sys
from requests.exceptions import RequestException
from typing import Tuple, Optional
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# --- Constantes ---
CONFIG_INI = "config.ini"
SONAR_SECTION = "SonarQube"
DEFAULT_URL_PLACEHOLDER = "https://sitio_demo.cl" 
DEFAULT_TOKEN_PLACEHOLDER = "squ_demo" 

# --- UTILITY: Lector de Configuración ---

def _read_sonar_config() -> Tuple[str, str]:
    """Lee y retorna la URL y el Token desde config.ini."""
    config = configparser.ConfigParser()
    
    try:
        # Intenta leer el archivo
        if not config.read(CONFIG_INI):
            print(f"[⚠️] Advertencia: Archivo '{CONFIG_INI}' no encontrado.")
            raise configparser.NoSectionError
            
        # Obtener valores con fallback
        url = config.get(SONAR_SECTION, 'url', fallback=DEFAULT_URL_PLACEHOLDER)
        token = config.get(SONAR_SECTION, 'sonar.token', fallback=DEFAULT_TOKEN_PLACEHOLDER)
        
    except configparser.NoSectionError:
        print(f"[⚠️] Advertencia: Sección [{SONAR_SECTION}] no encontrada. Usando valores por defecto.")
        url = DEFAULT_URL_PLACEHOLDER
        token = DEFAULT_TOKEN_PLACEHOLDER
        
    return url, token

# --- Funciones de Validación ---

def _check_sonar_api_status(host_url: str, token: str) -> bool:
    """Verifica la conectividad al servidor SonarQube."""
    if not host_url or host_url == DEFAULT_URL_PLACEHOLDER:
        print("[⚠️] Omisión API: URL del host SonarQube es placeholder. Saltando validación API.")
        return True
    
    print(f"\n📞 Verificando conectividad API en: {host_url}")
    # Endpoint recomendado para obtener la versión
    version_endpoint = f"{host_url.rstrip('/')}/api/server/version"
    headers = {'Authorization': f'Bearer {token}'}

    try:
        # Se incluye verify=False para entornos de prueba con certificados auto-firmados
        response = requests.get(version_endpoint, headers=headers, timeout=10, verify=False) 
        response.raise_for_status()
        
        server_version = response.text.strip()
        print(f"[✓] Conexión API exitosa. Versión del Servidor SonarQube: {server_version}")
        return True
        
    except RequestException as e:
        print(f"[❌] ERROR de Conexión/HTTP: No se pudo conectar al servidor en {host_url}.")
        if hasattr(e, 'response') and e.response.status_code in (401, 403):
            print("   -> Causa: Token de SonarQube Inválido o sin permisos.")
        else:
            print(f"   -> Causa: {e}")
        return False


def _check_cli_version(scanner_executable: str = "sonar-scanner") -> bool:
    """
    Verifica que el ejecutable 'sonar-scanner' esté disponible ejecutando '-v' (¡REQUERIDO!).
    """
    # Adaptación para Windows
    if platform.system() == "Windows" and scanner_executable == "sonar-scanner":
        scanner_executable = "sonar-scanner.bat"
        
    cli_version_command = [scanner_executable, "-v"]
    print(f"\n🔍 Ejecutando verificación de versión CLI: {' '.join(cli_version_command)}")
    
    try:
        result_v = subprocess.run(
            cli_version_command, 
            check=True, 
            capture_output=True, 
            text=True, 
            encoding='utf-8',
            timeout=15
        )
        
        # Mostrar la salida que contiene la versión del Scanner
        print("--- Salida de sonar-scanner -v ---")
        print(result_v.stdout.strip())
        print("----------------------------------")
        
        print("[✓] Verificación CLI exitosa.")
        return True
        
    except FileNotFoundError:
        print(f"[❌] ERROR CLI: El ejecutable '{scanner_executable}' no fue encontrado.")
        return False
    except subprocess.CalledProcessError as e:
        print(f"[❌] ERROR CLI: La verificación falló (código {e.returncode}). Salida de error: {e.stderr.strip()}")
        return False

# --- Función Principal (Exportable al Orquestador 00_main.py) ---

def validate_sonar_scanner_and_api(scanner_executable: str = "sonar-scanner") -> bool:
    """
    Función principal del Paso 4. Lee la configuración de config.ini y realiza 
    las verificaciones de la API y la CLI.
    """
    print("\n---------------------------------------------------")
    print("🚀 [Paso 4: Validación de SonarScanner y Conectividad]")
    print("---------------------------------------------------")
    
    # 1. Leer la configuración de la "fuente de verdad" (config.ini)
    host_url, token = _read_sonar_config()
    
    # 2. Verificar la disponibilidad del SonarScanner CLI (-v)
    cli_ok = _check_cli_version(scanner_executable)
    
    # 3. Verificar la API del servidor SonarQube
    api_ok = _check_sonar_api_status(host_url, token)
    
    return api_ok and cli_ok

# --- Bloque de ejecución principal para independencia ---

if __name__ == "__main__":
    print("\n--- PRUEBA INDEPENDIENTE DE 04_validate_sonarscan.py ---")
    
    # La prueba independiente llama directamente a la función principal
    test_passed = validate_sonar_scanner_and_api()

    # Mostrar resultado final
    if test_passed:
        print("\n✅ PRUEBA INDEPENDIENTE EXITOSA: CLI y conexión API validadas.")
    else:
        print("\n❌ PRUEBA INDEPENDIENTE FALLIDA: Revise los errores anteriores.")