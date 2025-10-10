import os
import platform
import configparser
import requests
import re


def mostrar_info_sistema():
    """Muestra información del sistema operativo y arquitectura."""
    sistema = platform.system()
    maquina = platform.machine()
    procesador = platform.processor()

    print("=== INFORMACIÓN DEL SISTEMA ===")
    print(f"Sistema operativo: {sistema}")
    print(f"Arquitectura: {maquina}")
    print(f"Procesador: {procesador}")
    print("===============================")

    return sistema, maquina


def obtener_version_sonarqube(url, token):
    """Obtiene la versión de SonarQube desde la API."""
    headers = {'Authorization': f'Bearer {token}'}
    try:
        print("[+] Conectando a SonarQube...")
        response = requests.get(f'{url}/api/server/version', headers=headers)
        response.raise_for_status()
        version = response.text.strip()
        print(f"[✓] Versión detectada: {version}")
        return version
    except requests.exceptions.RequestException as e:
        print(f"[✗] Error al conectar con SonarQube: {e}")
        return None


def mostrar_url_documentacion(version_sonarqube):
    """Muestra la URL de documentación oficial según la versión de SonarQube."""
    version_major_minor = '.'.join(version_sonarqube.split('.')[:2])  # Ejemplo: '10.8'
    url_documentacion = f"https://docs.sonarsource.com/sonarqube-server/{version_major_minor}/analyzing-source-code/scanners/sonarscanner/"
    
    print("\n[+] Documentación oficial para esta versión:")
    print(f"{url_documentacion}\n")


def obtener_datos_scanner_desde_version_file():
    """
    Lee el archivo remoto que contiene las URLs y hashes del SonarScanner CLI.
    Devuelve un diccionario con los datos.
    """
    url_version_file = "https://raw.githubusercontent.com/SonarSource/sonarqube-scan-action/master/sonar-scanner-version"
    print(f"[+] Leyendo archivo de configuración desde: {url_version_file}")

    try:
        response = requests.get(url_version_file)
        response.raise_for_status()

        scanner_data = {}
        lines = response.text.splitlines()

        for line in lines:
            if '=' in line:
                key, value = line.split('=', 1)
                scanner_data[key.strip()] = value.strip()

        print("[✓] Datos del scanner cargados correctamente.")
        return scanner_data

    except Exception as e:
        print(f"[✗] Error al leer el archivo de configuración: {e}")
        return None


def seleccionar_url_descarga(scanner_data):
    """Selecciona la URL de descarga según el sistema operativo y arquitectura."""
    sistema = platform.system().lower()
    arquitectura = platform.machine().lower()

    print(f"[i] Sistema actual: {sistema} - {arquitectura}")

    if sistema == 'windows' and '64' in arquitectura:
        return scanner_data.get('sonar-scanner-url-windows-x64')
    elif sistema == 'linux':
        if 'aarch64' in arquitectura or 'arm' in arquitectura:
            return scanner_data.get('sonar-scanner-url-linux-aarch64')
        else:
            return scanner_data.get('sonar-scanner-url-linux-x64')
    elif sistema == 'darwin':  # macOS
        if 'aarch64' in arquitectura or 'arm' in arquitectura:
            return scanner_data.get('sonar-scanner-url-macosx-aarch64')
        else:
            return scanner_data.get('sonar-scanner-url-macosx-x64')
    else:
        print("[✗] Plataforma no soportada.")
        return None


def descargar_archivo(url, destino):
    """Descarga el archivo desde la URL y lo guarda en destino."""
    try:
        print(f"[+] Descargando desde: {url}")
        with requests.get(url, stream=True) as r:
            r.raise_for_status()
            with open(destino, 'wb') as archivo:
                for chunk in r.iter_content(chunk_size=8192):
                    archivo.write(chunk)
        print(f"[✓] Archivo guardado en: {destino}")
        return True
    except Exception as e:
        print(f"[✗] Error al descargar: {e}")
        return False


def main():
    print("=== INFO: DESCARGA AUTOMÁTICA DE SONARSCANNER ===\n")

    # Mostrar info del sistema antes de continuar
    mostrar_info_sistema()

    # Cargar configuración
    config = configparser.ConfigParser()
    if not os.path.isfile('config.ini'):
        print("[✗] Archivo config.ini no encontrado.")
        return

    config.read('config.ini')

    try:
        sonar_config = config['SonarQube']
        token = sonar_config.get('sonar.token')
        url_base = sonar_config.get('url')

        if not token or not url_base:
            print("[✗] Falta token o URL en config.ini")
            return

        # Paso 1: Obtener versión de SonarQube
        version_sonar = obtener_version_sonarqube(url_base, token)
        if not version_sonar:
            print("[i] No se pudo obtener la versión de SonarQube, pero continuamos...")
        else:
            # Paso 2: Mostrar URL de documentación oficial
            mostrar_url_documentacion(version_sonar)

        # Paso 3: Leer archivo .version
        scanner_data = obtener_datos_scanner_desde_version_file()
        if not scanner_data:
            return

        # Paso 4: Seleccionar URL de descarga según sistema
        url_descarga = seleccionar_url_descarga(scanner_data)
        if not url_descarga:
            print("[✗] No se encontró una URL de descarga compatible con tu sistema.")
            return

        print(f"[✓] URL de descarga seleccionada: {url_descarga}")

        # Paso 5: Descargar el archivo
        carpeta_destino = 'sonarscan'
        os.makedirs(carpeta_destino, exist_ok=True)
        nombre_archivo = os.path.basename(url_descarga)
        ruta_completa = os.path.join(carpeta_destino, nombre_archivo)

        if os.path.exists(ruta_completa):
            print(f"[i] El archivo ya existe: {ruta_completa}")
        else:
            if descargar_archivo(url_descarga, ruta_completa):
                print(f"[✓] ¡Listo! Puedes encontrar el scanner en la carpeta '{carpeta_destino}'.")
            else:
                print("[✗] Hubo un error durante la descarga.")

    except KeyError:
        print("[✗] La sección [SonarQube] o claves requeridas no están en config.ini.")


if __name__ == "__main__":
    main()