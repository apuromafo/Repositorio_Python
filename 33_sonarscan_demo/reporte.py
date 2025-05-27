#!/usr/bin/env python3
# coding: utf-8
"""
Herramienta completa para generar reportes de SonarQube.
Este script realiza lo siguiente:
- Lee configuración desde config.ini (creado automáticamente si no existe).
- Compara los valores con sonar-scanner.properties.
- Pregunta si desea actualizar config.ini si hay diferencias.
- Ejecuta el generador de reporte con sonar-cnes-report-X.Y.Z.jar.
- Crea directorios únicos por ejecución.
- Opcionalmente comprime la carpeta de salida en ZIP.
"""

__description__ = 'Herramienta de apoyo a ejecutar reporte de frida'
__author__ = 'Michel Faúndez'
__version__ = '0.0.4'
__date__ = '2025-06-04'

import os
import sys
import argparse
import configparser
import shutil
from datetime import datetime
import subprocess
from pathlib import Path

# === Variables globales ===

RUTA_PROPERTIES = r'C:\sonar-scanner-X.1.0.4889-windows-x64\conf\sonar-scanner.properties'

config = None
BASE_DIR = ""  # Se inicializa dentro de main()

# === Funciones de ayuda y validación ===

def mostrar_ayuda():
    """
    Muestra ayuda detallada sobre cómo usar este script.
    """
    print("""
[?] Ayuda del script - Generador de reportes SonarQube

Forma de uso:
1. Asegúrate de tener instalado Java y configurado sonar-scanner.properties
2. Luego ejecuta:
   python reporte.py -p NOMBRE_PROYECTO -o RUTA_SALIDA

   o usa -r para generar un ZIP:
   python reporte.py -r BUG-XXXX

3. También puedes usar variables de entorno:
   SONAR_PROYECTO = Nombre del proyecto
   SONAR_SALIDA   = Carpeta base de salida
   SONAR_REPORTE  = Genera un archivo ZIP con el resultado

Ejemplos:
   python reporte.py -p mi-proyecto -o ./salida
   python reporte.py -r BUG-XXXX
""")
    sys.exit(0)

def verificar_java():
    """
    Verifica si java está disponible en el sistema.
    """
    try:
        res = subprocess.run(['java', '-version'], capture_output=True, text=True)
        if res.returncode != 0:
            print("[❌] No se encontró 'java' en el sistema.")
            print("[!] Instala Java desde https://www.java.com/es/download/ ")
            sys.exit(1)
    except FileNotFoundError:
        print("[❌] No se encontró 'java'.")
        print("[!] Instala Java y asegura que esté en el PATH del sistema.")
        sys.exit(1)

def descargar_ultimo_jar(ruta_destino):
    """
    Busca y descarga la última versión del JAR desde GitHub.
    """
    print("[+] No se encontró el archivo JAR local. Buscando en GitHub...")
    try:
        url_api = "https://api.github.com/repos/cnescatlab/sonar-cnes-report/releases/latest"
        respuesta = requests.get(url_api)
        respuesta.raise_for_status()
        datos_release = respuesta.json()

        version = datos_release.get("tag_name", "").lstrip("v")
        print(f"[+] Versión más reciente: {version}")

        for asset in datos_release.get("assets", []):
            if asset["name"].endswith(".jar"):
                print(f"[+] Descargando {asset['name']}...")
                contenido = requests.get(asset["browser_download_url"]).content
                with open(ruta_destino, 'wb') as f:
                    f.write(contenido)
                print(f"[✅] Archivo descargado: {ruta_destino}")
                return True

        print("[❌] No se encontró ningún archivo .jar en los activos.")
        return False

    except Exception as e:
        print(f"[❌] Error al buscar o descargar el JAR: {e}")
        return False

# === Funciones principales ===

def cargar_configuracion(ruta_config):
    """
    Carga la configuración desde un archivo INI.
    Si no existe, crea uno básico.
    """
    global config
    config_parser = configparser.ConfigParser()
    if not os.path.exists(ruta_config):
        crear_config_ini(ruta_config)
    config_parser.read(ruta_config)
    if 'SonarQube' not in config_parser:
        raise KeyError("[ERROR] La sección 'SonarQube' no se encuentra en el archivo de configuración.")
    config = config_parser['SonarQube']

def crear_config_ini(ruta_config):
    """
    Crea un archivo config.ini con valores por defecto.
    """
    print("[!] No se encontró config.ini. Creando uno nuevo con valores por defecto...")
    config_parser = configparser.ConfigParser()
    config_parser['SonarQube'] = {
        'sonar.token': 'squ_xx_xxxxxxxxxxxxxxx',
        'url': 'https://sonarqube-aws.sitio.vip/ ',
        'NombreReporte': 'Seguridad Ofensiva',
        'ruta_jar': 'sonar-cnes-report-5.0.2.jar',
        'ruta_plantilla': 'code-analysis-template.docx'
    }
    with open(ruta_config, 'w', encoding='utf-8') as f:
        config_parser.write(f)
    print(f"[✅] Archivo creado: {ruta_config}")

def respaldar_config_ini(ruta_config):
    """
    Hace una copia de seguridad antes de modificarlo.
    Formato: config.ini.backupDDMMHHMM
    """
    fecha_hora = datetime.now().strftime("%d%m%H%M")
    ruta_backup = os.path.splitext(ruta_config)[0] + f".backup{fecha_hora}"
    shutil.copy2(ruta_config, ruta_backup)
    print(f"[+] Backup creado: {ruta_backup}")

def leer_properties(ruta_prop):
    """
    Lee el archivo .properties y devuelve un diccionario con sus claves.
    Solo lee las claves necesarias: sonar.host.url y sonar.token
    """
    prop_dict = {}
    if not os.path.exists(ruta_prop):
        print(f"[ERROR] No se encontró el archivo .properties en: {ruta_prop}")
        return prop_dict
    with open(ruta_prop, 'r', encoding='utf-8') as f:
        for linea in f:
            linea = linea.strip()
            if linea and not linea.startswith('#'):
                if '=' in linea:
                    clave, valor = linea.split('=', 1)
                    prop_dict[clave.strip()] = valor.strip()

    claves_necesarias = ['sonar.host.url', 'sonar.token']
    faltantes = [c for c in claves_necesarias if c not in prop_dict]
    if faltantes:
        print("[ERROR] Faltan claves en sonar-scanner.properties:")
        for c in faltantes:
            print(f"        - {c}")
        print("[SUGERENCIA] Asegúrate de que tenga estas líneas:")
        print("        sonar.host.url=https://tu-instancia.sonarqube.com  ")
        print("        sonar.token=mi_token_secreto")
        return {}

    return prop_dict

def comparar_y_actualizar_config(config_path):
    """
    Compara sonar.host.url y sonar.token con los valores de config.ini.
    Si hay diferencias, pregunta si quiere actualizar el archivo INI.
    """
    props = leer_properties(RUTA_PROPERTIES)
    if not props:
        print("[⚠️] No se pudieron leer valores del archivo .properties.")
        return

    url_scanner = props.get('sonar.host.url')
    token_scanner = props.get('sonar.token')

    global config
    url_ini = config.get('url')
    token_ini = config.get('sonar.token')

    cambios = []
    if url_scanner != url_ini:
        cambios.append(('url', url_scanner))
    if token_scanner != token_ini:
        cambios.append(('sonar.token', token_scanner))

    if cambios:
        print("\n[!] Diferencias detectadas entre .properties y config.ini:")
        for clave, valor_prop in cambios:
            valor_ini = url_ini if clave == 'url' else token_ini
            print(f" - {clave}:")
            print(f"     Valor en .properties: {valor_prop}")
            print(f"     Valor en .ini       : {valor_ini}")

        respuesta = input("\n¿Desea actualizar estos valores en config.ini? (s/n): ").strip().lower()
        if respuesta == 's':
            respaldar_config_ini(config_path)
            config_parser = configparser.ConfigParser()
            config_parser.read(config_path)
            for clave, valor in cambios:
                config_parser['SonarQube'][clave] = valor
            with open(config_path, 'w', encoding='utf-8') as f:
                config_parser.write(f)
            print("[✅] Valores actualizados correctamente.")
        else:
            print("[❌] No se realizaron cambios.")
    else:
        print("\nGenerador de reportes SonarQube" )#"\n[✅] Todos los valores coinciden entre .properties y config.ini.")

def crear_directorio_unico(base_dir):
    """
    Crea un directorio único basado en la fecha y hora actual.
    Retorna la ruta completa del nuevo directorio.
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    nombre = f"reporte_{timestamp}"
    ruta = os.path.join(base_dir, nombre)
    os.makedirs(ruta, exist_ok=True)
    print(f"[+] Directorio único creado: {ruta}")
    return ruta

def ejecutar_sonar_report(token, url, proyecto, nombre_reporte, plantilla, salida):
    """
    Ejecuta el comando de generación de reporte con java -jar.
    Maneja errores comunes como tokens inválidos o archivos faltantes.
    """
    global BASE_DIR
    ruta_jar = os.path.join(BASE_DIR, config.get('ruta_jar'))

    # Si no existe el JAR, intentar descargarlo
    if not os.path.isfile(ruta_jar):
        print(f"[⚠️] No se encontró el archivo JAR: {ruta_jar}")
        print("[?] ¿Deseas descargar automáticamente la última versión? (s/n)")
        respuesta = input().strip().lower()
        if respuesta == 's':
            if not descargar_ultimo_jar(ruta_jar):
                print("[❌] No se pudo descargar el JAR. Saliendo.")
                sys.exit(1)
        else:
            print("[❌] Operación cancelada. El archivo JAR es obligatorio.")
            sys.exit(1)

    comando = [
        'java', '-jar', ruta_jar,
        '-t', token,
        '-s', url,
        '-p', proyecto,
        '-a', nombre_reporte,
        '-r', plantilla,
        '-o', salida
    ]

    try:
        resultado = subprocess.run(comando, check=True, capture_output=True, text=True)
        if resultado.stdout:
            print("Salida estándar:")
            print(resultado.stdout)
        if resultado.stderr:
            print("Información adicional:")
            print(resultado.stderr)
        print("[✅] Reporte generado exitosamente.")
    except subprocess.CalledProcessError as e:
        print("[❌] Error al ejecutar SonarQube:")
        if e.stdout:
            print(e.stdout)
        if e.stderr:
            print(e.stderr)
        if "Unauthorized" in e.stderr or "401" in e.stderr:
            print("[!] Sugerencia: El token puede estar expirado o incorrecto.")
        sys.exit(1)

def comprimir_salida(salida):
    """
    Comprime el directorio de salida en un archivo ZIP.
    """
    nombre_salida = os.path.basename(salida)
    fecha = datetime.now().strftime("%Y%m%d_%H%M%S")
    nombre_zip = f"reporte_{nombre_salida}_{fecha}.zip"
    ruta_zip = os.path.join(os.path.dirname(salida), nombre_zip)
    shutil.make_archive(ruta_zip.replace('.zip', ''), 'zip', salida)
    print(f"[+] Carpeta comprimida: {ruta_zip}.zip")

# === Función principal ===

def main():
    global BASE_DIR, config

    parser = argparse.ArgumentParser(description='Generador de reportes de SonarQube', add_help=False)
    parser.add_argument('-h', '--help', action='store_true', help='Mostrar esta ayuda')
    parser.add_argument('-p', '--proyecto', help='Nombre del proyecto', required=False)
    parser.add_argument('-o', '--salida', help='Ruta base de salida', required=False)
    parser.add_argument('-r', '--reporte', help='Nombre del proyecto (genera ZIP)', required=False)
    args = parser.parse_args()

    if args.help:
        mostrar_ayuda()

    proyecto = args.proyecto or os.getenv('SONAR_PROYECTO')
    salida_base = args.salida or os.getenv('SONAR_SALIDA')
    reporte = args.reporte or os.getenv('SONAR_REPORTE')

    base_dir_env = os.getenv('SONAR_BASE_DIR')
    if base_dir_env and os.path.isdir(base_dir_env):
        BASE_DIR = Path(base_dir_env).resolve()
    else:
        BASE_DIR = Path(__file__).parent.resolve()
        print(f"[+] Usando directorio actual como BASE_DIR: {BASE_DIR}")

    ruta_config = os.getenv('SONAR_CONFIG', BASE_DIR / "config.ini")

    try:
        cargar_configuracion(ruta_config)
    except (FileNotFoundError, KeyError) as e:
        print(f"[❌] Error cargando configuración: {e}")
        sys.exit(1)

    # Comparar con .properties y preguntar si hay diferencias
    comparar_y_actualizar_config(ruta_config)
    cargar_configuracion(ruta_config)  # Recargar tras posibles cambios

    # Obtener valores desde config.ini
    token = config.get('sonar.token')
    url = config.get('url')
    nombre_reporte = config.get('NombreReporte')
    ruta_plantilla = os.path.join(BASE_DIR, config.get('ruta_plantilla'))

    # Buscar en subcarpeta 'plantillas/'
    if not os.path.isfile(ruta_plantilla):
        ruta_plantilla = os.path.join(BASE_DIR, "plantillas", config.get('ruta_plantilla'))
        if not os.path.isfile(ruta_plantilla):
            print(f"[❌] No se encontró la plantilla '{config.get('ruta_plantilla')}' en ninguna ubicación.")
            print("Buscado en:")
            print(f"  - {os.path.join(BASE_DIR, config.get('ruta_plantilla'))}")
            print(f"  - {os.path.join(BASE_DIR, 'plantillas', config.get('ruta_plantilla'))}")
            sys.exit(1)

    # Validar campos obligatorios
    if not all([token, url, nombre_reporte, ruta_plantilla]):
        print("[❌] Faltan valores obligatorios en config.ini.")
        sys.exit(1)

    if reporte:
        proyecto = reporte
        salida_base = reporte
        zipar = True
    else:
        zipar = False

    if salida_base and not os.path.isabs(salida_base):
        salida_base = Path.cwd() / salida_base

    if not salida_base:
        print("""
[❌] ERROR: Debe proporcionar una ruta de salida (-o) o definir SONAR_SALIDA

Uso:
  python reporte.py -p <proyecto> -o <salida>
  python reporte.py -r <nombre_reporte>

Para ver todas las opciones:
  python reporte.py -h
""")
        sys.exit(1)

    try:
        salida = crear_directorio_unico(salida_base)
    except Exception as e:
        print(f"[❌] Error al crear directorio de salida: {e}")
        sys.exit(1)

    if not proyecto or not salida:
        print("[❌] Debe proporcionar el nombre del proyecto y la ruta de salida.")
        sys.exit(1)

    try:
        ejecutar_sonar_report(token, url, proyecto, nombre_reporte, ruta_plantilla, str(salida))
    except Exception as e:
        print(f"[❌] Error durante la ejecución: {e}")
        sys.exit(1)

    if zipar:
        comprimir_salida(str(salida))

if __name__ == '__main__':
    try:
        import requests
    except ImportError:
        print("""
[❌] Falta la librería 'requests'.
Instálala usando:
    pip install requests
""")
        sys.exit(1)

    main()