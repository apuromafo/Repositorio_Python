#!/usr/bin/env python3
# coding: utf-8
"""
07_reporte.py - Versión 2.5.0 (EDICIÓN TRANSPARENCIA TOTAL)
- Panel informativo de variables detectadas.
- Validación proactiva de existencia del proyecto en SonarQube.
- Menú vertical estructurado.
- Gestión de errores 404 y limpieza de temporales.
"""

import os
import sys
import argparse
import configparser
import subprocess
import requests
import shutil
from datetime import datetime
from pathlib import Path
import urllib3

# Configuración de entorno
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
BASE_DIR = Path(__file__).parent.resolve()
CONFIG_INI_PATH = BASE_DIR / "config.ini"
TEMP_FILE = BASE_DIR / "temp_project_name.txt"

def leer_config_maestra():
    config = configparser.ConfigParser()
    if not CONFIG_INI_PATH.exists():
        print(f"[❌] Error: No se encontró {CONFIG_INI_PATH}. Ejecute el Paso 01.")
        return None
    try:
        config.read(CONFIG_INI_PATH, encoding='utf-8')
        return {
            "url": config.get("SonarQube", "url", fallback="").strip(),
            "token": config.get("SonarQube", "sonar.token", fallback="").strip(),
            "jar": config.get("SonarQube", "ruta_jar", fallback="sonar-cnes-report-5.0.4.jar").strip(),
            "plantilla": config.get("SonarQube", "ruta_plantilla", fallback="code-analysis-template.docx").strip(),
            "autor": config.get("SonarQube", "nombrereporte", fallback="Seguridad Ofensiva").strip()
        }
    except Exception as e:
        print(f"[❌] Error crítico al leer config.ini: {e}")
        return None

def mostrar_panel_transparencia(conf, proyecto):
    """Muestra un cuadro estético con los datos que se enviarán a la API."""
    token_mask = f"{conf['token'][:5]}***{conf['token'][-5:]}" if len(conf['token']) > 10 else "***"
    
 
    print(f" {'RESUMEN DE CONFIGURACIÓN DETECTADA':^63} ")
    print("" + " "*65 + " ")
    print(f" 🌐 Servidor Sonar: {conf['url'][:44]:<43}")
    print(f" 🔑 Token (Auth):   {token_mask:<43} ")
    print(f" 📂 Proyecto Key:   {proyecto:<43} ")
    print(f" 📄 Plantilla DOCX: {conf['plantilla'][:43]:<43} ")
    print(f" 👤 Autor Reporte:  {conf['autor'][:43]:<43} ")
 

def validar_proyecto_api(url, token, proyecto):
    """Valida si el proyecto existe antes de llamar al JAR."""
    print(f"[i] Validando existencia de '{proyecto}' en el servidor...")
    endpoint = f"{url.rstrip('/')}/api/components/show?component={proyecto}"
    try:
        res = requests.get(endpoint, auth=(token, ''), verify=False, timeout=15)
        if res.status_code == 200:
            print(f"[✅] Proyecto verificado y listo para reportar.")
            return True
        elif res.status_code == 404:
            print(f"[⚠️] Error 404: El proyecto '{proyecto}' no existe en este servidor.")
            return False
        else:
            print(f"[⚠️] No se pudo validar (Status {res.status_code}). Procediendo con cautela...")
            return True
    except Exception as e:
        print(f"[❌] Error de conexión: {e}")
        return False

def descargar_regulatory(url_base, proyecto, token, output_dir):
    print(f"\n[📥] Descargando Regulatory Report ZIP...")
    endpoint = f"{url_base.rstrip('/')}/api/regulatory_reports/download?project={proyecto}&branch=main"
    try:
        response = requests.get(endpoint, auth=(token, ''), verify=False, timeout=60)
        if response.status_code == 200:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            folder_reg = Path(output_dir) / f"regulatory_{proyecto}_{timestamp}"
            folder_reg.mkdir(parents=True, exist_ok=True)
            ruta_zip = folder_reg / f"Regulatory_Report_{proyecto}.zip"
            with open(ruta_zip, 'wb') as f:
                f.write(response.content)
            print(f"[✅] ZIP guardado: {ruta_zip.name}")
            return folder_reg
        return None
    except Exception as e:
        print(f"[❌] Fallo en descarga Regulatory: {e}")
        return None

def generar_cnes(jar, token, url, proyecto, autor, plantilla, output_dir):
    print(f"\n[🚀] Ejecutando CNES Report (Proceso Java)...")
    jar_path = BASE_DIR / jar
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    folder_cnes = Path(output_dir) / f"cnes_{proyecto}_{timestamp}"
    folder_cnes.mkdir(parents=True, exist_ok=True)

    comando = ["java", "-jar", str(jar_path), "-s", url, "-t", token, "-p", proyecto, "-a", autor, "-o", str(folder_cnes)]
    if (BASE_DIR / plantilla).exists():
        comando.extend(["-t", str(BASE_DIR / plantilla)])

    try:
        subprocess.run(comando, check=True, capture_output=True, text=True)
        print(f"[✅] CNES generado exitosamente.")
        return folder_cnes
    except subprocess.CalledProcessError as e:
        print(f"[❌] Error en el proceso CNES:\n    {e.stderr[:150]}...")
        if folder_cnes.exists() and not any(folder_cnes.iterdir()):
            shutil.rmtree(folder_cnes)
        return None

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--project", help="Project Key")
    parser.add_argument("-o", "--output", default="Reportes_Generados", help="Carpeta de salida")
    args = parser.parse_args()

    print(f"\n{'='*67}\n📊 PASO 07: GENERACIÓN DE REPORTES PROFESIONALES\n{'='*67}")
    conf = leer_config_maestra()
    if not conf: return

    # 1. LÓGICA DE DETECCIÓN DE PROYECTO
    proyecto = args.project
    if not proyecto and TEMP_FILE.exists():
        with open(TEMP_FILE, "r", encoding="utf-8") as f:
            data = f.read().strip()
            proyecto_detectado = data.split('|')[0] if '|' in data else data
        
        print(f"[i] Detectado del paso anterior: {proyecto_detectado}")
        if input(f"[?] ¿Es este el proyecto correcto? (s/N): ").lower() == 's':
            proyecto = proyecto_detectado

    if not proyecto:
        proyecto = input("[?] Ingrese el Project Key manualmente: ").strip()

    if not proyecto:
        print("[❌] Operación abortada: No se proporcionó Project Key.")
        return

    # 2. PANEL DE TRANSPARENCIA Y VALIDACIÓN
    mostrar_panel_transparencia(conf, proyecto)
    if not validar_proyecto_api(conf['url'], conf['token'], proyecto):
        if input("[?] ¿Desea forzar la generación de todos modos? (s/N): ").lower() != 's':
            return

    # 3. MENÚ VERTICAL ESTÉTICO
    print("\nELIJA EL TIPO DE REPORTE A GENERAR:")
    print("  [1] Solo CNES (Word Técnico / Excel)     ")
    print("  [2] Solo Regulatory (ZIP Oficial Sonar)  ")
    print("  [3] Ambos Reportes (Recomendado)         ")
    print("  [0] Salir                                ")
    
    seleccion = input("Seleccione una opción [3]: ").strip() or "3"

    if seleccion == "0": return

    base_salida = BASE_DIR / args.output
    base_salida.mkdir(exist_ok=True)
    rutas = []

    try:
        # 4. EJECUCIÓN
        if seleccion in ['1', '3']:
            r = generar_cnes(conf["jar"], conf["token"], conf["url"], proyecto, conf["autor"], conf["plantilla"], base_salida)
            if r: rutas.append(r)
        
        if seleccion in ['2', '3']:
            r = descargar_regulatory(conf["url"], proyecto, conf["token"], base_salida)
            if r: rutas.append(r)

        # 5. POST-PROCESAMIENTO
        if rutas:
            print("\n" + "─"*45)
            if input("[?] ¿Desea comprimir cada carpeta en un archivo ZIP? (s/n) [s]: ").lower() != 'n':
                for ruta in rutas:
                    shutil.make_archive(str(ruta), 'zip', ruta)
                    print(f"[📦] CREADO: {Path(ruta).name}.zip")
            
            # Limpieza final
            if TEMP_FILE.exists():
                os.remove(TEMP_FILE)
                print("[i] Temporal limpiado con éxito.")
        else:
            print("\n[!] No se generó contenido. Revise el estado del proyecto en SonarQube.")

        print(f"\n{'='*67}\n[✓] PROCESO FINALIZADO\n{'='*67}")

    except KeyboardInterrupt:
        print("\n\n[👋] Cancelado por el usuario.")

if __name__ == "__main__":
    main()