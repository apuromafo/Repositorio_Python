# -*- coding: utf-8 -*-
import re
import sys
import argparse
import json
import os
import configparser
from datetime import datetime
from pathlib import Path

# ===================================================
# 📝 INFORMACIÓN DEL SCRIPT
# ===================================================
# Version: 1.3.6 (Fiel al original + Integración config.ini)
# Autor: seguridad ofensiva
# ===================================================

BASE_DIR = Path(__file__).parent.resolve()
CONFIG_INI_PATH = BASE_DIR / "config.ini"

def leer_url_desde_config():
    """Lee la URL base desde el config.ini generado en el paso 01."""
    config = configparser.ConfigParser()
    if CONFIG_INI_PATH.exists():
        try:
            config.read(CONFIG_INI_PATH, encoding='utf-8')
            return config.get("SonarQube", "url", fallback="https://sonarqube-aws.sitio.vip").rstrip('/')
        except:
            pass
    return "https://sonarqube-aws.sitio.vip"

URL_BASE = leer_url_desde_config()

CONFIG = {
    "VERSION": "1.3.6",
    "URL_DASHBOARD": f"{URL_BASE}/dashboard?id=",
    "URL_DOWNLOAD": f"{URL_BASE}/api/regulatory_reports/download?project={{}}&branch=main",
    "PREFIJO_BUG_DEFAULT": "BUG-",
    "PREFIJOS_PERMITIDOS": ["BUG-", "GVDR-"],
    "TITULO_DEFECTO": "ANALISIS",
    "RAMA_MASTER_DEFAULT": "MASTER",
    "FORMATO_FECHA": "%Y_%m_%d",
    "CARACTERES_PROHIBIDOS": r'[^\w.-]',
    "CARPETA_REPORTES": "Reportes",
    "FORMATO_ARCHIVO_OPCIONES": "opciones_{}.txt",
    "OPCIONES_LENGUAJE": {
        "1": "MAVEN", "2": "GRADLE", "3": "JS/TS & WEB", "4": ".NET",
        "5": "C/C++", "6": "OBJECTIVE-C", "7": "FLUTTER/DART", 
        "8": "JAVA (Generic/Binaries)", "9": "RPG", "10": "MOBILE", "11": "OTROS",
    },
    "LOGICA_LENGUAJES": {
        "RPG": {"INDICADOR": "RPG", "TIPO_SCANNER": "SONAR_SCANNER", "COMANDO_PROPIEDAD": '-D"sonar.rpg.leftMarginWidth=0"'},
        "JAVA (Generic/Binaries)": {"INDICADOR": "JAVA", "TIPO_SCANNER": "SONAR_SCANNER", "COMANDO_PROPIEDAD": '-D"sonar.java.binaries=."'},
        "MOBILE": {"INDICADOR": "MOBILE", "TIPO_SCANNER": "SONAR_SCANNER", "COMANDO_PROPIEDAD": ''},
        "MAVEN": {"INDICADOR": "MAVEN", "TIPO_SCANNER": "MAVEN", "COMANDO_PROPIEDAD": ''},
        "GRADLE": {"INDICADOR": "GRADLE", "TIPO_SCANNER": "GRADLE", "COMANDO_PROPIEDAD": ''},
        ".NET": {"INDICADOR": "DOTNET", "TIPO_SCANNER": "DOTNET", "COMANDO_PROPIEDAD": ''},
        "JS/TS & WEB": {"INDICADOR": "WEB", "TIPO_SCANNER": "SONAR_SCANNER", "COMANDO_PROPIEDAD": ''},
        "C/C++": {"INDICADOR": "CPP", "TIPO_SCANNER": "SONAR_SCANNER", "COMANDO_PROPIEDAD": ''},
        "OBJECTIVE-C": {"INDICADOR": "OBJC", "TIPO_SCANNER": "SONAR_SCANNER", "COMANDO_PROPIEDAD": ''},
        "FLUTTER/DART": {"INDICADOR": "FLUTTER", "TIPO_SCANNER": "SONAR_SCANNER", "COMANDO_PROPIEDAD": ''},
        "OTROS": {"INDICADOR": "GENERAL", "TIPO_SCANNER": "SONAR_SCANNER", "COMANDO_PROPIEDAD": ''},
    }
}

def sanitize_display_name(text):
    if not text: return ""
    replacements = {'á':'a','é':'e','í':'i','ó':'o','ú':'u','ñ':'n','Á':'A','É':'E','Í':'I','Ó':'O','Ú':'U','Ñ':'N'}
    for a, u in replacements.items(): text = text.replace(a, u)
    text = re.sub(r'[^a-zA-Z0-9\s\-\._]', '', text)
    return re.sub(r'\s+', ' ', text).strip()

def sanitize_key(text):
    if not text: return ""
    sanitized = re.sub(CONFIG['CARACTERES_PROHIBIDOS'], '_', text.strip())
    return re.sub(r'[_]+', '_', sanitized).upper()

def solicitar_dato(paso_numero, descripcion, valor_previo=None):
    print(f"\n--- PASO {paso_numero}: {descripcion} ---")
    if valor_previo is not None and valor_previo != "":
        print(f"    [Valor actual: {valor_previo}]")
        confirmar = input(f"    ¿Deseas mantener este valor? (S/n) [S]: ").strip().upper() or 'S'
        if confirmar == 'S':
            return valor_previo
    nuevo_valor = input(f"    Introduce el nuevo valor: ").strip()
    return nuevo_valor if nuevo_valor else valor_previo

def guardar_reporte(ticket, datos):
    try:
        folder = BASE_DIR / CONFIG['CARPETA_REPORTES']
        if not folder.exists():
            folder.mkdir(parents=True)
        clean_name = ticket.replace("BUG-", "").replace("GVDR-", "")
        ruta = folder / CONFIG['FORMATO_ARCHIVO_OPCIONES'].format(clean_name)
        with open(ruta, 'w', encoding='utf-8') as f:
            json.dump(datos, f, indent=4, ensure_ascii=False)
        print(f"\n[OK] Reporte guardado con éxito en: {ruta}")
        
        # PERSISTENCIA PARA PASO 07: Guardamos el Key y Nombre en un temporal
        with open(BASE_DIR / "temp_project_name.txt", "w", encoding="utf-8") as f:
            f.write(f"{datos['project_key']}|{datos['titulo_orig']}")
            
    except Exception as e:
        print(f"\n[ERROR] No se pudo guardar el archivo: {e}")

def mostrar_disclaimer(p_key):
    print("\n" + "-"*80)
    print("### AVISO IMPORTANTE: USO DE LICENCIA Y CONECTIVIDAD")
    print("-" * 80)
    print(f"⚠️  VPN: Debe estar activa para conectar a {URL_BASE}")
    print(f"\n### USO DE LICENCIA SONARQUBE")
    print(f"Para optimizar el uso de la licencia, los proyectos deben usar la rama")
    print(f"**{CONFIG['RAMA_MASTER_DEFAULT']}** en su Project Key si es el código base.")
    print(f"Esto evita duplicar el consumo de líneas de código escaneadas.")
    print(f"\n> Project Key generado: {p_key}")
    print("-" * 80)

def mostrar_bloque_final(p_key, p_name, logica, comentarios):
    print("\n" + "="*30 + " RESULTADOS GENERADOS " + "="*30)
    sistemas = ["WINDOWS", "LINUX/MAC"]
    for os_type in sistemas:
        print(f"\n> COMANDO PARA {os_type} ({logica['INDICADOR']}):")
        scanner_bin = "sonar-scanner.bat" if os_type == "WINDOWS" else "sonar-scanner"
        line_cont = " ^\n  " if os_type == "WINDOWS" else " \\\n   "
        if logica['TIPO_SCANNER'] == "MAVEN":
            cmd = f"mvn clean verify sonar:sonar{line_cont}-Dsonar.projectKey={p_key}{line_cont}-Dsonar.projectName='{p_name}'"
        elif logica['TIPO_SCANNER'] == "DOTNET":
            cmd = f"dotnet sonarscanner begin /k:\"{p_key}\" /n:\"{p_name}\"\ndotnet build\ndotnet sonarscanner end"
        else:
            prop = f" {logica['COMANDO_PROPIEDAD']}" if logica['COMANDO_PROPIEDAD'] else ""
            cmd = f"{scanner_bin} -D\"sonar.projectKey={p_key}\" -D\"sonar.projectName={p_name}\"{prop} -X"
        print(f"```bash\n{cmd}\n```")

    print("\n" + "-"*80)
    print(f"🔗 DASHBOARD: {CONFIG['URL_DASHBOARD']}{p_key}")
    print(f"📥 REPORTE:    {CONFIG['URL_DOWNLOAD'].format(p_key)}")
    if comentarios:
        print(f"📝 NOTAS:      {comentarios}")
    print("-" * 80)

def ejecutar(opciones_previas=None):
    try:
        print(f"\n{'='*60}\n GENERADOR DE ANALISIS SONARQUBE v{CONFIG['VERSION']}\n{'='*60}")
        
        # 1. TICKET
        val_ticket = opciones_previas.get('ticket') if opciones_previas else None
        bug_raw = solicitar_dato(1, "Número de TICKET (ej: BUG-1234)", val_ticket)
        if not bug_raw: return
        
        bug_num = sanitize_key(bug_raw)
        if not any(p in bug_num for p in CONFIG['PREFIJOS_PERMITIDOS']):
            bug_num = f"{CONFIG['PREFIJO_BUG_DEFAULT']}{bug_num.replace('-', '')}"

        # 2. TECNOLOGÍA
        val_lang_id = opciones_previas.get('lang_id') if opciones_previas else "1"
        val_lang_name = opciones_previas.get('tecnologia') if opciones_previas else "MAVEN"
        
        print(f"\n--- PASO 2: Selección de Tecnología ---")
        print(f"    [Actual: {val_lang_name}]")
        if (input(f"    ¿Mantener esta tecnología? (S/n) [S]: ").strip().upper() or 'S') == 'N':
            for k, v in sorted(CONFIG['OPCIONES_LENGUAJE'].items(), key=lambda x: int(x[0])):
                print(f"      ({k}) {v}")
            lang_opt = input(f"    Selecciona una opción [{val_lang_id}]: ").strip() or val_lang_id
        else:
            lang_opt = val_lang_id

        lang_name = CONFIG['OPCIONES_LENGUAJE'].get(lang_opt, "OTROS")
        logica = CONFIG['LOGICA_LENGUAJES'].get(lang_name)

        # 3. NOMBRE PROYECTO
        val_tit = opciones_previas.get('titulo_orig') if opciones_previas else CONFIG['TITULO_DEFECTO']
        titulo_raw = solicitar_dato(3, "Nombre descriptivo del Proyecto/Repositorio", val_tit)
        titulo_display = sanitize_display_name(titulo_raw)
        titulo_key = sanitize_key(titulo_display)

        # 4. FLAGS
        val_inc_bug = opciones_previas.get('inc_bug', 'S') if opciones_previas else 'S'
        inc_bug = solicitar_dato(4, "¿Incluir ticket en el nombre visual? (S/n)", val_inc_bug).upper()
        
        val_inc_fecha = opciones_previas.get('inc_fecha', 'N') if opciones_previas else 'N'
        inc_fecha = solicitar_dato(5, "¿Añadir fecha actual al ID? (s/N)", val_inc_fecha).upper()

        # 6. COMENTARIOS
        val_comm = opciones_previas.get('comentarios', '') if opciones_previas else ''
        comentarios = solicitar_dato(6, "Información adicional (Rama Bitbucket, URLs)", val_comm)

        # CÁLCULOS Y OUTPUT
        fecha_hoy = datetime.now().strftime(CONFIG['FORMATO_FECHA'])
        final_key = f"{bug_num}_{titulo_key}"
        if inc_fecha == "S": final_key += f"_{fecha_hoy}"
        if logica['INDICADOR'] == "RPG": final_key = f"RPG_{final_key}"
        final_name = f"{bug_num} - {titulo_display}" if inc_bug == "S" else titulo_display

        mostrar_bloque_final(final_key, final_name, logica, comentarios)
        mostrar_disclaimer(final_key)

        # GUARDADO
        reporte_data = {
            "ticket": bug_num, "lang_id": lang_opt, "tecnologia": lang_name,
            "titulo_orig": titulo_raw, "inc_bug": inc_bug, "inc_fecha": inc_fecha, 
            "project_key": final_key, "comentarios": comentarios
        }
        
        if (input(f"\n¿Deseas guardar estos cambios? (S/n) [S]: ").strip().upper() or 'S') == 'S':
            guardar_reporte(bug_num, reporte_data)

    except KeyboardInterrupt:
        print("\n\n[!] Cancelado por el usuario.")
        sys.exit(0)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", type=str, help="Ruta al archivo de opciones")
    args = parser.parse_args()

    opciones_cargadas = None
    if args.input and os.path.exists(args.input):
        try:
            with open(args.input, 'r', encoding='utf-8') as f:
                opciones_cargadas = json.load(f)
        except:
            print("\n[!] Error al leer el archivo.")
            
    ejecutar(opciones_cargadas)