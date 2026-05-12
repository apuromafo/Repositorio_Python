# 01_config.ini.py
# Versión: 2.4.3 (CONFIGURACIÓN MAESTRA COMPLETA)
# Objetivo: Configurar URL, Token, Plantilla, JAR y Autor de forma interactiva.

import configparser
import os
import sys
from pathlib import Path
from typing import Optional, Dict, Tuple

# --- Constantes ---
CONSTANTS = {
    "MAX_DIR_SEARCH": 4,
    "SCANNER_PREFIX": 'sonar-scanner-',
    "INSTALL_FOLDER": 'sonarscan',
    "CONFIG_INI": "config.ini",
    "PROPERTIES": "sonar-project.properties",
    "SECTION": "SonarQube"
}

def _find_base_dir_and_scanner() -> Tuple[Path, str]:
    """Busca la carpeta del scanner en 'sonarscan/' o niveles superiores."""
    current_dir = Path(os.getcwd())
    folder_sonarscan = current_dir / CONSTANTS["INSTALL_FOLDER"]
    if folder_sonarscan.exists() and folder_sonarscan.is_dir():
        for item in folder_sonarscan.iterdir():
            if item.is_dir() and item.name.startswith(CONSTANTS["SCANNER_PREFIX"]):
                return current_dir, f"{CONSTANTS['INSTALL_FOLDER']}/{item.name}"
    check_dir = current_dir
    for _ in range(CONSTANTS["MAX_DIR_SEARCH"] + 1):
        for item in check_dir.iterdir():
            if item.is_dir() and item.name.startswith(CONSTANTS["SCANNER_PREFIX"]):
                return check_dir, item.name
        if check_dir.parent == check_dir: break
        check_dir = check_dir.parent
    return current_dir, ""

def solicitar_input(prompt: str, valor_actual: str) -> str:
    """Maneja la entrada de usuario permitiendo dejar el valor actual por defecto."""
    nuevo = input(f"{prompt} (Actual: {valor_actual or 'Ninguno'}): ").strip()
    return nuevo if nuevo else valor_actual

def gestionar_config_ini(config_path: Path):
    """Interfaz interactiva para configurar todos los campos del config.ini."""
    config = configparser.ConfigParser()
    
    # Valores por defecto iniciales
    url = "https://tu-servidor-sonar.cl"
    token = ""
    jar = "sonar-cnes-report-5.0.4.jar"
    plantilla = "code-analysis-template.docx"
    autor = "Seguridad Ofensiva"

    if config_path.exists():
        config.read(config_path, encoding='utf-8')
        if CONSTANTS["SECTION"] in config:
            url = config.get(CONSTANTS["SECTION"], 'url', fallback=url)
            token = config.get(CONSTANTS["SECTION"], 'sonar.token', fallback=token)
            jar = config.get(CONSTANTS["SECTION"], 'ruta_jar', fallback=jar)
            plantilla = config.get(CONSTANTS["SECTION"], 'ruta_plantilla', fallback=plantilla)
            autor = config.get(CONSTANTS["SECTION"], 'nombrereporte', fallback=autor)

    print("\n--- CONFIGURACIÓN MAESTRA DE SONARQUBE ---")
    print("Presiona [ENTER] para mantener el valor actual.\n")
    
    url = solicitar_input("[?] URL del servidor", url)
    token = solicitar_input("[?] Token de acceso", token)
    jar = solicitar_input("[?] Nombre del archivo JAR", jar)
    plantilla = solicitar_input("[?] Ruta/Nombre de la plantilla (.docx)", plantilla)
    autor = solicitar_input("[?] Nombre del autor/equipo para el reporte", autor)

    # Guardar cambios
    if not config.has_section(CONSTANTS["SECTION"]):
        config.add_section(CONSTANTS["SECTION"])
    
    config.set(CONSTANTS["SECTION"], 'url', url)
    config.set(CONSTANTS["SECTION"], 'sonar.token', token)
    config.set(CONSTANTS["SECTION"], 'ruta_jar', jar)
    config.set(CONSTANTS["SECTION"], 'ruta_plantilla', plantilla)
    config.set(CONSTANTS["SECTION"], 'nombrereporte', autor)

    with open(config_path, 'w', encoding='utf-8') as f:
        config.write(f)
    
    print(f"\n[✅] Configuración guardada exitosamente en {CONSTANTS['CONFIG_INI']}")
    return {'url': url, 'sonar.token': token}

def sincronizar_properties(base_dir: Path, data: Dict[str, str]):
    prop_path = base_dir / CONSTANTS["PROPERTIES"]
    if not prop_path.exists(): return
    try:
        with open(prop_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        new_lines = []
        for line in lines:
            if line.strip().startswith('sonar.host.url='):
                new_lines.append(f"sonar.host.url={data['url']}\n")
            elif line.strip().startswith('sonar.token='):
                new_lines.append(f"sonar.token={data['sonar.token']}\n")
            else:
                new_lines.append(line)
        with open(prop_path, 'w', encoding='utf-8') as f:
            f.writelines(new_lines)
        print(f"[✓] {CONSTANTS['PROPERTIES']} sincronizado automáticamente.")
    except Exception as e:
        print(f"[❌] Error al sincronizar .properties: {e}")

def main():
    try:
        print(f"\n{'='*60}\n⚙️  PASO 01: CONFIGURACIÓN E INTERACTIVIDAD\n{'='*60}")
        base_dir, scanner_path = _find_base_dir_and_scanner()
        
        config_path = base_dir / CONSTANTS["CONFIG_INI"]
        datos_clave = gestionar_config_ini(config_path)

        if scanner_path:
            sincronizar_properties(base_dir, datos_clave)
        
        print("\n[✓] Paso 01 finalizado correctamente.")
    except KeyboardInterrupt:
        print("\n[👋] Cancelado.")
    except Exception as e:
        print(f"\n[❌] ERROR: {e}")

if __name__ == "__main__":
    main()