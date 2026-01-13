# 01_config.ini.py
# Versión: 2.2.0 (Pregunta obligatoriamente si desea actualizar config.ini)
# Objetivo: 1. Preguntar si desea modificar la URL y Token en config.ini. 
#           2. Aplicar esos valores a sonar-project.properties estrictamente.

import configparser
import os
import re
from typing import Optional, Dict

# --- Nombres de archivos y constantes ---
CONFIG_INI = "config.ini"
SONAR_PROPERTIES = "sonar-project.properties"
SONAR_SECTION = "SonarQube"
# Placeholders que se usan para la creación por defecto y para prompts
DEFAULT_URL_PLACEHOLDER = "https://sitio.sonarqube.cl" 
DEFAULT_TOKEN_PLACEHOLDER = "squ_XX" 

# --- Funciones de Utilidad Base ---

def _ensure_default_files_exist() -> bool:
    """
    Crea config.ini y sonar-project.properties si no existen, con valores de ejemplo.
    Retorna True si los archivos existen o se crearon, False si hubo un error.
    """
    success = True
    
    # 1. Crear config.ini si no existe
    if not os.path.exists(CONFIG_INI):
        print(f"[i] Creando '{CONFIG_INI}' por defecto. Por favor, edítelo.")
        default_ini_content = f"""[{SONAR_SECTION}]
sonar.token = {DEFAULT_TOKEN_PLACEHOLDER}
url = {DEFAULT_URL_PLACEHOLDER}
nombrereporte = Analisis de Codigo
ruta_jar = sonar-cnes-report-5.0.2.jar
ruta_plantilla = plantillas\\code-analysis-template.docx
"""
        try:
            with open(CONFIG_INI, 'w', encoding='utf-8') as f:
                f.write(default_ini_content)
        except Exception as e:
            print(f"[❌] Error crítico al crear '{CONFIG_INI}': {e}", file=sys.stderr)
            success = False

    # 2. Crear sonar-project.properties si no existe
    if not os.path.exists(SONAR_PROPERTIES):
        print(f"[i] Creando '{SONAR_PROPERTIES}' por defecto.")
        default_prop_content = f"""# Propiedades de configuración de SonarScanner
sonar.projectKey=mi_proyecto_ejemplo
sonar.sources=.
sonar.host.url={DEFAULT_URL_PLACEHOLDER}
sonar.token={DEFAULT_TOKEN_PLACEHOLDER}
"""
        try:
            with open(SONAR_PROPERTIES, 'w', encoding='utf-8') as f:
                f.write(default_prop_content)
        except Exception as e:
            print(f"[❌] Error crítico al crear '{SONAR_PROPERTIES}': {e}", file=sys.stderr)
            success = False
            
    return success

def _read_properties_file_safe(path: str) -> Dict[str, str]:
    """Lee un archivo .properties simple (clave=valor) de forma segura, 
    ignorando líneas comentadas y vacías."""
    data = {}
    if not os.path.exists(path):
        return data

    try:
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                # Ignorar líneas vacías o comentadas
                if not line or line.startswith('#'):
                    continue
                # Buscar patrón clave=valor
                match = re.match(r'^([a-zA-Z0-9._-]+)\s*=\s*(.*)$', line)
                if match:
                    key = match.group(1).strip()
                    value = match.group(2).strip()
                    data[key] = value
    except Exception as e:
        print(f"[⚠️] Advertencia: Error al leer/parsear {path}. Error: {e}")
        return {} 
        
    return data

def update_properties_file_strict(ini_data: dict, properties_path: str) -> bool:
    """
    Actualiza estrictamente las claves de SonarQube en sonar-project.properties
    basándose en los valores de config.ini. Las claves obsoletas se eliminan o 
    se reescriben si son las claves objetivo.
    """
    target_keys = {
        'url': 'sonar.host.url',
        'sonar.token': 'sonar.token'
    }

    new_content_lines = []
    
    # Cargar el contenido actual
    if os.path.exists(properties_path):
        try:
            with open(properties_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
        except Exception as e:
            print(f"[❌] Error al leer el archivo {properties_path}: {e}")
            return False
    else:
        # Si el archivo no existe, lo crearemos solo con las claves target
        lines = []

    # Banderas para saber si ya hemos agregado las claves
    keys_written = {prop_key: False for prop_key in target_keys.values()}
    
    # 1. Procesar líneas existentes (reemplazar las claves objetivo)
    for line in lines:
        line_stripped = line.strip()
        # Ignorar líneas vacías
        if not line_stripped:
            new_content_lines.append(line)
            continue
        
        # Buscar patrón clave=valor
        match = re.match(r'^([a-zA-Z0-9._-]+)\s*=\s*(.*)$', line_stripped)
        
        if match:
            key = match.group(1).strip()
            # Si la clave es una de nuestras claves objetivo, la reemplazamos con el nuevo valor
            if key in target_keys.values():
                ini_key = next(k for k, v in target_keys.items() if v == key)
                new_value = ini_data.get(ini_key, '')
                # Reemplazar la línea con el nuevo valor de config.ini
                new_line = f"{key}={new_value}\n"
                new_content_lines.append(new_line)
                keys_written[key] = True
            else:
                # Mantener otras propiedades
                new_content_lines.append(line)
        else:
            # Mantener comentarios y otras líneas que no son clave=valor
            new_content_lines.append(line)

    # 2. Agregar las claves objetivo si no se encontraron en el archivo (al final)
    for ini_key, prop_key in target_keys.items():
        if not keys_written[prop_key]:
            new_value = ini_data.get(ini_key, '')
            # Añadir una nueva línea para la clave faltante
            new_content_lines.append(f"\n# Agregado por 01_config.ini.py\n{prop_key}={new_value}\n")

    # 3. Escribir el nuevo contenido
    try:
        with open(properties_path, 'w', encoding='utf-8') as f:
            f.writelines(new_content_lines)
        return True
    except Exception as e:
        print(f"[❌] Error crítico al escribir en '{properties_path}': {e}")
        return False

# --- Funciones de Configuración (Modificadas) ---

def _update_config_ini(config_obj: configparser.ConfigParser, new_url: str, new_token: str):
    """Actualiza y guarda los nuevos valores de URL y Token en config.ini."""
    if SONAR_SECTION not in config_obj:
        config_obj[SONAR_SECTION] = {}
        
    config_obj[SONAR_SECTION]['url'] = new_url
    config_obj[SONAR_SECTION]['sonar.token'] = new_token
    
    try:
        with open(CONFIG_INI, 'w', encoding='utf-8') as configfile:
            config_obj.write(configfile)
        print(f"[✓] Éxito: '{CONFIG_INI}' actualizado con los nuevos valores.")
    except Exception as e:
        print(f"[❌] Error crítico al escribir en '{CONFIG_INI}': {e}")
        raise # Propagar el error

def _read_config_ini() -> Optional[dict]:
    """Lee y retorna los datos de config.ini."""
    data = {}
    config = configparser.ConfigParser()
    try:
        # La lectura es insensible a mayúsculas
        config.read(CONFIG_INI) 
        if SONAR_SECTION in config:
            section = config[SONAR_SECTION]
            # Obtener claves principales
            data['url'] = section.get('url', fallback='').strip()
            data['sonar.token'] = section.get('sonar.token', fallback='').strip()
            
            # Obtener otras claves (importantes para el paso 6)
            data['nombrereporte'] = section.get('nombrereporte', fallback='').strip()
            data['ruta_jar'] = section.get('ruta_jar', fallback='').strip()
            data['ruta_plantilla'] = section.get('ruta_plantilla', fallback='').strip()

    except Exception as e:
        print(f"[❌] Error al leer '{CONFIG_INI}': {e}")
        return None
    return data

def _prompt_and_update_ini_data(ini_data: dict) -> Optional[dict]:
    """
    Pregunta al usuario si desea modificar la URL y el Token en config.ini.
    Si acepta, lee los nuevos valores y actualiza config.ini.
    Retorna los datos de config.ini (posiblemente actualizados) o None si el usuario cancela o hay error.
    """
    current_url = ini_data.get('url', DEFAULT_URL_PLACEHOLDER)
    current_token = ini_data.get('sonar.token', DEFAULT_TOKEN_PLACEHOLDER)
    
    print("\n---------------------------------------------------")
    print("      Verificación de 'config.ini' (Fuente de Verdad)      ")
    print("---------------------------------------------------")
    print(f"URL actual:  {current_url}")
    print(f"Token actual: {current_token[:4]}...{current_token[-4:]} (mostrando inicio/fin)")
    
    try:
        respuesta = input("\n[?] ¿Desea **MODIFICAR** la URL y el Token en config.ini? (s/N): ").strip().lower()
    except EOFError:
        respuesta = 'n'
        
    # Usar los datos actuales como base
    new_data = ini_data.copy()
    
    if respuesta in ('s', 'si'):
        print("\n--- INGRESO DE NUEVOS VALORES ---")
        while True:
            # Pedir nueva URL, sugiriendo la actual como valor por defecto
            new_url = input(f"Ingrese la NUEVA URL de SonarQube (dejar vacío para '{current_url}'): ").strip()
            if not new_url:
                new_url = current_url
            
            # Pedir nuevo Token, sugiriendo el actual
            new_token = input(f"Ingrese el NUEVO Token de SonarQube (dejar vacío para '{current_token}'): ").strip()
            if not new_token:
                new_token = current_token
                
            if not new_url or not new_token:
                 print("[❌] ERROR: No se permiten valores vacíos. Inténtelo de nuevo.")
                 continue

            try:
                # 1. Leer el archivo original para mantener otras claves
                config = configparser.ConfigParser()
                config.read(CONFIG_INI)
                # 2. Actualizar y reescribir config.ini
                _update_config_ini(config, new_url, new_token)
                
                # 3. Actualizar el diccionario de datos para la siguiente fase (sincronización)
                new_data['url'] = new_url
                new_data['sonar.token'] = new_token
                
                print("[✓] 'config.ini' actualizado. Continuando con la sincronización.")
                return new_data
            except Exception:
                # El error ya fue reportado en _update_config_ini
                return None 
    else:
        print("\n[i] Valores de 'config.ini' conservados. Verificando sincronización...")
        return ini_data


# --- Función Principal ---

def config_sync_check(properties_path: str = SONAR_PROPERTIES) -> bool:
    """
    Carga config.ini, permite al usuario actualizarlo, y luego sincroniza 
    los valores clave (URL y Token) con sonar-project.properties estrictamente.
    """
    print(f"\n⚙️ [Paso 1: Sincronización de Configuración]")
    
    # 0. Asegurar que los archivos existan
    if not _ensure_default_files_exist():
        return False
        
    # 1. Leer config.ini (la fuente de verdad)
    ini_data = _read_config_ini()
    if ini_data is None:
        return False
        
    # 2. INTERACCIÓN OBLIGATORIA: Permitir al usuario actualizar config.ini
    ini_data = _prompt_and_update_ini_data(ini_data)
    if ini_data is None:
        return False
    
    # 3. Leer los datos actuales del archivo de escaneo (para log informativo)
    prop_data = _read_properties_file_safe(properties_path)

    # 4. Determinar si hay diferencias
    needs_update = False
    print("\n--- Verificación de Sincronización con .properties ---")

    key_mapping = {
        'url': 'sonar.host.url',
        'sonar.token': 'sonar.token'
    }

    for ini_key, prop_key in key_mapping.items():
        ini_value = ini_data.get(ini_key, '').strip()
        prop_value = prop_data.get(prop_key, '').strip()
        
        # Si la URL o el Token en el .ini es diferente al .properties, necesitamos actualizar.
        if ini_value != prop_value:
            print(f"[⚠️] Diferencia detectada: '{prop_key}'. Aplicando actualización estricta.")
            needs_update = True
        else:
            print(f"[✓] Sincronizado: '{prop_key}'")

    if not needs_update:
        print("[✓] URL y Token ya sincronizados. No se requiere acción de escritura.")
        # Retorna True con la configuración validada y potencialmente actualizada en el paso 2.
        return True

    # 5. APLICACIÓN ESTRICTA (Si needs_update es True, se aplica automáticamente)
    print(f"\n[i] Sincronizando 'config.ini' -> '{properties_path}' de forma estricta.")
    if not update_properties_file_strict(ini_data, properties_path):
        print("[❌] Error al aplicar los valores estrictamente.")
        return False
        
    print(f"[✓] Éxito: Sincronización completada. '{properties_path}' actualizado.")
    return True

if __name__ == "__main__":
    import sys
    try:
        print("\n--- PRUEBA INDEPENDIENTE DE 01_config.ini.py ---")
        # El nombre de la función principal basada en el traceback
        if not config_sync_check():
            print("[❌] 01_config.ini.py finalizado con errores funcionales.")
            sys.exit(1)
        else:
            print("[✓] 01_config.ini.py finalizado con éxito.")
    except KeyboardInterrupt:
        # Este es el catch si la interrupción ocurre antes/después de la llamada principal.
        # Si ocurre dentro de input(), ya fue manejado en la función.
        print("\n[👋] Proceso de configuración cancelado por el usuario.")
        sys.exit(0)
    except Exception as e:
        # Manejo de error crítico general
        print(f"[❌] Error crítico inesperado en 01_config.ini.py: {e}", file=sys.stderr)
        sys.exit(1)