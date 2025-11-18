import re 
import sys
import argparse
import json
import platform
from datetime import datetime

# ===================================================
# 📝 INFORMACION DEL SCRIPT
# ===================================================
# Version: 1.0.5 (Sanitizacion Estricta ProjectName)
# Autor: seguridad ofensiva
# Ultima Actualizacion: 17 / 11 / 2025
# Descripcion: Genera comandos de analisis de SonarQube (mvn, gradle, dotnet, sonar-scanner)
#              adaptados a la nomenclatura interna (BUG-XXXX, RAMA, TITULO) y las 
#              directrices de uso de licencia (priorizando rama MASTER).
# NUEVO: Soporte para prefijos multiples de Project Key (BUG- y GVDR-).
# CORREGIDO: Se aplica sanitización estricta al Project Name (sonar.projectName) para eliminar corchetes, paréntesis y otros caracteres raros, manteniendo solo alfanuméricos, espacios, guiones y puntos, por compatibilidad.
# ===================================================

# ===============================================
# CONFIGURACION DECLARATIVA (Datos Estructurales)
# ===============================================
CONFIG = {
    # --- Configuracion General ---
    "VERSION": "1.0.7", # Version actualizada
    "PREFIJO_BUG_DEFAULT": "BUG-", # Prefijo por defecto para forzar
    "PREFIJOS_PERMITIDOS": ["BUG-", "GVDR-"], # NUEVO: Lista de prefijos permitidos
    "TITULO_DEFECTO": "ANALISIS",
    "RAMA_DEFECTO_SIN_BB": "SIN_RAMA",
    "RAMA_MASTER_DEFAULT": "MASTER",
    "FORMATO_FECHA": "%Y_%m_%d", # Formato: AAAA_MM_DD
    "CARACTERES_PROHIBIDOS": r'[^\w.-]', # Caracteres a reemplazar por '_' (para Project Key)
    "PREFIJO_BB_URL": "https://bitbucket.org/coopeuch/",
    "FORMATO_ARCHIVO_OPCIONES": "opciones_{}.txt", # Formato: opciones_ID_TICKET.txt (Inicial)
    "FORMATO_ARCHIVO_UPDATE": "opciones_{}_update_{}.txt", # Formato: opciones_ID_TICKET_update_AAAA_MM_DD.txt (Update)

    # --- Opciones de Menu para el Usuario ---
    "OPCIONES_LENGUAJE": {
        "1": "MAVEN", "2": "GRADLE", "3": "JS/TS & WEB", "4": ".NET",
        "5": "C/C++", "6": "OBJECTIVE-C", "7": "FLUTTER/DART", 
        "8": "JAVA (Generic/Binaries)", "9": "RPG", "10": "MOBILE", "11": "OTROS",
    },
    
    # --- Logica de Nomenclatura y Comando por Tecnologia ---
    "LOGICA_LENGUAJES": {
        "RPG": {"INDICADOR": "RPG", "APLICA_RAMA": False, "TIPO_SCANNER": "SONAR_SCANNER", "COMANDO_PROPIEDAD": '-D"sonar.rpg.leftMarginWidth=0"'},
        "JAVA (Generic/Binaries)": {"INDICADOR": "JAVA", "APLICA_RAMA": True, "TIPO_SCANNER": "SONAR_SCANNER", "COMANDO_PROPIEDAD": '-D"sonar.java.binaries=."'},
        "MOBILE": {"INDICADOR": "MOBILE", "APLICA_RAMA": True, "TIPO_SCANNER": "SONAR_SCANNER", "COMANDO_PROPIEDAD": ''},
        "MAVEN": {"INDICADOR": "MAVEN", "APLICA_RAMA": True, "TIPO_SCANNER": "MAVEN", "COMANDO_PROPIEDAD": ''},
        "GRADLE": {"INDICADOR": "GRADLE", "APLICA_RAMA": True, "TIPO_SCANNER": "GRADLE", "COMANDO_PROPIEDAD": ''},
        ".NET": {"INDICADOR": "DOTNET", "APLICA_RAMA": True, "TIPO_SCANNER": "DOTNET", "COMANDO_PROPIEDAD": ''},
        "JS/TS & WEB": {"INDICADOR": "WEB", "APLICA_RAMA": True, "TIPO_SCANNER": "SONAR_SCANNER", "COMANDO_PROPIEDAD": ''},
        "C/C++": {"INDICADOR": "CPP", "APLICA_RAMA": True, "TIPO_SCANNER": "SONAR_SCANNER", "COMANDO_PROPIEDAD": ''},
        "OBJECTIVE-C": {"INDICADOR": "OBJC", "APLICA_RAMA": True, "TIPO_SCANNER": "SONAR_SCANNER", "COMANDO_PROPIEDAD": ''},
        "FLUTTER/DART": {"INDICADOR": "FLUTTER", "APLICA_RAMA": True, "TIPO_SCANNER": "SONAR_SCANNER", "COMANDO_PROPIEDAD": ''},
        "OTROS": {"INDICADOR": "GENERAL", "APLICA_RAMA": True, "TIPO_SCANNER": "SONAR_SCANNER", "COMANDO_PROPIEDAD": ''},
    }
}

# ===============================================
# MENSAJES DE USUARIO (I18N Ready)
# ===============================================
MESSAGES = {
    # General (MODIFICADO para incluir la version)
    "HEADER": "\n--- Generador de Nombre de Ticket SonarQube y Comando (v{VERSION}) ---",
    "MODE_UPDATE_WARNING": "\n*** MODO ACTUALIZACIÓN (-i): Se usará el valor actual a menos que elijas actualizar (S) ***",
    "PROMPT_UPDATE": "¿Deseas actualizar? (S/n): ",
    "WARN_INPUT_INVALID": "Advertencia: Entrada no valida. Por favor, revisa el formato o las opciones.",
    "WARN_UPDATE_RESPONSE": "Advertencia: Respuesta no valida. Usa 'S' o 'N'.",
    "INFO_OPERATION_CANCELED": "\nOperacion cancelada por el usuario.",
    
    # P1: BUG (Modificado para prefijos multiples)
    "P1_PROMPT_INPUT": "\n1. Introduce el nuevo numero del TICKET (ej: {PREFIJO_1}1234, {PREFIJO_2}5678): ",
    "P1_PROMPT_UPDATE": "El TICKET actual es {BUG_VAL}. ¿Deseas actualizar? (S/n): ",
    "P1_WARN_PREFIX": "Advertencia: El ticket introducido no comienza con uno de los prefijos permitidos ({PREFIJOS}).",
    "P1_INFO_FORCE_PREFIX": "El script forzara el prefijo '{PREFIJO_USADO}' para la Project Key generada.",
    
    # P2: LENGUAJE
    "P2_HEADER": "\n2. Selecciona el tipo de lenguaje/tecnologia:",
    "P2_PROMPT_INPUT": "   Opcion: ",
    "P2_PROMPT_UPDATE": "El lenguaje actual es **{LANG_VAL}**. ¿Deseas actualizar? (S/n): ",
    "P2_PROMPT_NEW": "   Introduce la nueva opción (ej: 1, MAVEN, etc.): ",

    # P3: TITULO
    "P3_PROMPT_INPUT": "3. Introduce el titulo/nombre del proyecto (Project Name): ",
    "P3_PROMPT_UPDATE": "El titulo actual es **{TITLE_VAL}**. ¿Deseas actualizar? (S/n): ",
    "P3_PROMPT_NEW": "3. Introduce el nuevo titulo/nombre del proyecto (Project Name): ",

    # P4: RAMA
    "P4_PROMPT_CHECK": "\n4. ¿El analisis es sobre una rama de Bitbucket (Pu)? (s/N): ",
    "P4_PROMPT_UPDATE": "El uso de rama actual es {RAMA_VAL}. ¿Deseas actualizar? (S/n): ",
    "P4_INFO_NO_BB": "   > Analisis sin Bitbucket/rama. Se usara el Project Key simplificado.",
    "P4_PROMPT_RAMA_NAME": "   - Introduce el nombre de la rama Bitbucket (ej: feature/mi-cambio): ",
    "P4_PROMPT_RAMA_NAME_UPDATE": "La rama actual es **{RAMA_NAME}**. ¿Deseas actualizar? (S/n): ",
    "P4_PROMPT_MASTER": "   - ¿Es esta la rama **{MASTER_VAL}** o base del proyecto? (s/N): ",
    "P4_PROMPT_MASTER_UPDATE": "El estado 'MASTER' es {MASTER_VAL}. ¿Deseas actualizar? (S/n): ",

    # P5: INCLUIR BUG EN NOMBRE
    "P5_PROMPT": "\n5. ¿Incluir el ticket BUG ({BUG_VAL}) en el Project Name? (S/n): ",
    "P5_PROMPT_UPDATE": "El Project Name actual {PROJECT_NAME} ¿Deseas actualizar el uso del BUG? (S/n): ",

    # P6: INCLUIR FECHA
    "P6_PROMPT": "\n6. ¿Deseas anadir la fecha de hoy al nombre? (s/N): ",
    "P6_PROMPT_UPDATE": "El uso de fecha actual es {FECHA_VAL}. ¿Deseas actualizar? (S/n): ",
    
    # Output & Saving
    "OUTPUT_HEADER": "\n" + "="*80,
    "OUTPUT_PROJECT_KEY": "✅ Nombre de Proyecto (sonar.projectKey): **{KEY}**",
    "OUTPUT_PROJECT_NAME": "✅ Nombre del Proyecto (sonar.projectName): **{NAME}**",
    "OUTPUT_CMD_HEADER": "\n### Comando para SonarQube ({OS} - {LANG})",
    
    # Command Attention Messages (CORREGIDO)
    "OUTPUT_CMD_ATTENTION_MAVEN": "Recomendado: Utiliza este comando en la raiz de tu proyecto Maven.",
    "OUTPUT_CMD_ATTENTION_GRADLE": "Recomendado: Ejecuta este comando en la raiz de tu proyecto Gradle.",
    "OUTPUT_CMD_ATTENTION_DOTNET": ".NET/C#: El analisis requiere 3 pasos. Ejecuta estos comandos *en orden*.",
    "OUTPUT_CMD_ATTENTION_RPG": "Utiliza esta linea en el directorio raiz del codigo RPG/AS400.",
    "OUTPUT_CMD_ATTENTION_JAVA": "ATENCION: Esta linea incluye la propiedad de binarios. Usala si tu proyecto Java no usa Maven/Gradle o requiere escaneo de `.class`.",
    "OUTPUT_CMD_ATTENTION_CPP": "C/C++: Este es el comando base. Debes anteponer el *build wrapper*.",
    "OUTPUT_CMD_ATTENTION_DEFAULT": "Utiliza esta linea en el directorio raiz de tu proyecto.",

    # Disclaimer (CORREGIDO)
    "DISCLAIMER_HEADER": "\n\n" + "-"*80 + "\n### AVISO IMPORTANTE: USO DE LICENCIA Y CONECTIVIDAD",
    "DISCLAIMER_VPN_TITLE": "⚠️ **CONECTIVIDAD:**",
    "DISCLAIMER_VPN_TEXT": "Para que el escaneo de SonarQube se conecte a la plataforma, es **necesario** que la VPN se encuentre activa.",
    "DISCLAIMER_LICENSE_TITLE": "\n### USO DE LICENCIA SONARQUBE",
    "DISCLAIMER_LICENSE_TEXT_1": "En la practica, somos los que estamos usando la licencia de SonarQube.",
    "DISCLAIMER_LICENSE_TEXT_2": "Para optimizar el uso, todos los proyectos que se creen en SonarQube a partir de hoy",
    "DISCLAIMER_LICENSE_TEXT_3": "deben tener la rama **{MASTER_VAL}** en su Project Key si provienen de la rama base de Bitbucket.",
    "DISCLAIMER_LICENSE_TEXT_4": "Esto evita que el codigo base se re-escanee cada vez que se crea un ticket,",
    "DISCLAIMER_LICENSE_TEXT_5": "lo que nos ayuda a no usar licencia por codigo que ya existe.",
    "DISCLAIMER_KEY_GENERATED": "\n> **Project Key generado:** **{KEY}**",
    "DISCLAIMER_FOOTER": "-" * 80,
    
    # Save Prompts
    "SAVE_PROMPT_NEW": "\n¿Deseas guardar estas opciones para usar despues? (s/N): ",
    "SAVE_INFO_SAVED": "\n[INFO] Opciones guardadas en: **{FILE_NAME}**",
    "SAVE_INFO_REUSE": "Para volver a usarlas, ejecuta: python script_name.py -i {FILE_NAME}",
    "SAVE_ERROR": "\n[ERROR] No se pudo guardar el archivo de opciones: {ERROR}",
}

# ===============================================
# FUNCIONES DE ALMACENAMIENTO Y CARGA
# ===============================================

def guardar_opciones(bug_num_sanitized, opciones_dict, config, messages, is_update=False):
    """
    Guarda las opciones de usuario en un archivo JSON/TXT con formato condicional.
    """
    # Identificar y remover el prefijo para usar solo el numero/id en el nombre del archivo
    bug_number_only = bug_num_sanitized
    prefijos = config.get('PREFIJOS_PERMITIDOS', [config.get('PREFIJO_BUG_DEFAULT', '')])
    
    # Buscar el prefijo usado y removerlo para obtener el ID del ticket para el nombre del archivo
    for prefix in prefijos:
        if bug_num_sanitized.startswith(prefix):
            bug_number_only = bug_num_sanitized[len(prefix):]
            break
            
    if is_update:
        fecha_hoy = datetime.now().strftime(config['FORMATO_FECHA'])
        nombre_archivo = config['FORMATO_ARCHIVO_UPDATE'].format(bug_number_only, fecha_hoy)
    else:
        # Usamos bug_number_only (la parte del ID) para el nombre del archivo
        nombre_archivo = config['FORMATO_ARCHIVO_OPCIONES'].format(bug_number_only) 
    
    try:
        with open(nombre_archivo, 'w') as f:
            json.dump(opciones_dict, f, indent=4, ensure_ascii=False)
        
        print(messages['SAVE_INFO_SAVED'].format(FILE_NAME=nombre_archivo))
        if not is_update:
             print(messages['SAVE_INFO_REUSE'].format(FILE_NAME=nombre_archivo))
    except Exception as e:
        print(messages['SAVE_ERROR'].format(ERROR=e))

def cargar_opciones(nombre_archivo, messages):
    """Carga las opciones de usuario desde un archivo JSON/TXT."""
    try:
        with open(nombre_archivo, 'r') as f:
            opciones_cargadas = json.load(f)
        print(f"\n[INFO] Opciones cargadas exitosamente desde: **{nombre_archivo}**")
        return opciones_cargadas
    except FileNotFoundError:
        print(f"\n[ERROR] Archivo no encontrado: {nombre_archivo}")
        return None
    except json.JSONDecodeError:
        print(f"\n[ERROR] Formato de archivo invalido (no es un JSON valido): {nombre_archivo}")
        return None
    except Exception as e:
        print(f"\n[ERROR] Ocurrio un error al cargar el archivo: {e}")
        return None

# ===============================================
# FUNCIONES DE SANITIZACION Y UTILIDAD
# ===============================================

def validate_yes_no(input_val):
    """Validador robusto para 'S' o 'N', case-insensitive."""
    return input_val.upper() in ['S', 'N']

def sanitize_display_name(text):
    """
    v1.0.7: Reemplaza tildes y limita los caracteres para el Project Name (sonar.projectName).
    Permite: Alfanuméricos, espacios, guiones, puntos y guiones bajos (cumpliendo estricto).
    """
    if not text: return ""
    
    # 1. Reemplazar tildes (y eñes)
    replacements = {
        'á': 'a', 'é': 'e', 'í': 'i', 'ó': 'o', 'ú': 'u',
        'Á': 'A', 'É': 'E', 'Í': 'I', 'Ó': 'O', 'Ú': 'U',
        'ñ': 'n', 'Ñ': 'N',
    }
    sanitized = text
    for accented, unaccented in replacements.items():
        sanitized = sanitized.replace(accented, unaccented)
    
    # 2. Limitar caracteres: 
    # Reemplaza todo lo que NO sea (letras, numeros, espacio, guion, punto, guion bajo) por vacio.
    # Esto elimina corchetes, parentesis, interrogaciones, etc.
    sanitized = re.sub(r'[^a-zA-Z0-9\s\-\._]', '', sanitized)
    
    # 3. Limpiar espacios múltiples (reemplaza multiples espacios por uno solo)
    sanitized = re.sub(r'\s+', ' ', sanitized)
    
    return sanitized.strip()

def sanitize_input(text, config, is_project_key=True):
    """Limpia la cadena de texto para su uso en nombres de tickets o Project Keys (estricto)."""
    if not text: return ""
    
    sanitized = text.strip()
    
    if not is_project_key:
        # Sanitizacion basica (solo quitar multiples espacios)
        sanitized = re.sub(r'\s+', ' ', sanitized)

    if is_project_key:
        # Sanitizacion estricta para KEY (todo a '_' excepto alfanumerico, guion, punto)
        sanitized = re.sub(config['CARACTERES_PROHIBIDOS'], '_', sanitized)
        sanitized = re.sub(r'[_]+', '_', sanitized) 
        sanitized = sanitized.upper()
        
    return sanitized

def get_user_input(prompt, validator_func, messages, allow_empty=False, default_value=None):
    """Pide una entrada al usuario y la valida, o usa un valor por defecto (interactivo)."""
    
    prompt_display = f"{prompt} [{default_value}] " if default_value is not None else prompt
    
    while True:
        try:
            user_input = input(prompt_display).strip()
            
            if not user_input and default_value is not None:
                user_input = default_value

            if allow_empty and not user_input:
                return user_input
            
            value_to_validate = user_input.upper() if validator_func is validate_yes_no else user_input

            if validator_func(value_to_validate):
                return value_to_validate if validator_func is validate_yes_no else user_input
            else:
                print(messages['WARN_INPUT_INVALID'])
        except KeyboardInterrupt:
            print(messages['INFO_OPERATION_CANCELED'])
            return None
        except Exception as e:
            print(f"Ocurrio un error inesperado: {e}")
            return None

def get_user_input_update(prompt, current_value, messages, validator_func=None, allow_empty=True, update_prompt=None):
    """
    Pide una entrada al usuario en modo 'update' forzado, con validacion S/N robusta.
    """
    
    print(f"\n> Valor actual: **{current_value}**")
    update_prompt = update_prompt or messages['PROMPT_UPDATE']

    # 1. Preguntar si desea actualizar
    while True:
        try:
            update_choice = input(f"{update_prompt} [S] ").strip().upper() or 'S'
            
            if update_choice == 'N': return current_value
            elif update_choice == 'S': break
            else: print(messages['WARN_UPDATE_RESPONSE'])
        except KeyboardInterrupt:
            print(messages['INFO_OPERATION_CANCELED'])
            return None

    # 2. Pedir el nuevo valor
    prompt_display = f"{prompt} [{current_value}] " if current_value is not None else prompt

    while True:
        try:
            user_input = input(prompt_display).strip()
            
            if not user_input and current_value is not None:
                user_input = current_value

            is_yes_no_field = (validator_func is validate_yes_no)
            
            value_to_validate = user_input.upper() if is_yes_no_field else user_input

            if allow_empty and not user_input:
                return user_input 
                
            if validator_func is None or validator_func(value_to_validate):
                return value_to_validate if is_yes_no_field else user_input
            else:
                print(messages['WARN_INPUT_INVALID'])

        except KeyboardInterrupt:
            print(messages['INFO_OPERATION_CANCELED'])
            return None
        except Exception as e:
            print(f"Ocurrio un error inesperado: {e}")
            return None
# ===============================================
# FUNCIONES DE ENTRADA (Input Orchestration)
# ===============================================

def _get_bug_details(config, messages, update_func, opcion_bug_previo):
    """
    P1: Obtiene y sanitiza el número de BUG/TICKET, verificando prefijos multiples.
    """
    
    prefijos = config['PREFIJOS_PERMITIDOS']
    default_prefix = config['PREFIJO_BUG_DEFAULT']

    def validate_bug(bug_input):
        sanitized_bug = sanitize_input(bug_input, config, is_project_key=False).upper()
        # Validación mínima: Debe contener alfanuméricos
        return any(c.isalnum() for c in sanitized_bug)
    
    # Construir el prompt con los prefijos
    prefijos_display = ", ".join(prefijos)
    prompt = messages['P1_PROMPT_INPUT'].format(PREFIJO_1=prefijos[0], PREFIJO_2=prefijos[1]) 
    update_prompt_msg = messages['P1_PROMPT_UPDATE'].format(BUG_VAL=opcion_bug_previo)
    
    # --- Lógica de Input según el modo ---
    if update_func == get_user_input_update:
        bug_num_input = update_func(
            prompt, opcion_bug_previo, messages, validate_bug, update_prompt=update_prompt_msg
        )
    else:
        bug_num_input = update_func(
            prompt, validate_bug, messages, allow_empty=False, default_value=opcion_bug_previo
        )

    if bug_num_input is None: return None, None
    
    bug_num_clean = sanitize_input(bug_num_input, config, is_project_key=False).upper()
    
    # 1. Verificar si el input ya tiene un prefijo permitido
    prefijo_encontrado = None
    for prefix in prefijos:
        if bug_num_clean.startswith(prefix):
            prefijo_encontrado = prefix
            break
            
    # 2. Si no tiene un prefijo permitido, forzar el prefijo por defecto
    if prefijo_encontrado is None:
        print(messages['P1_WARN_PREFIX'].format(PREFIJOS=prefijos_display))
        print(messages['P1_INFO_FORCE_PREFIX'].format(PREFIJO_USADO=default_prefix))
        
        bug_num_clean_sin_prefijo = bug_num_clean
        for prefix in prefijos:
            if bug_num_clean.startswith(prefix.rstrip('-')):
                bug_num_clean_sin_prefijo = bug_num_clean.lstrip(prefix.rstrip('-'))
                break
        
        bug_num_clean = f"{default_prefix}{bug_num_clean_sin_prefijo.lstrip('-')}"
        
        # Volver a sanitizar el ticket completo (BUG-NOBUG-13234)
        bug_num_sanitized = sanitize_input(bug_num_clean, config, is_project_key=True)
    else:
        # Ya tiene un prefijo valido, solo sanitizar por si hay caracteres invalidos en el ID
        bug_num_sanitized = sanitize_input(bug_num_clean, config, is_project_key=True)
        
    return bug_num_sanitized, bug_num_sanitized

def _get_language_details(config, messages, update_func, es_modo_update, opcion_lang_previo):
    """P2: Obtiene el lenguaje y la lógica asociada."""
    
    opciones = config['OPCIONES_LENGUAJE']
    def validate_lang_option(option_input):
        return option_input in opciones or option_input in opciones.values()
    
    def resolve_language_name(input_val):
        if input_val.isdigit() and input_val in opciones:
            return opciones[input_val]
        if input_val in opciones.values():
            return input_val
        return input_val 

    print(messages['P2_HEADER'])
    for key, value in sorted(opciones.items(), key=lambda item: int(item[0]) if item[0].isdigit() else float('inf')):
        print(f"    ({key}) {value}")

    if es_modo_update:
        opcion_elegida = update_func(
            messages['P2_PROMPT_NEW'], opcion_lang_previo, messages, validate_lang_option, 
            update_prompt=messages['P2_PROMPT_UPDATE'].format(LANG_VAL=opcion_lang_previo)
        )
    
    else:
        opcion_elegida = update_func(
            messages['P2_PROMPT_INPUT'], validate_lang_option, messages, default_value=opcion_lang_previo
        )
    
    if opcion_elegida is None: return None, None
    
    lenguaje_seleccionado = resolve_language_name(opcion_elegida)
    
    logica_lenguaje = config['LOGICA_LENGUAJES'].get(lenguaje_seleccionado, config['LOGICA_LENGUAJES']['OTROS'])
    return lenguaje_seleccionado, logica_lenguaje

def _get_title_details(config, messages, update_func, opcion_titulo_previo):
    """P3: Obtiene el título del proyecto y sus formatos sanitizados."""
    
    # El validador (lambda x: len(x) > 0) es el mismo para ambos modos
    validator = lambda x: len(x) > 0

    if update_func == get_user_input_update:
        titulo_input_raw = update_func(
            messages['P3_PROMPT_NEW'], opcion_titulo_previo, messages, 
            validator_func=validator, allow_empty=False,
            update_prompt=messages['P3_PROMPT_UPDATE'].format(TITLE_VAL=opcion_titulo_previo)
        )
    else:
        titulo_input_raw = update_func(
            messages['P3_PROMPT_INPUT'], 
            validator_func=validator, 
            messages=messages, allow_empty=False,
            default_value=(opcion_titulo_previo or config['TITULO_DEFECTO'])
        )
    
    if titulo_input_raw is None: return None, None

    if not titulo_input_raw:
        titulo_input_raw = config['TITULO_DEFECTO']

    # Aplicar la sanitización estricta para Project Name (v1.0.7)
    titulo_input_sanitized_display = sanitize_display_name(titulo_input_raw)
    
    # Aplicar la sanitización estricta para Project Key (a mayúsculas y guiones bajos)
    titulo_formateado_key = sanitize_input(titulo_input_sanitized_display, config, is_project_key=True)
    
    if not titulo_formateado_key:
        titulo_formateado_key = config['TITULO_DEFECTO']

    return titulo_input_sanitized_display.strip(), titulo_formateado_key

def _get_branch_details(config, messages, update_func, opciones_previas, logica_lenguaje, titulo_formateado_key):
    """P4: Obtiene la rama y las variables de Bitbucket."""
    
    opcion_rama_check_previo = opciones_previas.get('USA_RAMA', 'N') if opciones_previas else 'N'
    opcion_rama_nombre_previo = opciones_previas.get('RAMA_NOMBRE', '') if opciones_previas else ''
    opcion_es_master_previo = opciones_previas.get('ES_MASTER', 'N') if opciones_previas else 'N'
    
    rama_base_key = config['RAMA_DEFECTO_SIN_BB']
    rama_full_url = "" 
    rama_display_name = "" 
    
    rama_check = 'N'
    es_rama_master = 'N'
    
    if logica_lenguaje['APLICA_RAMA']:
        # P4.1: ¿Usar Rama?
        if update_func == get_user_input_update:
            rama_check = update_func(
                messages['P4_PROMPT_CHECK'], opcion_rama_check_previo, messages, validate_yes_no,
                update_prompt=messages['P4_PROMPT_UPDATE'].format(RAMA_VAL=opcion_rama_check_previo)
            )
        else:
            rama_check = update_func(
                messages['P4_PROMPT_CHECK'], validate_yes_no, messages, default_value=opcion_rama_check_previo
            )
        
        if rama_check is None: return None
        
        if rama_check == "S":
            # P4.2: Nombre de la Rama
            validator_name = lambda x: len(x)>0
            if update_func == get_user_input_update:
                 rama_display_name = update_func(
                    messages['P4_PROMPT_RAMA_NAME'], opcion_rama_nombre_previo, messages, 
                    validator_func=validator_name, allow_empty=False,
                    update_prompt=messages['P4_PROMPT_RAMA_NAME_UPDATE'].format(RAMA_NAME=opcion_rama_nombre_previo)
                )
            else:
                rama_display_name = update_func(
                    messages['P4_PROMPT_RAMA_NAME'], 
                    validator_func=validator_name, 
                    messages=messages, allow_empty=False,
                    default_value=opcion_rama_nombre_previo
                )
            
            if rama_display_name is None: return None

            # P4.3: ¿Es Master?
            if update_func == get_user_input_update:
                es_rama_master = update_func(
                    messages['P4_PROMPT_MASTER'].format(MASTER_VAL=config['RAMA_MASTER_DEFAULT']), opcion_es_master_previo, messages, validate_yes_no,
                    update_prompt=messages['P4_PROMPT_MASTER_UPDATE'].format(MASTER_VAL=opcion_es_master_previo)
                )
            else:
                es_rama_master = update_func(
                    messages['P4_PROMPT_MASTER'].format(MASTER_VAL=config['RAMA_MASTER_DEFAULT']), validate_yes_no, messages, default_value=opcion_es_master_previo
                )

            if es_rama_master is None: return None
            
            # Lógica de Key de Rama
            if es_rama_master == "S":
                rama_base_key = config['RAMA_MASTER_DEFAULT']
            else:
                # La rama se sanitiza para el Project Key
                rama_input_sanitized = sanitize_input(rama_display_name, config, is_project_key=True)
                rama_base_key = rama_input_sanitized if rama_input_sanitized else config['RAMA_DEFECTO_SIN_BB']
            
            # Construcción de URL
            if rama_display_name:
                # Limpiar slashes iniciales o finales del nombre de la rama para la URL
                rama_url_clean = rama_display_name.strip('/') 
                
                repo_name = titulo_formateado_key.split('_')[0] if '_' in titulo_formateado_key else 'REPOSITORIO_NOMBRE_AQUI'
                # Usar rama_url_clean en la URL
                rama_full_url = f"{config['PREFIJO_BB_URL']}{repo_name}/branch/{rama_url_clean}"
            
        else:
            print(messages['P4_INFO_NO_BB'])

    rama_formateada = rama_base_key.upper()
    
    return {
        'USA_RAMA': rama_check, 
        'RAMA_NOMBRE': rama_display_name, 
        'ES_MASTER': es_rama_master, 
        'RAMA_KEY': rama_formateada,
        'RAMA_URL': rama_full_url
    }

def _get_include_flags(config, messages, update_func, opciones_previas, bug_num_sanitized, titulo_input_sanitized_display):
    """P5 & P6: Obtiene las opciones de incluir BUG y FECHA."""
    
    # P5: Incluir BUG en Project Name
    opcion_bug_in_name_previo = opciones_previas.get('INCLUIR_BUG_IN_NAME', 'S') if opciones_previas else 'S'
    
    # Aplicar la lógica de Project Name usando la nueva sanitización estricta para la previsualización
    project_name_preview = titulo_input_sanitized_display.strip()
    if opcion_bug_in_name_previo == 'S':
        project_name_preview = f"{bug_num_sanitized} - {project_name_preview}"

    prompt_p5 = messages['P5_PROMPT'].format(BUG_VAL=bug_num_sanitized)
    update_prompt_p5 = messages['P5_PROMPT_UPDATE'].format(PROJECT_NAME=project_name_preview)
    
    if update_func == get_user_input_update:
        # Update Mode 
        incluir_bug_in_name_input = update_func(
            prompt_p5, 
            opcion_bug_in_name_previo, 
            messages, 
            validate_yes_no,
            update_prompt=update_prompt_p5
        )
    else:
        # Normal Mode 
         incluir_bug_in_name_input = update_func(
            prompt_p5, 
            validate_yes_no, 
            messages, 
            default_value=opcion_bug_in_name_previo
        )

    if incluir_bug_in_name_input is None: return None

    # P6: Incluir Fecha
    opcion_fecha_previo = opciones_previas.get('INCLUIR_FECHA', 'N') if opciones_previas else 'N'
    prompt_p6 = messages['P6_PROMPT']
    update_prompt_p6 = messages['P6_PROMPT_UPDATE'].format(FECHA_VAL=opcion_fecha_previo)

    if update_func == get_user_input_update:
        # Update Mode
        incluir_fecha_input = update_func(
            prompt_p6, 
            opcion_fecha_previo, 
            messages, 
            validate_yes_no,
            update_prompt=update_prompt_p6
        )
    else:
        # Normal Mode
        incluir_fecha_input = update_func(
            prompt_p6, 
            validate_yes_no, 
            messages, 
            default_value=opcion_fecha_previo
        )

    if incluir_fecha_input is None: return None

    return {
        'INCLUIR_BUG_IN_NAME': incluir_bug_in_name_input, 
        'INCLUIR_FECHA': incluir_fecha_input
    }

# ===============================================
# FUNCIONES DE SALIDA (Output Orchestration)
# ===============================================

def _build_and_display_keys(config, datos_finales, messages):
    """
    Construye la Project Key final y el Project Name.
    Muestra los resultados en el encabezado.
    """
    
    bug_num_sanitized = datos_finales['BUG_NUM']
    titulo_formateado_key = datos_finales['TITULO_KEY']
    titulo_input_sanitized_display = datos_finales['TITULO'] # Ya está estrictamente sanitizado (v1.0.7)
    rama_formateada = datos_finales['RAMA_KEY']
    incluir_fecha_input = datos_finales['INCLUIR_FECHA']
    incluir_bug_in_name_input = datos_finales['INCLUIR_BUG_IN_NAME']
    logica_lenguaje = datos_finales['LOGICA_LENGUAJE']

    fecha_str = ""
    if incluir_fecha_input == "S":
        fecha_str = f"_{datetime.now().strftime(config['FORMATO_FECHA'])}"

    # --- Logica de Construccion del Nombre (sonar.projectKey) ---
    bug_componente = f"{bug_num_sanitized}_{titulo_formateado_key}"
    
    if logica_lenguaje['INDICADOR'] == "RPG":
        nombre_final_key = f"RPG_{bug_componente}{fecha_str}"
    elif rama_formateada == config['RAMA_DEFECTO_SIN_BB']:
        nombre_final_key = f"{bug_componente}{fecha_str}"
    else:
        nombre_final_key = f"{rama_formateada}_{bug_componente}{fecha_str}"

    # --- Logica de sonar.projectName (Aplica P5) ---
    project_name_final = titulo_input_sanitized_display.strip()
    
    if incluir_bug_in_name_input == "S":
        # Usamos bug_num_sanitized (la versión del Project Key, que es segura)
        if not project_name_final.upper().startswith(bug_num_sanitized):
            project_name_final = f"{bug_num_sanitized} - {project_name_final}"

    # Muestra los resultados clave
    print(messages['OUTPUT_HEADER'])
    print(messages['OUTPUT_PROJECT_KEY'].format(KEY=nombre_final_key))
    print(messages['OUTPUT_PROJECT_NAME'].format(NAME=project_name_final))
    print("="*80)
    
    return nombre_final_key, project_name_final

def mostrar_comandos_finales(project_key, project_name_formatted, logica_lenguaje, os_seleccionado, bug_num_sanitized, rama_full_url, messages):
    """Muestra la linea de comando adecuada segun la tecnologia y el OS."""
    
    project_description = f"{project_name_formatted}" if not rama_full_url else f"{bug_num_sanitized} {rama_full_url}"
        
    scanner_cli_base = "sonar-scanner"
    if os_seleccionado == "WINDOWS":
        scanner_cli = f"{scanner_cli_base}.bat" 
        line_continuation = " ^\n  " 
    else:
        scanner_cli = scanner_cli_base
        line_continuation = " \\\n  "
        
    params_base = (
        f'-D"sonar.projectKey={project_key}" '
        f'-D"sonar.projectName={project_name_formatted}" '
        f'-D"sonar.projectDescription={project_description}"'
    )
    
    propiedad_extra = logica_lenguaje.get('COMANDO_PROPIEDAD', '')
    if propiedad_extra:
        params_base += f' {propiedad_extra}'
        
    indicador_nomenclatura = logica_lenguaje.get('INDICADOR', 'GENERAL')
    tipo_scanner = logica_lenguaje.get('TIPO_SCANNER', 'SONAR_SCANNER')

    comando_final = ""
    instruccion_extra = ""
    
    # --- Logica de Comandos por Tipo de Scanner (usando las claves corregidas) ---
    if tipo_scanner == "MAVEN":
        comando_final = (f"mvn clean verify sonar:sonar{line_continuation}-Dsonar.projectKey={project_key}{line_continuation}-Dsonar.projectName='{project_name_formatted}'{line_continuation}-Dsonar.projectDescription='{project_description}'{line_continuation}{propiedad_extra.replace(' ', line_continuation) if propiedad_extra else ''}").strip()
        instruccion_extra = messages['OUTPUT_CMD_ATTENTION_MAVEN']
    elif tipo_scanner == "GRADLE":
        comando_final = (f"./gradlew sonarqube -Dsonar.projectKey={project_key} -Dsonar.projectName='{project_name_formatted}' -Dsonar.projectDescription='{project_description}' {propiedad_extra}").strip()
        instruccion_extra = messages['OUTPUT_CMD_ATTENTION_GRADLE']
    elif tipo_scanner == "DOTNET":
        instruccion_extra = messages['OUTPUT_CMD_ATTENTION_DOTNET']
        comando_begin = (f"dotnet sonarscanner begin /k:\"{project_key}\" /n:\"{project_name_formatted}\" /d:sonar.projectDescription=\"{project_description}\" {propiedad_extra}").strip()
        comando_build = "dotnet build"
        comando_end = "dotnet sonarscanner end"
        comando_final = f"{comando_begin}\n{comando_build}\n{comando_end}"
    elif tipo_scanner == "SONAR_SCANNER":
        comando_final = (f'{scanner_cli} -D"sonar.sources=." {params_base} -X').strip()
        if indicador_nomenclatura == "RPG":
            instruccion_extra = messages['OUTPUT_CMD_ATTENTION_RPG']
        elif indicador_nomenclatura == "JAVA" and 'binaries' in propiedad_extra:
             instruccion_extra = messages['OUTPUT_CMD_ATTENTION_JAVA']
        elif indicador_nomenclatura == "CPP":
            instruccion_extra = messages['OUTPUT_CMD_ATTENTION_CPP']
        else:
            instruccion_extra = messages['OUTPUT_CMD_ATTENTION_DEFAULT']

    print(messages['OUTPUT_CMD_HEADER'].format(OS=os_seleccionado, LANG=indicador_nomenclatura))
    print(f"> {instruccion_extra}")
    print("```bash")
    print(comando_final)
    print("```")

def _display_disclaimer_and_save(config, datos_finales, project_key, messages, es_modo_update):
    """Muestra el disclaimer de Licencia/VPN y maneja el guardado de opciones."""

    # --- 4. Mensaje de Licencia y VPN (usando todas las claves) ---
    print(messages['DISCLAIMER_HEADER'])
    print("-" * 80)
    print(messages['DISCLAIMER_VPN_TITLE'])
    print(messages['DISCLAIMER_VPN_TEXT'])
    print(messages['DISCLAIMER_LICENSE_TITLE'])
    print(messages['DISCLAIMER_LICENSE_TEXT_1'])
    print(messages['DISCLAIMER_LICENSE_TEXT_2'])
    print(messages['DISCLAIMER_LICENSE_TEXT_3'].format(MASTER_VAL=config['RAMA_MASTER_DEFAULT']))
    print(messages['DISCLAIMER_LICENSE_TEXT_4'])
    print(messages['DISCLAIMER_LICENSE_TEXT_5'])
    print(messages['DISCLAIMER_KEY_GENERATED'].format(KEY=project_key))
    print(messages['DISCLAIMER_FOOTER'])
    
    # --- 5. Guardar Opciones ---
    bug_num_sanitized = datos_finales['BUG_NUM']
    
    if es_modo_update:
        guardar_opciones(bug_num_sanitized, datos_finales, config, messages, is_update=True)
    else:
        # Usa input en modo normal, dentro de try/except por si el usuario presiona Ctrl+C aquí
        try:
            guardar_input = input(messages['SAVE_PROMPT_NEW']).strip().upper()
            if guardar_input == "S":
                guardar_opciones(bug_num_sanitized, datos_finales, config, messages, is_update=False)
        except KeyboardInterrupt:
            print(messages['INFO_OPERATION_CANCELED'])
            return

# ===============================================
# LOGICA PRINCIPAL DEL SCRIPT
# ===============================================

def generar_nombre_ticket_sonarqube(config, messages, opciones_previas=None):
    """
    Orquesta la recolección de datos, la generación de nombres y la salida.
    """
    # Se imprime la versión al inicio
    print(messages['HEADER'].format(VERSION=config['VERSION']))

    opciones_finales = {}
    es_modo_update = opciones_previas is not None
    update_func = get_user_input_update if es_modo_update else get_user_input

    if es_modo_update:
        print(messages['MODE_UPDATE_WARNING'])

    # 1. TICKET/BUG (P1)
    bug_num_sanitized, _ = _get_bug_details(config, messages, update_func, opciones_previas.get('BUG_NUM') if opciones_previas else None)
    if bug_num_sanitized is None: return

    opciones_finales['BUG_NUM'] = bug_num_sanitized

    # 2. LENGUAJE (P2)
    lenguaje_seleccionado, logica_lenguaje = _get_language_details(
        config, messages, update_func, es_modo_update, opciones_previas.get('LENGUAJE_OPCION') if opciones_previas else None
    )
    if lenguaje_seleccionado is None: return
    opciones_finales['LENGUAJE_OPCION'] = lenguaje_seleccionado
    opciones_finales['LOGICA_LENGUAJE'] = logica_lenguaje

    # 3. TITULO (P3)
    titulo_input_sanitized_display, titulo_formateado_key = _get_title_details(
        config, messages, update_func, opciones_previas.get('TITULO') if opciones_previas else None
    )
    if titulo_input_sanitized_display is None: return
    opciones_finales['TITULO'] = titulo_input_sanitized_display
    opciones_finales['TITULO_KEY'] = titulo_formateado_key

    # 4. RAMA (P4)
    rama_data = _get_branch_details(
        config, messages, update_func, opciones_previas or {}, logica_lenguaje, titulo_formateado_key
    )
    if rama_data is None: return
    opciones_finales.update(rama_data)

    # 5. INCLUIR FLAGS (P5, P6)
    flag_data = _get_include_flags(
        config, messages, update_func, opciones_previas or {}, bug_num_sanitized, titulo_input_sanitized_display
    )
    if flag_data is None: return
    opciones_finales.update(flag_data)

    # 6. GENERACIÓN DE KEYS Y OUTPUT
    project_key, project_name_final = _build_and_display_keys(config, opciones_finales, messages)

    # 7. COMANDOS
    # Se usa "WINDOWS" y "LINUX/MAC" para forzar la muestra de ambos comandos.
    mostrar_comandos_finales(
        project_key, project_name_final, logica_lenguaje, "WINDOWS", bug_num_sanitized, 
        opciones_finales.get('RAMA_URL', ''), messages
    )
    print("\n" + "-"*80)
    mostrar_comandos_finales(
        project_key, project_name_final, logica_lenguaje, "LINUX/MAC", bug_num_sanitized, 
        opciones_finales.get('RAMA_URL', ''), messages
    )
    print("\n" + "="*80)

    # 8. DISCLAIMER Y GUARDADO
    _display_disclaimer_and_save(config, opciones_finales, project_key, messages, es_modo_update)


if __name__ == "__main__":
    # --- Manejo de Argumentos ---
    parser = argparse.ArgumentParser(description="Generador de comandos de analisis de SonarQube con soporte para carga y guardado de opciones.")
    parser.add_argument("-i", "--input", type=str, help="Ruta al archivo .txt con las opciones guardadas (ej: opciones_1234.txt).")
    args = parser.parse_args()

    opciones_cargadas = None
    if args.input:
        opciones_cargadas = cargar_opciones(args.input, MESSAGES)
        if opciones_cargadas is None:
            sys.exit(1)
            
    generar_nombre_ticket_sonarqube(CONFIG, MESSAGES, opciones_cargadas)