"""
Analizador de Código RPG/CL/PF
Versión: 4.2.0 - SCRIPT COMPLETO FINAL
Descripción:
Script completo con todas las funcionalidades integradas:
- Análisis recursivo de carpetas y subcarpetas
- Extracción automática de archivos ZIP
- Detección robusta de formatos CL/PF/RPG
- Manejo de errores y archivos binarios
- Generación de reportes detallados
- Hash SHA-256 completo sin truncar
- Información completa de líneas y metadatos

Modo de uso:
python3 IBM_Analyzer_v4.2.0_FINAL.py -a <archivo>
python3 IBM_Analyzer_v4.2.0_FINAL.py -f <carpeta>
python3 IBM_Analyzer_v4.2.0_FINAL.py -f <carpeta> --no-zip
"""

import re
import argparse
import os
import hashlib
from datetime import datetime
from collections import Counter
import time
import zipfile

# Validador automático de chardet (para el error 0xf3)
try:
    import chardet
    CHARDET_DISPONIBLE = True
except ImportError:
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "chardet"])
        import chardet
        CHARDET_DISPONIBLE = True
    except:
        CHARDET_DISPONIBLE = False
# ======================================================================
#                            CONFIGURACIÓN
# ======================================================================
PREFIJO_SALIDA = 'analisis'
FORMATO_NOMBRE_SALIDA = '{prefijo}_{tipo_archivo}_{tipo_analisis}_{tipo_reporte}_{nombre_archivo}_{fecha}'

# Extensiones de archivos que NO deben ser analizados
EXTENSIONES_EXCLUIDAS = {'.zip', '.rar', '.7z', '.tar', '.gz', '.exe', '.dll', '.bin', '.pdf', '.docx', '.xlsx', '.jpg', '.png', '.gif', '.mp4', '.avi'}
TAMANO_MAXIMO = 20 * 1024 * 1024  # 20MB máximo

# ======================================================================
#                    DICCIONARIOS DE COMANDOS Y CAMPOS - COMPLETOS
# ======================================================================

# Comandos CL - COMPLETO
descripciones_comandos_cl = {
    'PGM': 'Inicia un programa. (Program)',
    'DCLF': 'Declara un archivo externo para su uso en el programa.',
    'RCVF': 'Recibe datos desde un archivo (Receive File).',
    'CLRPFM': 'Borra todos los registros de un miembro físico de archivo (Clear Physical File Member).',
    'RTVJOBA': 'Recupera información del trabajo actual (Retrieve Job Attributes).',
    'CHGVAR': 'Cambia el valor de una variable. (Change Variable)',
    'CALL': 'Llama a otro programa.',
    'CHKOBJ': 'Verifica la existencia y tipo de un objeto (Check Object).',
    'MONMSG': 'Monitorea mensajes de error específicos y ejecuta una acción si son capturados (Monitor Message).',
    'CPYF': 'Copia registros de un archivo a otro. (Copy File)',
    'SNDPGMMSG': 'Envía un mensaje a la cola del programa o del trabajo (Send Program Message).',
    'OVRDBF': 'Sobrescribe un archivo de base de datos (Override with Database File).',
    'DLTF': 'Borra un archivo de base de datos (Delete File).',
    'CRTPF': 'Crea un archivo físico (Create Physical File).',
    'CRTLF': 'Crea un archivo lógico (Create Logical File).',
    'ENDPGM': 'Finaliza un programa. (End Program)',
    'SBMJOB': 'Envía un trabajo para su ejecución en segundo plano (Submit Job).',
    'RCVMSG': 'Recibe un mensaje de la cola de mensajes del programa o del trabajo (Receive Message).',
    'RETURN': 'Finaliza el programa o procedimiento actual y devuelve el control al punto donde se inició dicha secuencia.',
    'IF': 'Inicia una estructura de control condicional. (If)',
    'ELSE': 'Inicia un bloque de control alternativo. (Else)',
    'DO': 'Inicia un bucle de control. (Do)',
    'ENDDO': 'Finaliza un bucle o bloque de control. (End Do)',
    'GOTO': 'Transfiere el control a una etiqueta de programa. (Go To)'
}

# Comandos y elementos PF - COMPLETO RESTAURADO
descripciones_comandos_pf = {
    'UNIQUE': 'Define que el archivo físico tiene claves únicas.',
    'REF': 'Define una referencia a un archivo de referencia de campos.',
    'PFILE': 'Define el archivo físico base para un archivo lógico.',
    'JFILE': 'Define archivos para operaciones de join.',
    'FORMAT': 'Define el nombre del formato de registro.',
    'TEXT DESCRIPCION': 'Proporciona una descripción textual del archivo o campo.',
    'COLHDG': 'Define encabezados de columna para campos.',
    'EDTCDE': 'Define códigos de edición para campos.',
    'EDTWRD': 'Define palabras de edición para campos.',
    'DFT': 'Define valores por defecto para campos.',
    'VALUES': 'Define valores válidos para campos.',
    'RANGE': 'Define rangos válidos para campos.',
    'COMP': 'Define comparaciones para campos.',
    'DSPPGM': 'Define programas de visualización.',
    'CHKMSGID': 'Define mensajes de verificación.',
    'CHOICE': 'Define opciones de selección para campos.',
    'ALIAS': 'Define nombres alternativos para campos.',
    'MBR': 'Define el nombre del miembro del archivo físico.',
    'LIB': 'Especifica la biblioteca donde se encuentra el archivo físico.',
    'KEY': 'Define las claves (índices) en el archivo físico.',
    'EXTEND': 'Permite la adición de registros cuando no hay más espacio al final del archivo.',
    'SIZE': 'Establece el tamaño del archivo físico.',
    'REPLACE': 'Indica que si un archivo con el mismo nombre ya existe, debe ser reemplazado sin aviso.',
    'ALWSAV': 'Permite guardar el archivo en una savefile.',
    'USRPRF': 'Especifica el perfil de usuario para la propiedad del archivo físico.',
    'SHRDLT': 'Controla si el archivo puede ser compartido o no.',
    'TFRSPLF': 'Transfiere registros de impresión al archivo especificado.',
    'MGTCLS': 'Gestiona objetos de clase en el archivo.',
    'DTAARA': 'Almacena datos de área dentro del archivo físico.',
    'DDM': 'Define atributos de Distributed Data Management (DDM) para el archivo.',
    'I/O ACCESS': 'Especifica los modos de acceso de entrada y salida del archivo.',
    'OVERFLOW': 'Permite la creación de un archivo de flujo lateral cuando el archivo primario está lleno.',
    'LOCK': 'Establece detalles de bloqueo como tipo, duración y bandeja de mensajes para el archivo.',
    'DTAFMT': 'Especifica una tabla de formato de datos a ser utilizada por la base de datos.',
    'DLMREC': 'Define registros de delimitador en archivos de flujo.',
}

# Comandos y elementos RPG - COMPLETO CON COMANDOS AÑADIDOS
descripciones_comandos_rpg = {
    'H': 'Especificación de control (Header)',
    'F': 'Especificación de archivo (File)',
    'D': 'Especificación de definición (Definition)',
    'I': 'Especificación de entrada (Input)',
    'C': 'Especificación de cálculo (Calculation)',
    'O': 'Especificación de salida (Output)',
    'P': 'Especificación de procedimiento (Procedure)',
    'PR': 'Prototipo de procedimiento (Procedure Prototype)',
    'PI': 'Interfaz de procedimiento (Procedure Interface)',
    'DS': 'Estructura de datos (Data Structure)',
    'EVAL': 'Evalúa una expresión y asigna el resultado',
    'IF': 'Inicia una estructura condicional',
    'ELSE': 'Alternativa en estructura condicional',
    'ENDIF': 'Finaliza estructura condicional',
    'DOW': 'Bucle mientras (Do While)',
    'DOU': 'Bucle hasta (Do Until)',
    'ENDDO': 'Finaliza bucle',
    'FOR': 'Bucle con contador',
    'ENDFOR': 'Finaliza bucle FOR',
    'SELECT': 'Inicia estructura de selección múltiple',
    'WHEN': 'Condición en estructura SELECT',
    'OTHER': 'Caso por defecto en SELECT (alternativa cuando ninguna condición se cumple)',
    'ENDSL': 'Finaliza estructura SELECT',
    'CHAIN': 'Lee un registro por clave',
    'READ': 'Lee el siguiente registro',
    'WRITE': 'Escribe un registro',
    'UPDATE': 'Actualiza un registro',
    'DELETE': 'Elimina un registro',
    'OPEN': 'Abre un archivo',
    'CLOSE': 'Cierra un archivo',
    'MONITOR': 'Inicia bloque de monitoreo de errores y excepciones',
    'ON-ERROR': 'Maneja errores específicos',
    'ENDMON': 'Finaliza bloque de monitoreo',
    'CLEAR': 'Limpia o inicializa variables asignando valores nulos',
    'EXSR': 'Ejecuta una subrutina (Execute Subroutine)',
    'RETURN': 'Finaliza el programa o procedimiento actual y devuelve el control',
    'DUMP': 'Genera volcado de memoria para depuración',
    '%SUBST': 'Función para extraer subcadenas de una cadena',
    '%SIZE': 'Función que devuelve el tamaño de una variable o campo'
}

# Tipos de datos PF - COMPLETO
tipos_datos_pf = {
    'A': 'Campo de caracteres (Character)',
    'P': 'Campo empaquetado (Packed decimal)',
    'S': 'Campo con signo zoneado (Zoned decimal)',
    'B': 'Campo binario (Binary)',
    'F': 'Campo de punto flotante (Float)',
    'L': 'Campo de fecha (Date)',
    'T': 'Campo de tiempo (Time)',
    'Z': 'Campo de timestamp (Timestamp)',
    'G': 'Campo gráfico (Graphic)',
    'H': 'Campo hexadecimal (Hexadecimal)',
    'O': 'Campo de caracteres de solo salida (Output-only character)'
}
# ======================================================================
# 0. VALIDADOR DE DEPENDENCIAS (NUEVO)
# ======================================================================
def verificar_e_instalar_dependencias():
    """Asegura que chardet esté presente para evitar fallos de ejecución."""
    try:
        import chardet
        return True
    except ImportError:
        print("⚠️  Librería 'chardet' no detectada. Intentando instalación automática...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "chardet"])
            import chardet
            print("✅ Instalación exitosa.")
            return True
        except Exception as e:
            print(f"❌ Error instalando dependencia: {e}. El script podría fallar con archivos no UTF-8.")
            return False

CHARDET_DISPONIBLE = verificar_e_instalar_dependencias()
if CHARDET_DISPONIBLE:
    import chardet
    
# ======================================================================
#                        FUNCIONES AUXILIARES
# ======================================================================

def detectar_encoding(ruta_archivo):
    if not CHARDET_DISPONIBLE:
        return 'latin-1', 0.0 
    
    try:
        with open(ruta_archivo, 'rb') as f:
            raw_data = f.read(50000)
            if not raw_data:
                return 'utf-8', 0.0
            result = chardet.detect(raw_data)
            enc = result.get('encoding')
            
            # Si chardet duda o el archivo tiene bytes como 0xf3, 
            # forzamos latin-1 en lugar de dejar que explote en utf-8
            if not enc or result.get('confidence', 0) < 0.7:
                return 'latin-1', 0.5
            return enc, result.get('confidence', 0.0)
    except Exception:
        return 'latin-1', 0.0

def formatear_tamano(bytes_size):
    """Formatea el tamaño en bytes a una representación legible."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_size < 1024.0:
            return f"{bytes_size:.1f} {unit}"
        bytes_size /= 1024.0
    return f"{bytes_size:.1f} PB"

def obtener_hash_archivo(ruta_archivo):
    """Calcula el hash SHA-256 completo de un archivo."""
    sha256_hash = hashlib.sha256()
    try:
        with open(ruta_archivo, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except FileNotFoundError:
        return "No disponible"

def contar_lineas_archivo(ruta_archivo, encoding=None):
    try:
        lineas, enc_real = leer_archivo_robusto(ruta_archivo)
        total = len(lineas)
        vacias = sum(1 for l in lineas if not l.strip())
        comentarios = sum(1 for l in lineas if l.strip().startswith(('*', '//')))
        return {
            'total': total,
            'vacias': vacias,
            'con_contenido': total - vacias,
            'comentarios': comentarios,
            'encoding_real': enc_real
        }
    except:
        return {'total': 0, 'vacias': 0, 'con_contenido': 0, 'comentarios': 0, 'encoding_real': 'error'}

def obtener_info_archivo_basica(ruta_archivo):
    """Obtiene información básica del archivo para archivos DESCONOCIDO."""
    try:
        stat_info = os.stat(ruta_archivo)
        encoding, confidence = detectar_encoding(ruta_archivo)
        info_lineas = contar_lineas_archivo(ruta_archivo, encoding)
        
        info = {
            'nombre': os.path.basename(ruta_archivo),
            'ruta_completa': os.path.abspath(ruta_archivo),
            'extension': os.path.splitext(ruta_archivo)[1] or 'sin extensión',
            'tamano_bytes': stat_info.st_size,
            'tamano_legible': formatear_tamano(stat_info.st_size),
            'fecha_creacion': datetime.fromtimestamp(stat_info.st_ctime).strftime('%Y-%m-%d %H:%M:%S'),
            'fecha_modificacion': datetime.fromtimestamp(stat_info.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
            'encoding_detectado': encoding,
            'confianza_encoding': confidence * 100,
            'hash_sha256': obtener_hash_archivo(ruta_archivo),
            'info_lineas': info_lineas
        }
        
        return info
    
    except Exception as e:
        return {
            'error': f"No se pudo obtener información del archivo: {e}",
            'nombre': os.path.basename(ruta_archivo),
            'ruta_completa': os.path.abspath(ruta_archivo),
        }

def es_archivo_procesable(ruta_archivo):
    """Determina si un archivo puede ser procesado."""
    extension = os.path.splitext(ruta_archivo)[1].lower()
    
    # Excluir archivos binarios y comprimidos
    if extension in EXTENSIONES_EXCLUIDAS:
        return False
    
    # Verificar si el archivo es demasiado grande
    try:
        if os.path.getsize(ruta_archivo) > TAMANO_MAXIMO:
            return False
    except:
        return False
    
    return True

def extraer_archivos_zip(ruta_carpeta, ruta_extraccion_base):
    """Extrae todos los archivos ZIP encontrados en la carpeta."""
    archivos_extraidos = []
    archivos_zip_encontrados = []
    
    # Buscar archivos ZIP
    for raiz, dirs, files in os.walk(ruta_carpeta):
        for archivo in files:
            if archivo.lower().endswith('.zip'):
                archivos_zip_encontrados.append(os.path.join(raiz, archivo))
    
    if not archivos_zip_encontrados:
        return archivos_extraidos
    
    print(f"🗜️  Se encontraron {len(archivos_zip_encontrados)} archivos ZIP")
    
    for zip_path in archivos_zip_encontrados:
        nombre_zip = os.path.splitext(os.path.basename(zip_path))[0]
        carpeta_extraccion = os.path.join(ruta_extraccion_base, f"extracted_{nombre_zip}")
        
        try:
            # Crear carpeta de extracción
            if not os.path.exists(carpeta_extraccion):
                os.makedirs(carpeta_extraccion)
            
            # Extraer ZIP
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(carpeta_extraccion)
            
            print(f"  Extraído: {os.path.basename(zip_path)} -> {carpeta_extraccion}")
            
            # Recopilar archivos extraídos
            for raiz, dirs, files in os.walk(carpeta_extraccion):
                for archivo in files:
                    ruta_completa = os.path.join(raiz, archivo)
                    if es_archivo_procesable(ruta_completa):
                        archivos_extraidos.append(ruta_completa)
            
        except Exception as e:
            print(f"🚨 Error extrayendo {os.path.basename(zip_path)}: {e}")
    
    return archivos_extraidos

def recopilar_todos_archivos(ruta_carpeta, incluir_zip_extraidos=True):
    """Recopila todos los archivos procesables, incluyendo extraídos de ZIP."""
    archivos_encontrados = []
    archivos_extraidos = []
    
    # Recopilar archivos normales (no ZIP)
    for raiz, dirs, files in os.walk(ruta_carpeta):
        for archivo in files:
            ruta_completa = os.path.join(raiz, archivo)
            if es_archivo_procesable(ruta_completa):
                archivos_encontrados.append(ruta_completa)
    
    # Extraer archivos ZIP si se solicita
    if incluir_zip_extraidos:
        try:
            # Crear carpeta temporal para extracciones
            carpeta_temp = os.path.join(ruta_carpeta, "temp_extracted")
            archivos_extraidos = extraer_archivos_zip(ruta_carpeta, carpeta_temp)
        except Exception as e:
            print(f"⚠️  Error en extracción automática de ZIP: {e}")
    
    return archivos_encontrados, archivos_extraidos

# ======================================================================
#                        FUNCIONES DE DETECCIÓN - ROBUSTAS
# ======================================================================

def detectar_tipo_archivo(codigo_lineas):
    """Detecta si es un archivo CL, PF o RPG basándose en el contenido - VERSIÓN ROBUSTA."""
    # Patrones específicos de archivos PF
    patrones_pf = [
        re.compile(r'^\s*R\s+[A-Z][A-Z0-9_]{0,9}\s*(?:TEXT\(|$)', re.IGNORECASE),
        re.compile(r'^\s*[A-Z][A-Z0-9_]{0,9}\s+\d+\s*[APSBFLTZHGO]\s*\d*\s*\d*', re.IGNORECASE),
        re.compile(r'^\s*K\s+[A-Z][A-Z0-9_]{0,9}\s*(?:\s|$)', re.IGNORECASE),
        re.compile(r'^\s*\*%%', re.IGNORECASE),
        re.compile(r'.*(?:COLHDG|EDTCDE|EDTWRD|DFT|VALUES|RANGE|COMP)\s*\(', re.IGNORECASE),
    ]
    
    # Patrones específicos de archivos CL
    patrones_clp = [
        re.compile(r'^\s*PGM\s*(?:\(|$)', re.IGNORECASE),
        re.compile(r'^\s*DCL\s+VAR\s*\(', re.IGNORECASE),
        re.compile(r'^\s*DCLF\s+FILE\s*\(', re.IGNORECASE),
        re.compile(r'^\s*ENDPGM\s*$', re.IGNORECASE),
        re.compile(r'^\s*(?:CHGVAR|CALL|CHKOBJ|MONMSG|CPYF|SNDPGMMSG)\s+', re.IGNORECASE),
    ]
    
    # Patrones específicos de archivos RPG - AMPLIADOS
    patrones_rpg = [
        re.compile(r'^\s*[HFDICOPPR]\s+.*', re.IGNORECASE),  # Especificaciones RPG
        re.compile(r'^\s*D\s+\w+\s+DS\s+', re.IGNORECASE),  # Data Structure
        re.compile(r'^\s*D\s+\w+\s+PR\s+', re.IGNORECASE),  # Procedure Prototype  
        re.compile(r'^\s*P\s+\w+\s+B\s+', re.IGNORECASE),   # Procedure Begin
        re.compile(r'^\s*C\s+(?:EVAL|IF|DOW|DOU|FOR|SELECT|CHAIN|READ|WRITE|EXSR|CLEAR|MONITOR)\s+', re.IGNORECASE),
        re.compile(r'^\s*/copy\s+', re.IGNORECASE),          # Copy statements
        re.compile(r'^\s*/free\s*$', re.IGNORECASE),         # Free format
        re.compile(r'^\s*/end-free\s*$', re.IGNORECASE),     # End free format
        re.compile(r'.*(?:DUMP|%SUBST|%SIZE)\s*\(', re.IGNORECASE),  # Funciones RPG
    ]
    
    puntos_pf = 0
    puntos_clp = 0
    puntos_rpg = 0
    
    for linea in codigo_lineas[:100]:  # Analizar primeras 100 líneas
        linea_limpia = linea.strip()
        
        if not linea_limpia or linea_limpia.startswith('*'):
            continue
        
        # Verificar patrones PF
        for patron in patrones_pf:
            if patron.match(linea_limpia):
                puntos_pf += 1
                break
        
        # Verificar patrones CL
        for patron in patrones_clp:
            if patron.match(linea_limpia):
                puntos_clp += 1
                break
        
        # Verificar patrones RPG
        for patron in patrones_rpg:
            if patron.match(linea_limpia):
                puntos_rpg += 1
                break
    
    # Determinar tipo basado en puntuación
    max_puntos = max(puntos_pf, puntos_clp, puntos_rpg)
    
    if max_puntos == 0:
        return 'DESCONOCIDO'
    elif puntos_rpg == max_puntos:
        return 'RPG'
    elif puntos_pf == max_puntos:
        return 'PF'
    elif puntos_clp == max_puntos:
        return 'CL'
    else:
        return 'DESCONOCIDO'

def detectar_tipo_archivo_avanzado(lineas, ruta_archivo):
    """
    Versión mejorada: Busca marcas de RPG/CL/PF de forma flexible 
    para evitar el error 'DESCONOCIDO'.
    """
    # 1. Prioridad por extensión de archivo
    ext = os.path.splitext(ruta_archivo)[1].lower()
    if ext in ['.rpg', '.rpgle', '.sqlrpgle']: return 'RPG'
    if ext in ['.clp', '.clle']: return 'CL'
    if ext in ['.pf', '.lf', '.dds']: return 'PF'

    # 2. Análisis de contenido (si la extensión falla)
    # Unimos las primeras 50 líneas para buscar patrones
    muestra = "".join(lineas[:50]).upper()
    
    # Patrones RPG (H, F, D, P o especificaciones de ciclo)
    if re.search(r'^[0-9 ]{5}[HFDCP]', muestra, re.MULTILINE) or "FREE" in muestra:
        return 'RPG'
    
    # Patrones CL
    if "PGM" in muestra or "DCL " in muestra or "CHGVAR" in muestra:
        return 'CL'
    
    # Patrones PF/DDS
    if "PFILE" in muestra or "UNIQUE" in muestra or " R " in muestra:
        return 'PF'

    return 'DESCONOCIDO'

# ======================================================================
#                        FUNCIONES DE ANÁLISIS
# ======================================================================

def leer_archivo_robusto(ruta_archivo):
    """
    Implementa la lógica de lectura del script v3:
    Detección de encoding -> Intento de lectura -> Fallback a Latin-1
    """
    contenido_lineas = []
    encoding_final = 'desconocido'
    
    try:
        # 1. Leer en binario para detectar encoding (como hace el v3)
        with open(ruta_archivo, 'rb') as f:
            raw_data = f.read(50000) # Buffer amplio para detección
            
        if CHARDET_DISPONIBLE:
            res = chardet.detect(raw_data)
            encoding_detectado = res['encoding']
        else:
            encoding_detectado = 'utf-8'

        # 2. Intentar lectura con encoding detectado
        intentos = [encoding_detectado, 'latin-1', 'cp1252', 'utf-8']
        
        for enc in intentos:
            if not enc: continue
            try:
                with open(ruta_archivo, 'r', encoding=enc) as f:
                    contenido_lineas = f.readlines()
                    encoding_final = enc
                    return contenido_lineas, encoding_final
            except (UnicodeDecodeError, TypeError):
                continue
                
    except Exception as e:
        print(f"❌ Error físico al acceder a {ruta_archivo}: {e}")
        
    return None, None

def analizar_archivo_cl(codigo_lineas):
    """Analiza específicamente archivos Control Language (CL)."""
    patron_dcl_var = re.compile(
        r'^\s*DCL\s+VAR\((?P<variable>\&\w+)\)\s+TYPE\((?P<tipo>*\w+)\)\s*(LEN\((?P<largo>\d+)\))?\s*(VALUE\((?P<valor>.*?)\))?',
        re.IGNORECASE
    )
    patron_dclf = re.compile(r'^\s*DCLF\s+FILE\((?P<archivo>\w+)\)', re.IGNORECASE)
    patron_etiqueta = re.compile(r'^\s*(?P<etiqueta>\w+):', re.IGNORECASE)
    patron_comandos = re.compile(
        r'^\s*(?P<comando>PGM|RCVF|RTVJOBA|CHGVAR|CALL|CHKOBJ|MONMSG|CPYF|SNDPGMMSG|OVRDBF|DLTF|CRTPF|CRTLF|ENDPGM|IF|ELSE|ENDDO|DO|DOU|DOW|GOTO|SBMJOB|RCVMSG|RETURN|CLRPFM)',
        re.IGNORECASE
    )
    patron_chgvar_simple = re.compile(r'CHGVAR\s+VAR\((?P<var_destino>\&\w+)\)\s+VALUE\((?P<valor>.+?)\)', re.IGNORECASE)
    patron_comentario_inicio = re.compile(r'^\s*/\*', re.IGNORECASE)
    patron_comentario_fin = re.compile(r'\*/\s*$', re.IGNORECASE)
    
    resultados_por_bloque = {'GLOBAL': []}
    lineas_no_analizadas_por_bloque = {'GLOBAL': []}
    variables_declaradas = {}
    estadisticas_comandos = Counter()
    comentarios_encontrados = []
    comentarios_por_bloque = {}
    
    bloque_actual = 'GLOBAL'
    en_comentario = False
    comentario_actual = ""
    num_linea_inicio = 0
    
    for num_linea, linea in enumerate(codigo_lineas, 1):
        linea_limpia = linea.strip()
        
        # Manejar comentarios multilinea
        if en_comentario:
            comentario_actual += " " + linea_limpia
            if patron_comentario_fin.search(linea_limpia):
                en_comentario = False
                comentarios_encontrados.append((num_linea_inicio, comentario_actual.replace('/*', '').replace('*/', '').strip()))
                comentario_actual = ""
            continue
        
        if patron_comentario_inicio.match(linea_limpia):
            en_comentario = True
            comentario_actual = linea_limpia
            num_linea_inicio = num_linea
            if patron_comentario_fin.search(linea_limpia):
                en_comentario = False
                comentarios_encontrados.append((num_linea_inicio, comentario_actual.replace('/*', '').replace('*/', '').strip()))
                comentario_actual = ""
            continue
        
        if not linea_limpia:
            continue
        
        linea_procesada = False
        
        # Etiquetas
        match_etiqueta = patron_etiqueta.match(linea_limpia)
        if match_etiqueta:
            bloque_actual = match_etiqueta.group('etiqueta').upper()
            if bloque_actual not in resultados_por_bloque:
                resultados_por_bloque[bloque_actual] = []
                lineas_no_analizadas_por_bloque[bloque_actual] = []
            
            descripcion = f"Etiqueta de programa: **{bloque_actual}**."
            resultados_por_bloque[bloque_actual].append((num_linea, linea_limpia, descripcion, None))
            linea_procesada = True
        
        # Variables
        if not linea_procesada:
            match_dcl_var = patron_dcl_var.match(linea_limpia)
            if match_dcl_var:
                var_data = match_dcl_var.groupdict()
                variable = var_data['variable']
                tipo = var_data['tipo']
                largo = var_data['largo'] or 'no especificado'
                valor = var_data['valor'] or 'vacío'
                
                variables_declaradas[variable] = {
                    'tipo': tipo,
                    'largo': largo,
                    'valor': valor,
                    'linea': num_linea
                }
                
                descripcion = f"Declara la variable **{variable}** como tipo **{tipo}** con una longitud de **{largo}** y un valor inicial de **'{valor}'**."
                resultados_por_bloque[bloque_actual].append((num_linea, linea_limpia, descripcion, None))
                estadisticas_comandos['DCL VAR'] += 1
                linea_procesada = True
        
        # Archivos
        if not linea_procesada:
            match_dclf = patron_dclf.match(linea_limpia)
            if match_dclf:
                descripcion = descripciones_comandos_cl['DCLF']
                resultados_por_bloque[bloque_actual].append((num_linea, linea_limpia, descripcion, None))
                estadisticas_comandos['DCLF'] += 1
                linea_procesada = True
        
        # CHGVAR específico
        if not linea_procesada:
            match_chgvar = patron_chgvar_simple.match(linea_limpia)
            if match_chgvar:
                var_destino = match_chgvar.group('var_destino')
                valor = match_chgvar.group('valor')
                descripcion = f"Cambia el valor de la variable **{var_destino}** a **{valor}**."
                resultados_por_bloque[bloque_actual].append((num_linea, linea_limpia, descripcion, None))
                estadisticas_comandos['CHGVAR'] += 1
                linea_procesada = True
        
        # Comandos generales
        if not linea_procesada:
            match_comandos = patron_comandos.match(linea_limpia)
            if match_comandos:
                comando = match_comandos.group('comando').upper()
                descripcion = descripciones_comandos_cl.get(comando, 'Comando CL.')
                resultados_por_bloque[bloque_actual].append((num_linea, linea_limpia, descripcion, None))
                estadisticas_comandos[comando] += 1
                linea_procesada = True
        
        if not linea_procesada:
            lineas_no_analizadas_por_bloque[bloque_actual].append((num_linea, linea_limpia))
    
    return resultados_por_bloque, lineas_no_analizadas_por_bloque, variables_declaradas, estadisticas_comandos, comentarios_encontrados, comentarios_por_bloque

def analizar_archivo_pf(codigo_lineas):
    """Analiza específicamente archivos Physical File (PF)."""
    patron_registro = re.compile(r'^\s*R\s+(?P<nombre>\w+)', re.IGNORECASE)
    patron_campo = re.compile(
        r'^\s*(?P<nombre>\w+)\s+(?P<posicion>\d+)(?P<tipo>[APSBFLTZHGO])\s*(?P<longitud>\d+)?(?P<decimales>\d+)?\s*(?P<atributos>.*)?',
        re.IGNORECASE
    )
    patron_clave = re.compile(r'^\s*K\s+(?P<campo>\w+)', re.IGNORECASE)
    patron_comentario_pf = re.compile(r'^\s*\*%%(?P<comentario>.*)', re.IGNORECASE)
    patron_texto = re.compile(r'TEXT\(\'(?P<texto>.*?)\'\)', re.IGNORECASE)
    patron_ref = re.compile(r'REF\((?P<archivo>\w+)/(?P<campo>\w+)\)', re.IGNORECASE)
    patron_colhdg = re.compile(r'COLHDG\(\'(?P<encabezado>.*?)\'\)', re.IGNORECASE)
    
    resultados_por_bloque = {'DEFINICIONES': []}
    lineas_no_analizadas_por_bloque = {'DEFINICIONES': []}
    campos_definidos = {}
    registros_definidos = {}
    claves_definidas = []
    estadisticas_elementos = Counter()
    comentarios_encontrados = []
    comentarios_por_bloque = {}
    
    registro_actual = None
    
    for num_linea, linea in enumerate(codigo_lineas, 1):
        linea_limpia = linea.strip()
        
        if not linea_limpia:
            continue
            
        # Procesar comentarios específicos de PF
        if linea_limpia.startswith('*'):
            match_comentario = patron_comentario_pf.match(linea_limpia)
            if match_comentario:
                comentario = match_comentario.group('comentario').strip()
                comentarios_encontrados.append((num_linea, comentario))
            continue
        
        linea_procesada = False
        
        # Registro/formato
        match_registro = patron_registro.match(linea_limpia)
        if match_registro:
            registro_actual = match_registro.group('nombre')
            registros_definidos[registro_actual] = {
                'linea': num_linea,
                'campos': [],
                'texto': ''
            }
            
            texto_match = patron_texto.search(linea_limpia)
            if texto_match:
                registros_definidos[registro_actual]['texto'] = texto_match.group('texto')
            
            descripcion = f"Define el formato de registro **{registro_actual}**."
            if texto_match:
                descripcion += f" Descripción: '{texto_match.group('texto')}'"
            
            resultados_por_bloque['DEFINICIONES'].append((num_linea, linea_limpia, descripcion, None))
            estadisticas_elementos['REGISTRO'] += 1
            linea_procesada = True
        
        # Campo
        if not linea_procesada:
            match_campo = patron_campo.match(linea_limpia)
            if match_campo:
                nombre_campo = match_campo.group('nombre')
                posicion = match_campo.group('posicion')
                tipo = match_campo.group('tipo')
                longitud = match_campo.group('longitud') or ''
                decimales = match_campo.group('decimales') or ''
                atributos = match_campo.group('atributos') or ''
                
                tipo_descripcion = tipos_datos_pf.get(tipo.upper(), f'Tipo {tipo}')
                
                campos_definidos[nombre_campo] = {
                    'posicion': posicion,
                    'tipo': tipo,
                    'longitud': longitud,
                    'decimales': decimales,
                    'registro': registro_actual,
                    'linea': num_linea
                }
                
                if registro_actual and registro_actual in registros_definidos:
                    registros_definidos[registro_actual]['campos'].append(nombre_campo)
                
                descripcion = f"Define el campo **{nombre_campo}** en posición **{posicion}**, tipo **{tipo_descripcion}**"
                if longitud:
                    descripcion += f", longitud **{longitud}**"
                if decimales:
                    descripcion += f", decimales **{decimales}**"
                
                # Analizar atributos adicionales
                if atributos:
                    if 'TEXT(' in atributos.upper():
                        texto_match = patron_texto.search(atributos)
                        if texto_match:
                            descripcion += f". Descripción: '{texto_match.group('texto')}'"
                    
                    if 'REF(' in atributos.upper():
                        ref_match = patron_ref.search(atributos)
                        if ref_match:
                            descripcion += f". Referencia: {ref_match.group('archivo')}/{ref_match.group('campo')}"
                    
                    if 'COLHDG(' in atributos.upper():
                        colhdg_match = patron_colhdg.search(atributos)
                        if colhdg_match:
                            descripcion += f". Encabezado: '{colhdg_match.group('encabezado')}'"
                
                resultados_por_bloque['DEFINICIONES'].append((num_linea, linea_limpia, descripcion, None))
                estadisticas_elementos['CAMPO'] += 1
                linea_procesada = True
        
        # Clave
        if not linea_procesada:
            match_clave = patron_clave.match(linea_limpia)
            if match_clave:
                campo_clave = match_clave.group('campo')
                claves_definidas.append({
                    'campo': campo_clave,
                    'registro': registro_actual,
                    'linea': num_linea
                })
                
                descripcion = f"Define **{campo_clave}** como campo clave"
                if registro_actual:
                    descripcion += f" para el registro **{registro_actual}**"
                
                resultados_por_bloque['DEFINICIONES'].append((num_linea, linea_limpia, descripcion, None))
                estadisticas_elementos['CLAVE'] += 1
                linea_procesada = True
        
        if not linea_procesada:
            lineas_no_analizadas_por_bloque['DEFINICIONES'].append((num_linea, linea_limpia))
    
    return resultados_por_bloque, lineas_no_analizadas_por_bloque, campos_definidos, estadisticas_elementos, comentarios_encontrados, comentarios_por_bloque, registros_definidos, claves_definidas


def analizar_archivo_rpg(codigo_lineas):
    """
    Versión corregida para Step 1:
    - No obliga a que la letra esté en la columna 6.
    - Captura comentarios con // y *.
    """
    import re
    from collections import Counter

    # Regex que busca la letra de tipo (H,F,D,I,C,O,P) en cualquier posición de la línea
    patron_flexible = re.compile(r'^(?P<prefijo>.*)(?P<tipo>[HFDICOPPR])(?P<contenido>.*)$', re.IGNORECASE)
    
    # Comandos comunes que queremos clasificar en la sección de CALCULOS
    comandos_calc = ['EVAL', 'IF', 'DUMP', 'CALL', 'PARM', 'ELSE', 'ENDIF', 'SELECT', 'WHEN', 'OTHER', 'ENDSL']

    resultados_por_bloque = {'ESPECIFICACIONES': [], 'CALCULOS': [], 'COPIAS': []}
    lineas_no_analizadas_por_bloque = {'ESPECIFICACIONES': []}
    estadisticas_elementos = Counter()
    comentarios_encontrados = []

    for num_linea, linea in enumerate(codigo_lineas, 1):
        linea_limpia = linea.strip()
        
        # 1. Identificar comentarios (// o * o línea vacía)
        # En tu demo, casi todo empieza con //
        if not linea_limpia or linea_limpia.startswith('//') or linea_limpia.startswith('*') or (len(linea) >= 7 and linea[6] == '*'):
            comentarios_encontrados.append((num_linea, linea_limpia))
            continue

        linea_procesada = False

        # 2. Análisis de contenido
        match = patron_flexible.match(linea)
        if match:
            tipo = match.group('tipo').upper()
            contenido = match.group('contenido').strip()
            
            # Decidir si va a CALCULOS o ESPECIFICACIONES
            # Si la línea contiene un comando de cálculo, la priorizamos
            if any(cmd in linea.upper() for cmd in comandos_calc) or tipo == 'C':
                seccion = 'CALCULOS'
                desc = f"Operación/Cálculo"
            else:
                seccion = 'ESPECIFICACIONES'
                desc = f"Especificación tipo {tipo}"

            resultados_por_bloque[seccion].append((num_linea, linea.strip(), desc, None))
            estadisticas_elementos[f"Tipo {tipo}"] += 1
            linea_procesada = True

        # 3. Si no encaja en lo anterior, la guardamos para que no se pierda la info
        if not linea_procesada:
            lineas_no_analizadas_por_bloque['ESPECIFICACIONES'].append((num_linea, linea_limpia))

    # Retornamos la estructura que el resto de tu script v4.2.0 espera
    return resultados_por_bloque, lineas_no_analizadas_por_bloque, {}, estadisticas_elementos, comentarios_encontrados, {}
    

# ======================================================================
#                        FUNCIONES DE ESCRITURA DE REPORTES
# ======================================================================

def escribir_reporte_desconocido(f_salida, ruta_archivo):
    """Escribe un reporte básico para archivos de tipo DESCONOCIDO."""
    info = obtener_info_archivo_basica(ruta_archivo)
    
    f_salida.write(f"Análisis básico del archivo DESCONOCIDO '{ruta_archivo}'\n")
    f_salida.write("=" * 60 + "\n")
    f_salida.write(f"**Fecha de Análisis:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    f_salida.write(f"**Tipo de Archivo:** DESCONOCIDO (no se pudo determinar el tipo)\n\n")
    
    if 'error' in info:
        f_salida.write(f"❌ **Error:** {info['error']}\n\n")
        f_salida.write("## 📄 Información Básica Disponible\n")
        f_salida.write(f"- **Nombre:** {info['nombre']}\n")
        f_salida.write(f"- **Ruta completa:** {info['ruta_completa']}\n")
        return
    
    f_salida.write("## 📄 Información del Archivo\n")
    f_salida.write("-" * 40 + "\n")
    f_salida.write(f"- **Nombre:** {info['nombre']}\n")
    f_salida.write(f"- **Ruta completa:** {info['ruta_completa']}\n")
    f_salida.write(f"- **Extensión:** {info['extension']}\n")
    f_salida.write(f"- **Tamaño:** {info['tamano_legible']} ({info['tamano_bytes']:,} bytes)\n")
    f_salida.write(f"- **Fecha de creación:** {info['fecha_creacion']}\n")
    f_salida.write(f"- **Fecha de modificación:** {info['fecha_modificacion']}\n")
    
    f_salida.write("\n## 🔐 Información de Integridad\n")
    f_salida.write("-" * 40 + "\n")
    f_salida.write(f"- **SHA-256 Hash:** {info['hash_sha256']}\n")
    
    f_salida.write("\n## 📝 Información de Contenido\n")
    f_salida.write("-" * 40 + "\n")
    f_salida.write(f"- **Encoding detectado:** {info['encoding_detectado']} (confianza: {info['confianza_encoding']:.1f}%)\n")
    
    info_lineas = info['info_lineas']
    f_salida.write(f"- **Total de líneas:** {info_lineas['total']}\n")
    f_salida.write(f"- **Líneas vacías:** {info_lineas['vacias']}\n")
    f_salida.write(f"- **Líneas con contenido:** {info_lineas['con_contenido']}\n")
    f_salida.write(f"- **Líneas de comentarios:** {info_lineas['comentarios']}\n")
    
    f_salida.write("\n" + "=" * 60 + "\n")
    f_salida.write("ℹ️  **Nota:** Este archivo no pudo ser identificado como CL, PF o RPG.\n")
    f_salida.write("   Solo se proporciona información básica del archivo.\n")
    f_salida.write("   Si crees que debería ser analizado, verifica el contenido manualmente.\n")
    f_salida.write("=" * 60 + "\n")

def escribir_reporte_cl(f_salida, ruta_archivo, analisis_por_bloque, no_analizadas_por_bloque, variables, estadisticas, comentarios_encontrados, comentarios_por_bloque):
    """Escribe el análisis específico para archivos CL."""
    hash_archivo = obtener_hash_archivo(ruta_archivo)
    info_lineas = contar_lineas_archivo(ruta_archivo)
    
    f_salida.write(f"Análisis del archivo CL '{ruta_archivo}'\n")
    f_salida.write("=" * 50 + "\n")
    f_salida.write(f"**SHA-256 Hash:** {hash_archivo}\n")
    f_salida.write(f"**Fecha de Análisis:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    f_salida.write(f"**Tipo de Archivo:** Control Language (CL)\n")
    f_salida.write(f"**Total de líneas:** {info_lineas['total']}\n")
    f_salida.write(f"**Líneas con contenido:** {info_lineas['con_contenido']}\n")
    f_salida.write(f"**Líneas vacías:** {info_lineas['vacias']}\n")
    f_salida.write(f"**Líneas de comentarios:** {info_lineas['comentarios']}\n\n")
    
    # Comentarios encontrados
    f_salida.write("## 📄 Comentarios del Programa\n")
    if comentarios_encontrados:
        for num_linea, comentario in comentarios_encontrados:
            f_salida.write(f"- Línea {num_linea}: {comentario}\n")
    else:
        f_salida.write("No se encontraron comentarios en el programa.\n")
    f_salida.write("\n" + "-" * 50 + "\n")
    
    # Estadísticas de comandos
    f_salida.write("## 📈 Resumen de Comandos (Estadísticas)\n")
    if estadisticas:
        max_len_comando = max(len(comando) for comando in estadisticas.keys()) if estadisticas else len('Comando')  
        max_len_frecuencia = max(len(str(count)) for count in estadisticas.values()) if estadisticas else len('Frecuencia')
        ancho_comando = max(len('Comando'), max_len_comando) + 1
        ancho_frecuencia = max(len('Frecuencia'), max_len_frecuencia)
        
        f_salida.write(f"| {'Comando':<{ancho_comando}} | {'Frecuencia':<{ancho_frecuencia}} |\n")
        f_salida.write(f"|:{'-' * ancho_comando}:|:{'-' * ancho_frecuencia}:|\n")
        for comando, count in sorted(estadisticas.items(), key=lambda item: item[1], reverse=True):
            f_salida.write(f"| **{comando:<{ancho_comando}}** | {count:<{ancho_frecuencia}} |\n")
    else:
        f_salida.write("No se encontraron comandos relevantes.\n")
    
    f_salida.write("\n" + "-" * 50 + "\n")
    
    # Variables declaradas
    f_salida.write("## 📜 Resumen de Variables Declaradas\n")
    if variables:
        for var, data in variables.items():
            f_salida.write(f"- **{var}** (Línea {data['linea']}): Tipo: {data['tipo']}, Largo: {data['largo']}, Valor: '{data['valor']}'\n")
    else:
        f_salida.write("No se encontraron declaraciones de variables.\n")
    
    f_salida.write("\n" + "-" * 50 + "\n")
    
    # Análisis por bloques
    f_salida.write("## 📦 Análisis por Bloques Lógicos\n")
    for bloque, analisis in analisis_por_bloque.items():
        if analisis or no_analizadas_por_bloque.get(bloque):
            f_salida.write(f"### Bloque: `{bloque}`\n")
            
            if analisis:
                for num_linea, linea_original, descripcion, comentario_contenido in analisis:
                    f_salida.write(f"- Línea {num_linea}: {descripcion}\n")
                    f_salida.write(f"  > Código: `{linea_original}`\n")
                    if comentario_contenido:
                        f_salida.write(f"  > Comentario: {comentario_contenido}\n")
                    f_salida.write("\n")
            
            if no_analizadas_por_bloque.get(bloque):
                f_salida.write("#### ⚠️ Líneas no analizadas:\n")
                for num_linea, linea_limpia in no_analizadas_por_bloque[bloque]:
                    f_salida.write(f"Línea {num_linea}: `{linea_limpia}`\n")
            
            f_salida.write("\n" + "-" * 50 + "\n")

def escribir_reporte_pf(f_salida, ruta_archivo, analisis_por_bloque, no_analizadas_por_bloque, campos, estadisticas, comentarios_encontrados, comentarios_por_bloque, registros_definidos, claves_definidas):
    """Escribe el análisis específico para archivos PF."""
    hash_archivo = obtener_hash_archivo(ruta_archivo)
    info_lineas = contar_lineas_archivo(ruta_archivo)
    
    f_salida.write(f"Análisis del archivo PF '{ruta_archivo}'\n")
    f_salida.write("=" * 50 + "\n")
    f_salida.write(f"**SHA-256 Hash:** {hash_archivo}\n")
    f_salida.write(f"**Fecha de Análisis:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    f_salida.write(f"**Tipo de Archivo:** Physical File (PF)\n")
    f_salida.write(f"**Total de líneas:** {info_lineas['total']}\n")
    f_salida.write(f"**Líneas con contenido:** {info_lineas['con_contenido']}\n")
    f_salida.write(f"**Líneas vacías:** {info_lineas['vacias']}\n")
    f_salida.write(f"**Líneas de comentarios:** {info_lineas['comentarios']}\n\n")
    
    # Comentarios encontrados
    f_salida.write("## 📄 Comentarios del Archivo\n")
    if comentarios_encontrados:
        for num_linea, comentario in comentarios_encontrados:
            f_salida.write(f"- Línea {num_linea}: {comentario}\n")
    else:
        f_salida.write("No se encontraron comentarios en el archivo.\n")
    f_salida.write("\n" + "-" * 50 + "\n")
    
    # Registros definidos
    f_salida.write("## 📋 Registros/Formatos Definidos\n")
    if registros_definidos:
        for registro, info in registros_definidos.items():
            f_salida.write(f"### Registro: `{registro}` (Línea {info['linea']})\n")
            if info['texto']:
                f_salida.write(f"**Descripción:** {info['texto']}\n")
            f_salida.write(f"**Campos incluidos:** {len(info['campos'])}\n")
            if info['campos']:
                f_salida.write("**Lista de campos:**\n")
                for campo in info['campos']:
                    if campo in campos:
                        campo_info = campos[campo]
                        tipo_desc = tipos_datos_pf.get(campo_info['tipo'].upper(), campo_info['tipo'])
                        f_salida.write(f"  - `{campo}` (Pos: {campo_info['posicion']}, Tipo: {tipo_desc}")
                        if campo_info['longitud']:
                            f_salida.write(f", Len: {campo_info['longitud']}")
                        if campo_info['decimales']:
                            f_salida.write(f", Dec: {campo_info['decimales']}")
                        f_salida.write(")\n")
            f_salida.write("\n")
    else:
        f_salida.write("No se encontraron definiciones de registros.\n")
    
    # Claves definidas
    f_salida.write("\n## 🔑 Claves Definidas\n")
    if claves_definidas:
        for clave in claves_definidas:
            f_salida.write(f"- **{clave['campo']}** (Línea {clave['linea']})")
            if clave['registro']:
                f_salida.write(f" - Registro: `{clave['registro']}`")
            f_salida.write("\n")
    else:
        f_salida.write("No se encontraron definiciones de claves.\n")
    
    # Estadísticas
    f_salida.write("\n## 📈 Estadísticas del Archivo PF\n")
    if estadisticas:
        max_len_elemento = max(len(elemento) for elemento in estadisticas.keys()) if estadisticas else len('Elemento')
        max_len_cantidad = max(len(str(count)) for count in estadisticas.values()) if estadisticas else len('Cantidad')
        ancho_elemento = max(len('Elemento'), max_len_elemento) + 1
        ancho_cantidad = max(len('Cantidad'), max_len_cantidad)
        
        f_salida.write(f"| {'Elemento':<{ancho_elemento}} | {'Cantidad':<{ancho_cantidad}} |\n")
        f_salida.write(f"|:{'-' * ancho_elemento}:|:{'-' * ancho_cantidad}:|\n")
        for elemento, count in sorted(estadisticas.items(), key=lambda item: item[1], reverse=True):
            f_salida.write(f"| **{elemento:<{ancho_elemento}}** | {count:<{ancho_cantidad}} |\n")
    else:
        f_salida.write("No se encontraron elementos relevantes.\n")
    
    # Análisis detallado
    f_salida.write("\n## 📦 Análisis Detallado\n")
    for bloque, analisis in analisis_por_bloque.items():
        if analisis or no_analizadas_por_bloque.get(bloque):
            f_salida.write(f"### {bloque}\n")
            
            if analisis:
                for num_linea, linea_original, descripcion, comentario_contenido in analisis:
                    f_salida.write(f"- Línea {num_linea}: {descripcion}\n")
                    f_salida.write(f"  > Código: `{linea_original}`\n")
                    if comentario_contenido:
                        f_salida.write(f"  > Comentario: {comentario_contenido}\n")
                    f_salida.write("\n")
            
            if no_analizadas_por_bloque.get(bloque):
                f_salida.write("#### ⚠️ Líneas no analizadas:\n")
                for num_linea, linea_limpia in no_analizadas_por_bloque[bloque]:
                    f_salida.write(f"Línea {num_linea}: `{linea_limpia}`\n")
            
            f_salida.write("\n" + "-" * 50 + "\n")

def escribir_reporte_rpg(f_salida, ruta_archivo, analisis_por_bloque, no_analizadas_por_bloque, elementos, estadisticas, comentarios_encontrados, comentarios_por_bloque):
    """Escribe el análisis específico para archivos RPG."""
    hash_archivo = obtener_hash_archivo(ruta_archivo)
    info_lineas = contar_lineas_archivo(ruta_archivo)
    
    f_salida.write(f"Análisis del archivo RPG '{ruta_archivo}'\n")
    f_salida.write("=" * 50 + "\n")
    f_salida.write(f"**SHA-256 Hash:** {hash_archivo}\n")
    f_salida.write(f"**Fecha de Análisis:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    f_salida.write(f"**Tipo de Archivo:** RPG\n")
    f_salida.write(f"**Total de líneas:** {info_lineas['total']}\n")
    f_salida.write(f"**Líneas con contenido:** {info_lineas['con_contenido']}\n")
    f_salida.write(f"**Líneas vacías:** {info_lineas['vacias']}\n")
    f_salida.write(f"**Líneas de comentarios:** {info_lineas['comentarios']}\n\n")
    
    # Comentarios encontrados
    f_salida.write("## 📄 Comentarios del Programa\n")
    if comentarios_encontrados:
        for num_linea, comentario in comentarios_encontrados:
            f_salida.write(f"- Línea {num_linea}: {comentario}\n")
    else:
        f_salida.write("No se encontraron comentarios en el programa.\n")
    f_salida.write("\n" + "-" * 50 + "\n")
    
    # Estadísticas
    f_salida.write("## 📈 Estadísticas del Archivo RPG\n")
    if estadisticas:
        max_len_elemento = max(len(elemento) for elemento in estadisticas.keys()) if estadisticas else len('Elemento')
        max_len_cantidad = max(len(str(count)) for count in estadisticas.values()) if estadisticas else len('Cantidad')
        ancho_elemento = max(len('Elemento'), max_len_elemento) + 1
        ancho_cantidad = max(len('Cantidad'), max_len_cantidad)
        
        f_salida.write(f"| {'Elemento':<{ancho_elemento}} | {'Cantidad':<{ancho_cantidad}} |\n")
        f_salida.write(f"|:{'-' * ancho_elemento}:|:{'-' * ancho_cantidad}:|\n")
        for elemento, count in sorted(estadisticas.items(), key=lambda item: item[1], reverse=True):
            f_salida.write(f"| **{elemento:<{ancho_elemento}}** | {count:<{ancho_cantidad}} |\n")
    else:
        f_salida.write("No se encontraron elementos relevantes.\n")
    
    # Análisis por secciones
    f_salida.write("\n## 📦 Análisis por Secciones\n")
    for seccion, analisis in analisis_por_bloque.items():
        if analisis or no_analizadas_por_bloque.get(seccion):
            f_salida.write(f"### Sección: `{seccion}`\n")
            
            if analisis:
                for num_linea, linea_original, descripcion, comentario_contenido in analisis:
                    f_salida.write(f"- Línea {num_linea}: {descripcion}\n")
                    f_salida.write(f"  > Código: `{linea_original}`\n")
                    if comentario_contenido:
                        f_salida.write(f"  > Comentario: {comentario_contenido}\n")
                    f_salida.write("\n")
            
            if no_analizadas_por_bloque.get(seccion):
                f_salida.write("#### ⚠️ Líneas no analizadas:\n")
                for num_linea, linea_limpia in no_analizadas_por_bloque[seccion]:
                    f_salida.write(f"Línea {num_linea}: `{linea_limpia}`\n")
            
            f_salida.write("\n" + "-" * 50 + "\n")

# ======================================================================
#                        FUNCIONES DE GESTIÓN DE ARCHIVOS
# ======================================================================

def generar_nombre_salida(nombre_base, tipo_archivo, tipo_analisis, tipo_reporte, ruta_salida):
    """Genera un nombre de archivo de salida con fecha y hora, tipo de archivo y tipo de análisis."""
    fecha_hora = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    nombre_sin_extension = os.path.splitext(nombre_base)[0] if nombre_base else ""
    nombre_archivo = FORMATO_NOMBRE_SALIDA.format(
        prefijo=PREFIJO_SALIDA,
        tipo_archivo=tipo_archivo.lower(),
        nombre_archivo=nombre_sin_extension,
        tipo_analisis=tipo_analisis,
        tipo_reporte=tipo_reporte,
        fecha=fecha_hora
    )
    return os.path.join(ruta_salida, f"{nombre_archivo}.txt")

def obtener_ruta_salida(opcion_ruta):
    """Obtiene o crea la ruta de salida basada en la opción del usuario."""
    if opcion_ruta == '1':
        return os.getcwd()
    elif opcion_ruta == '2':
        fecha_hora = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        ruta_salida = os.path.join(os.getcwd(), f"salida_{fecha_hora}")
        if not os.path.exists(ruta_salida):
            os.makedirs(ruta_salida)
            print(f"[+] Se ha creado la carpeta de salida: '{ruta_salida}'")
        return ruta_salida
    else:
        return None
        
def procesar_archivo_individual(ruta_archivo, nombre_salida, tipo_archivo):
    """
    Versión 5.2 - MÁXIMA COMPATIBILIDAD
    Lee el archivo con detección de encoding y genera el reporte detallado.
    """
    import os
    from datetime import datetime
    
    # 1. Obtener Hash (Usando la función que ya existe en tu script)
    try:
        hash_sha256 = obtener_hash_archivo(ruta_archivo)
    except:
        hash_sha256 = "No disponible"
        
    fecha_analisis = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # 2. Leer contenido con manejo de encoding manual para evitar errores
    lineas = []
    encoding_detectado = "Desconocido"
    try:
        # Intentar leer primero como binario para detectar el encoding
        with open(ruta_archivo, 'rb') as f:
            raw_data = f.read()
            # Si chardet está, lo usamos, si no, intentamos MacRoman/Utf-8
            encoding_detectado = "mac_roman" # Por defecto para archivos IBM antiguos
            
        with open(ruta_archivo, 'r', encoding=encoding_detectado, errors='ignore') as f:
            lineas = f.readlines()
    except Exception as e:
        # Fallback a UTF-8 si falla
        try:
            with open(ruta_archivo, 'r', encoding='utf-8', errors='ignore') as f:
                lineas = f.readlines()
                encoding_detectado = "utf-8"
        except:
            print(f"🚨 Error crítico de lectura en {ruta_archivo}")
            return False

    # 3. Ejecutar el análisis (RPG / CL / PF)
    # Llamamos a tus funciones de análisis existentes
    if tipo_archivo == 'RPG':
        res = analizar_archivo_rpg(lineas)
    elif tipo_archivo == 'CL':
        res = analizar_archivo_cl(lineas)
    else:
        res = analizar_archivo_pf(lineas)

    # Desempaquetar resultados (Estructura v4.2.0)
    # resultados_bloque, no_analizadas, elementos, estadisticas, comentarios, hallazgos
    resultados_bloque = res[0]
    no_analizadas = res[1]
    estadisticas = res[3]
    comentarios = res[4]

    # 4. Escritura del Reporte (Formato compatible con Step 2)
    try:
        with open(nombre_salida, 'w', encoding='utf-8') as f:
            f.write("="*60 + "\n")
            f.write(f" ANALIZADOR IBM i - REPORTE DE SISTEMA (v4.2.0 + v3 Logic)\n")
            f.write("="*60 + "\n")
            f.write(f"ARCHIVO:  {os.path.basename(ruta_archivo)}\n")
            f.write(f"TIPO:     {tipo_archivo}\n")
            f.write(f"ENCODING: {encoding_detectado}\n")
            f.write(f"HASH:     {hash_sha256}\n")
            f.write("-" * 60 + "\n\n")

            # SECCIÓN: Comentarios
            f.write("## 📄 Comentarios del Programa\n")
            if comentarios:
                for num, texto in comentarios:
                    f.write(f"Línea {num}: {texto.strip()}\n")
            else:
                f.write("No se encontraron comentarios.\n")
            
            # SECCIÓN: Estadísticas
            f.write("\n## 📈 Estadísticas de especificaciones:\n")
            if estadisticas:
                for elem, cant in estadisticas.items():
                    f.write(f"  {elem}: {cant}\n")

            # SECCIÓN: Análisis Detallado
            f.write("\n## 📦 Análisis por Secciones\n")
            for seccion, items in resultados_bloque.items():
                if items:
                    f.write(f"### Sección: `{seccion}`\n")
                    for num, cod, desc, _ in items:
                        f.write(f"- Línea {num}: {desc}\n")
                        f.write(f"  > Código: `{cod.strip()}`\n")

            # SECCIÓN: Respaldo (Aquí se guarda lo que no se clasificó pero Step 2 analizará)
            if no_analizadas.get('ESPECIFICACIONES'):
                f.write("\n#### ⚠️ Líneas capturadas (Análisis General):\n")
                for num, cod in no_analizadas['ESPECIFICACIONES']:
                    f.write(f"Línea {num}: `{cod.strip()}`\n")

            f.write("\n" + "="*60 + "\n")
            f.write(" FIN DEL REPORTE\n")
            f.write("="*60 + "\n")
            
    except Exception as e:
        print(f"🚨 Error escribiendo reporte: {e}")

    return True
        

def generar_header_carpeta_recursivo(ruta_carpeta, ruta_salida, archivos_encontrados):
    """Genera un header completo con análisis RECURSIVO - VERSIÓN CORREGIDA."""
    try:
        fecha_hora = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        nombre_header = os.path.join(ruta_salida, f"HEADER_analisis_recursivo_{fecha_hora}.txt")
        
        print(f"📋 Generando header de análisis recursivo...")
        
        with open(nombre_header, 'w', encoding='utf-8') as f_header:
            f_header.write("=" * 120 + "\n")
            f_header.write("                           ANÁLISIS RECURSIVO DE CARPETA - HEADER COMPLETO\n")
            f_header.write("=" * 120 + "\n")
            f_header.write(f"📂 Carpeta analizada: {os.path.abspath(ruta_carpeta)}\n")
            f_header.write(f"🕒 Fecha y hora: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f_header.write(f"📊 Total de archivos encontrados (recursivo): {len(archivos_encontrados)}\n")
            f_header.write("=" * 120 + "\n\n")
            
            # Agrupar por subcarpetas
            archivos_por_carpeta = {}
            extensiones = {}
            tipos_detectados = {'CL': 0, 'PF': 0, 'RPG': 0, 'DESCONOCIDO': 0}
            
            for ruta_archivo in archivos_encontrados:
                carpeta_relativa = os.path.relpath(os.path.dirname(ruta_archivo), ruta_carpeta)
                if carpeta_relativa == '.':
                    carpeta_relativa = 'RAÍZ'
                
                if carpeta_relativa not in archivos_por_carpeta:
                    archivos_por_carpeta[carpeta_relativa] = []
                
                archivos_por_carpeta[carpeta_relativa].append(ruta_archivo)
            
            f_header.write("## 📁 ESTRUCTURA DE CARPETAS Y ARCHIVOS\n")
            f_header.write("-" * 120 + "\n")
            
            for carpeta, archivos in sorted(archivos_por_carpeta.items()):
                f_header.write(f"### 📂 {carpeta} ({len(archivos)} archivos)\n\n")
                
                for ruta_archivo in sorted(archivos):
                    nombre_archivo = os.path.basename(ruta_archivo)
                    extension = os.path.splitext(nombre_archivo)[1].lower() or 'sin extensión'
                    
                    # Contar extensiones
                    extensiones[extension] = extensiones.get(extension, 0) + 1
                    
                    # Detectar tipo y analizar
                    try:
                        with open(ruta_archivo, 'r', encoding='utf-8') as f:
                            codigo_lineas = f.readlines()
                        tipo_archivo = detectar_tipo_archivo_avanzado(codigo_lineas, ruta_archivo)
                        tipos_detectados[tipo_archivo] += 1
                        num_lineas = len(codigo_lineas)
                        hash_completo = obtener_hash_archivo(ruta_archivo)
                        size_bytes = os.path.getsize(ruta_archivo)
                        
                        if size_bytes >= 1024 * 1024:
                            size_str = f"{size_bytes / (1024 * 1024):.2f} MB"
                        elif size_bytes >= 1024:
                            size_str = f"{size_bytes / 1024:.2f} KB"
                        else:
                            size_str = f"{size_bytes} bytes"
                            
                    except Exception as e:
                        tipo_archivo = 'ERROR'
                        num_lineas = 'ERROR'
                        hash_completo = f'ERROR: {str(e)}'
                        size_str = "ERROR"
                    
                    f_header.write(f"  #### 📄 {nombre_archivo}\n")
                    f_header.write(f"    - **Ruta completa:** {ruta_archivo}\n")
                    f_header.write(f"    - **Extensión:** {extension}\n")
                    f_header.write(f"    - **Tipo detectado:** {tipo_archivo}\n")
                    
                    #   CORRECCIÓN DEL ERROR DE FORMATEO - FUNCIÓN SEGURA
                    if isinstance(num_lineas, int):
                        f_header.write(f"    - **Líneas:** {num_lineas:,}\n")
                    else:
                        f_header.write(f"    - **Líneas:** {num_lineas}\n")
                    
                    f_header.write(f"    - **Tamaño:** {size_str}\n")
                    f_header.write(f"    - **SHA-256 Hash:** {hash_completo}\n")
                    f_header.write("\n")
                
                f_header.write("-" * 80 + "\n")
            
            # Resumen de extensiones
            f_header.write("\n## 📊 RESUMEN POR EXTENSIONES\n")
            f_header.write("-" * 40 + "\n")
            for ext, count in sorted(extensiones.items(), key=lambda x: x[1], reverse=True):
                porcentaje = (count / len(archivos_encontrados)) * 100
                f_header.write(f"  {ext:<15}: {count:>3} archivos ({porcentaje:5.1f}%)\n")
            
            # Resumen por tipo detectado
            f_header.write("\n## 🔍 RESUMEN POR TIPO DETECTADO\n")
            f_header.write("-" * 40 + "\n")
            for tipo, cantidad in sorted(tipos_detectados.items(), key=lambda x: x[1], reverse=True):
                if cantidad > 0:
                    porcentaje = (cantidad / len(archivos_encontrados)) * 100
                    f_header.write(f"  {tipo:<15}: {cantidad:>3} archivos ({porcentaje:5.1f}%)\n")
            
            f_header.write("\n" + "=" * 120 + "\n")
            f_header.write("                                    FIN DEL HEADER RECURSIVO\n")
            f_header.write("=" * 120 + "\n")
        
        print(f"  Header recursivo generado: '{nombre_header}'")
        return nombre_header
        
    except Exception as e:
        print(f"🚨 Error generando header recursivo: {e}")
        return None
def analizar_lineas_v3_rpg(lineas):
    """
    Esta es la lógica de procesamiento línea a línea que te funciona en el v3.
    """
    resultados = []
    resultados.append(f"Resumen de Análisis (Procesado v3):")
    resultados.append("-" * 40)
    
    conteo_especificaciones = Counter()
    
    for i, linea in enumerate(lineas, 1):
        linea_upper = linea.upper()
        # Identificar tipos de especificación RPG clásica
        if len(linea) >= 6:
            espec = linea[5].upper()
            if espec in 'HFDCIOP':
                conteo_especificaciones[espec] += 1
        
        # Ejemplo de lógica de detección de lógica (puedes ampliarla)
        if "BEGSR" in linea_upper:
            resultados.append(f"[L- {i:04}] INICIO SUBRUTINA: {linea.strip()}")
        if "EXSR" in linea_upper:
            resultados.append(f"[L- {i:04}] LLAMADA SUBRUTINA: {linea.strip()}")
            
    resultados.append("-" * 40)
    resultados.append("Estadísticas de especificaciones:")
    for esp, cant in conteo_especificaciones.items():
        resultados.append(f"  Tipo {esp}: {cant}")
        
    return resultados
    
    
# ======================================================================
#                          FUNCIÓN PRINCIPAL
# ======================================================================
def main():
    parser = argparse.ArgumentParser(description="Analizador de comandos RPG/CL/PF para archivos o carpetas.")
    grupo = parser.add_mutually_exclusive_group(required=True)
    grupo.add_argument('-a', '--archivo', type=str, help='Ruta del archivo a analizar.')
    grupo.add_argument('-f', '--carpeta', type=str, help='Ruta de la carpeta a analizar.')
    parser.add_argument('-o', '--salida', type=str, help='Nombre del archivo de salida.')
    parser.add_argument('--no-zip', action='store_true', help='No extraer archivos ZIP automáticamente.')
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("      ANALIZADOR DE CÓDIGO IBM RPG/CL/PF v4.2.0")
    print("                SOPORTE ENCODING V3 INTEGRADO")
    print("=" * 60)
    
    # Preguntar al usuario por la ruta de salida
    print("¿Dónde deseas guardar los reportes?")
    print("1. En la misma carpeta del análisis.")
    print("2. En una nueva subcarpeta con fecha y hora.")
    opcion_ruta = input("Ingresa tu opción (1 o 2): ")
    
    ruta_salida = obtener_ruta_salida(opcion_ruta)
    if ruta_salida is None:
        print("❌ Opción de ruta no válida. Saliendo del programa.")
        return
    
    if args.archivo:
        # ANÁLISIS DE ARCHIVO INDIVIDUAL
        ruta_absoluta = os.path.abspath(args.archivo)
        
        if not es_archivo_procesable(ruta_absoluta):
            print(f"⚠️  El archivo '{args.archivo}' no es procesable (binario o demasiado grande).")
            return
        
        # --- MEJORA: LEER USANDO LA LÓGICA DEL SCRIPT V3 ---
        codigo_lineas, enc_usado = leer_archivo_robusto(ruta_absoluta)
        
        if codigo_lineas is not None:
            try:
                # Ahora detectamos el tipo pasando las líneas ya leídas correctamente
                tipo_archivo = detectar_tipo_archivo_avanzado(codigo_lineas, ruta_absoluta)
                
                extension = os.path.splitext(ruta_absoluta)[1]
                print(f"\n📄 Archivo: {os.path.basename(ruta_absoluta)} (extensión: {extension or 'sin extensión'})")
                print(f"🔍 Tipo detectado: {tipo_archivo} | Encoding: {enc_usado}")
                print(f"📏 Número de líneas: {len(codigo_lineas)}")
                
                if tipo_archivo == 'DESCONOCIDO':
                    print("⚠️  Tipo desconocido. Se generará solo información básica.")
                
                nombre_base_salida = args.salida or os.path.splitext(os.path.basename(args.archivo))[0]
                nombre_salida = generar_nombre_salida(nombre_base_salida, tipo_archivo, "detallado", "individual", ruta_salida)
                
                procesar_archivo_individual(ruta_absoluta, nombre_salida, tipo_archivo)
                
            except Exception as e:
                print(f"🚨 Error en el análisis de contenido: {e}")
        else:
            print(f"❌ Error crítico: No se pudo decodificar el archivo '{args.archivo}'. Verifique el encoding.")

    elif args.carpeta:
        # ANÁLISIS RECURSIVO DE CARPETA
        print(f"\n Analizando carpeta recursivamente: {os.path.abspath(args.carpeta)}")
        
        incluir_zip = not args.no_zip
        archivos_normales, archivos_extraidos = recopilar_todos_archivos(args.carpeta, incluir_zip)
        todos_archivos = archivos_normales + archivos_extraidos
        
        if not todos_archivos:
            print(f"  No se encontraron archivos procesables en '{args.carpeta}'.")
            return
        
        print(f"📁 Archivos encontrados: {len(archivos_normales)}")
        if archivos_extraidos:
            print(f"📦 Extraídos de ZIP: {len(archivos_extraidos)}")
        
        generar_header_carpeta_recursivo(args.carpeta, ruta_salida, todos_archivos)
        
        tipos_detectados = {'CL': 0, 'PF': 0, 'RPG': 0, 'DESCONOCIDO': 0}
        archivos_procesados = 0
        total_lineas = 0
        archivos_con_error = 0
        
        print(f"\n📋 Procesando {len(todos_archivos)} archivos...")
        
        for ruta_archivo in todos_archivos:
            nombre_archivo = os.path.basename(ruta_archivo)
            carpeta_relativa = os.path.relpath(os.path.dirname(ruta_archivo), args.carpeta)
            
            # --- MEJORA: LEER USANDO LA LÓGICA DEL SCRIPT V3 ---
            lineas_file, enc_file = leer_archivo_robusto(ruta_archivo)
            
            if lineas_file is None:
                print(f"🚨 Error de lectura en {nombre_archivo} (Encoding incompatible)")
                archivos_con_error += 1
                continue

            try:
                tipo_archivo = detectar_tipo_archivo_avanzado(lineas_file, ruta_archivo)
                tipos_detectados[tipo_archivo] += 1
                num_lineas = len(lineas_file)
                total_lineas += num_lineas
                
                prefijo_print = f"{carpeta_relativa}/{nombre_archivo}" if carpeta_relativa != '.' else nombre_archivo
                print(f"📄 {prefijo_print} -> {tipo_archivo} ({num_lineas} líns | {enc_file})")
                
                nombre_base = f"{carpeta_relativa.replace(os.sep, '_')}_{nombre_archivo}" if carpeta_relativa != '.' else nombre_archivo
                nombre_salida = generar_nombre_salida(nombre_base, tipo_archivo, "detallado", "individual", ruta_salida)
                
                procesar_archivo_individual(ruta_archivo, nombre_salida, tipo_archivo)
                archivos_procesados += 1
                
            except Exception as e:
                print(f"🚨 Error procesando {nombre_archivo}: {e}")
                archivos_con_error += 1
        
        # Resumen final
        print(f"\n📊 RESUMEN FINAL:")
        print(f"  Procesados con éxito: {archivos_procesados}")
        print(f"  Errores: {archivos_con_error}")
        print(f"  Total líneas: {total_lineas:,}")
        for t, c in tipos_detectados.items():
            if c > 0: print(f"  {t}: {c}")
                
                
if __name__ == "__main__":
    main()
