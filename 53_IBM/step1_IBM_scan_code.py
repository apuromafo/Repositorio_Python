"""
Analizador de Código RPG/CL/PF
Versión: 4.1.1 - FINAL COMPLETA
Descripción:
Este script analiza archivos o carpetas que contienen código RPG, CL (Control Language)
y PF (Physical File). Genera un informe detallado que incluye un resumen de comandos 
utilizados, estadísticas de uso, variables/campos declarados y un listado de líneas 
no reconocidas.

Modo de uso:
- Para analizar un solo archivo:
  python3 IBM_Analyzer_v4.1.1_FINAL.py -a <ruta_del_archivo>
- Para analizar una carpeta completa:
  python3 IBM_Analyzer_v4.1.1_FINAL.py -f <ruta_de_la_carpeta>
- Para especificar el nombre del archivo de salida (opcional):
  python3 IBM_Analyzer_v4.1.1_FINAL.py -a <ruta_del_archivo> -o <nombre_salida.txt>

# ==============================================================================
# --- HISTORIAL DE VERSIONES ---
# ==============================================================================
# v4.1.1 (2025-09-16) - [FINAL COMPLETA]
#  ✅ Añadido: Análisis recursivo de carpetas y subcarpetas
#  ✅ Corregido: Hash SHA-256 completo (64 caracteres) sin truncar
#  ✅ Corregido: Número de líneas incluido en todas las tablas
#  ✅ Corregido: Diccionario completo de comandos PF restaurado
#  ✅ Corregido: Archivos DESCONOCIDO con información básica solamente
#  ✅ Mejorado: Header recursivo con estructura de carpetas
#  ✅ Mejorado: Detección de encoding y metadatos completos
# ==============================================================================
"""

import re
import argparse
import os
import hashlib
from datetime import datetime
from collections import Counter
import time
from datetime import datetime

# Intentar importar chardet, si no está disponible usar fallback
try:
    import chardet
    CHARDET_DISPONIBLE = True
except ImportError:
    CHARDET_DISPONIBLE = False
    print("⚠️  Advertencia: chardet no está instalado. Usando UTF-8 por defecto.")

# ======================================================================
#                            CONFIGURACIÓN
# ======================================================================
PREFIJO_SALIDA = 'analisis'
CARPETA_REPORTE = "Reporte"
FORMATO_NOMBRE_SALIDA = '{prefijo}_{tipo_archivo}_{tipo_analisis}_{tipo_reporte}_{nombre_archivo}_{fecha}'

# ======================================================================
#                    DICCIONARIOS DE COMANDOS Y CAMPOS
# ======================================================================

# Comandos CL
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

# Comandos y elementos PF - DICCIONARIO COMPLETO RESTAURADO
descripciones_comandos_pf = {
    'UNIQUE': 'Define que el archivo físico tiene claves únicas.',
    'REF': 'Define una referencia a un archivo de referencia de campos.',
    'PFILE': 'Define el archivo físico base para un archivo lógico.',
    'JFILE': 'Define archivos para operaciones de join.',
    'FORMAT': 'Define el nombre del formato de registro.',
    'TEXT DESCRIPCION': 'Proporciona una descripción textual del archivo o campo.',  # Spanish for Text Description
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
    'MBR': 'Define el nombre del miembro del archivo físico.',  # Member name of the physical file.
    'LIB': 'Especifica la biblioteca donde se encuentra el archivo físico.',  # Library where the physical file is located.
    'KEY': 'Define las claves (índices) en el archivo físico.',  # Defines keys (indexes) in the physical file.
    'EXTEND': 'Permite la adición de registros cuando no hay más espacio al final del archivo.',  # Allows addition of records when no more space exists at end of file.
    'SIZE': 'Establece el tamaño del archivo físico.',  # Sets the size of the physical file.
    'REPLACE': 'Indica que si un archivo con el mismo nombre ya existe, debe ser reemplazado sin aviso.',  # Replace without warning if file already exists.
    'ALWSAV': 'Permite guardar el archivo en una savefile.',  # Allows saving of the file in a save file.
    'USRPRF': 'Especifica el perfil de usuario para la propiedad del archivo físico.',  # Specifies user profile for ownership.
    'SHRDLT': 'Controla si el archivo puede ser compartido o no.',  # Controls whether file can be shared or not.
    'TFRSPLF': 'Transfiere registros de impresión al archivo especificado.',  # Transfers spooled files to the specified file.
    'MGTCLS': 'Gestiona objetos de clase en el archivo.',  # Manages class objects in the file.
    'DTAARA': 'Almacena datos de área dentro del archivo físico.',  # Stores data areas within physical file.
    'DDM': 'Define atributos de Distributed Data Management (DDM) para el archivo.',  # Defines DDM attributes for the file.
    'I/O ACCESS': 'Especifica los modos de acceso de entrada y salida del archivo.',  # Specifies input and output access modes of file.
    'OVERFLOW': 'Permite la creación de un archivo de flujo lateral cuando el archivo primario está lleno.',  # Allows creation of overflow file when primary is full.
    'LOCK': 'Establece detalles de bloqueo como tipo, duración y bandeja de mensajes para el archivo.',  # Sets up locking details like type, duration, and message queue.
    'DTAFMT': 'Especifica una tabla de formato de datos a ser utilizada por la base de datos.',  # Specifies data format table to be used by database.
    'DLMREC': 'Define registros de delimitador en archivos de flujo.',  # Defines delimiter records in stream files.
}

# Comandos y elementos RPG
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
    'DUMP': '⚠️ HALLAZGO DE SEGURIDAD: Genera volcado de memoria para depuración',
    '%SUBST': 'Función para extraer subcadenas de una cadena',
    '%SIZE': 'Función que devuelve el tamaño de una variable o campo'
}

# Tipos de datos PF
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
# === INICIO DE BLOQUE CLASIFICADOR DE LÍNEAS NO ANALIZADAS (FINAL CORREGIDO) ===
# Define los patrones especiales para clasificar líneas que no fueron reconocidas.
# Se añade WRKSPLF para cubrir el caso faltante.
patrones_especiales = {
    "EXEC_SQL":       re.compile(r"C/EXEC SQL", re.IGNORECASE),
    "END_EXEC":       re.compile(r"C/END-EXEC", re.IGNORECASE),
    "CALL":           re.compile(r"\bCALL\b|\bCALL\s*'.*'", re.IGNORECASE),
    "DUMP":           re.compile(r"\bDUMP\b|\bDUMP\(", re.IGNORECASE),
    "CHGJOB":         re.compile(r"\bCHGJOB\b", re.IGNORECASE),
    "DEBUG":          re.compile(r"\bDEBUG\b|\*DEBUG\*", re.IGNORECASE),
    "DSPJOB":         re.compile(r"\bDSPJOB\b", re.IGNORECASE),
    "WRKSPLF":        re.compile(r"\bWRKSPLF\b", re.IGNORECASE), # <--- PATRÓN AÑADIDO
    "HALLAZGO":       re.compile(r"//\s*\*\*\s*Hallazgos.*\*\*", re.IGNORECASE),
    "COMENTARIO_NUM": re.compile(r"//\s*\d+\.\s*[A-Z_]+", re.IGNORECASE),
    "FIXME":          re.compile(r"//\s*FIXME:?.*", re.IGNORECASE),
    "COMENTARIO":     re.compile(r"//.+")
}

descripciones_patrones_especiales = {
    "EXEC_SQL":       "Instrucción de SQL embebido. **Revisar por riesgo de inyección de SQL.**",
    "END_EXEC":       "Fin de la instrucción de SQL embebido.",
    "CALL":           "Llamada directa a programa/comando. **Evaluar si el programa/comando es sensible.**",
    "DUMP":           "Instrucción de volcado de memoria/datos (DUMP). Típicamente usado para depuración; debe ser removido de producción.",
    "CHGJOB":         "Comando Change Job (CHGJOB). **Puede alterar la configuración de seguridad o debug del trabajo.**",
    "DEBUG":          "Comando o directiva de Debug. **Riesgo si queda activo en producción.**",
    "DSPJOB":         "Comando Display Job (DSPJOB). Muestra información potencialmente sensible del trabajo.",
    "WRKSPLF":        "Comando Work with Spooled Files (WRKSPLF). Acceso a archivos temporales o de impresión.",
    "HALLAZGO":       "Etiqueta de encabezado que marca una sección de hallazgos en los comentarios.",
    "COMENTARIO_NUM": "Comentario que simula una numeración de hallazgos.",
    "FIXME":          "Nota de desarrollo (FIXME). Indica código pendiente de corrección o revisión de seguridad.",
    "COMENTARIO":     "Línea clasificada como comentario simple."
}

# ======================================================================
#                        FUNCIONES AUXILIARES
# ======================================================================

def detectar_encoding(ruta_archivo):
    """
    Detecta la codificación del archivo.
    """
    if not CHARDET_DISPONIBLE:
        return 'utf-8', 0.0
    
    try:
        with open(ruta_archivo, 'rb') as f:
            raw_data = f.read()
            result = chardet.detect(raw_data)
            return result.get('encoding', 'utf-8'), result.get('confidence', 0.0)
    except Exception:
        return 'utf-8', 0.0

def formatear_tamano(bytes_size):
    """
    Formatea el tamaño en bytes a una representación legible.
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_size < 1024.0:
            return f"{bytes_size:.1f} {unit}"
        bytes_size /= 1024.0
    return f"{bytes_size:.1f} PB"

def obtener_hash_archivo(ruta_archivo):
    """Calcula el hash SHA-256 de un archivo para verificar su integridad."""
    sha256_hash = hashlib.sha256()
    try:
        with open(ruta_archivo, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except FileNotFoundError:
        return "No disponible"

def contar_lineas_archivo(ruta_archivo, encoding='utf-8'):
    """
    Cuenta líneas del archivo con diferentes métricas.
    """
    try:
        with open(ruta_archivo, 'r', encoding=encoding) as f:
            lineas = f.readlines()
            total_lineas = len(lineas)
            lineas_vacias = sum(1 for linea in lineas if not linea.strip())
            lineas_con_contenido = total_lineas - lineas_vacias
            lineas_comentarios = sum(1 for linea in lineas if linea.strip().startswith(('*', '//', '#')))
            
        return {
            'total': total_lineas,
            'vacias': lineas_vacias,
            'con_contenido': lineas_con_contenido,
            'comentarios': lineas_comentarios
        }
    except Exception:
        return {
            'total': 'No disponible',
            'vacias': 'No disponible', 
            'con_contenido': 'No disponible',
            'comentarios': 'No disponible'
        }

def obtener_info_archivo_basica(ruta_archivo):
    """
    Obtiene información básica del archivo para archivos DESCONOCIDO.
    """
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
def clasificar_lineas_no_analizadas(analisis_por_bloque, no_analizadas_por_bloque):
    """
    Aplica clasificación secundaria (patrones especiales) a las líneas no analizadas
    por el parser principal e integra los resultados en la estructura principal.
    """
    for seccion, lista_lineas in no_analizadas_por_bloque.items():
        for numlinea, linealimpia in lista_lineas:
            tipos_encontrados = detectar_patrones_especiales(linealimpia)
            
            if tipos_encontrados:
                # FILTRO CRÍTICO: Eliminar 'COMENTARIO' si existe otra etiqueta más específica.
                if 'COMENTARIO' in tipos_encontrados and len(tipos_encontrados) > 1:
                    tipos_encontrados.remove('COMENTARIO')
                    
                # Crea la descripción detallada
                descripciones_detalladas = []
                for tipo in tipos_encontrados:
                    # NOTA: descripciones_patrones_especiales debe ser un diccionario global o accesible.
                    detalle = descripciones_patrones_especiales.get(tipo, f"Patrón '{tipo}' detectado")
                    descripciones_detalladas.append(f"{tipo}: {detalle}")
                descripcion = ' | '.join(descripciones_detalladas)
            else:
                descripcion = 'Línea no reconocida'
            
            if seccion not in analisis_por_bloque:
                analisis_por_bloque[seccion] = []
            
            # Añadimos la línea clasificada a la estructura de resultados principal
            analisis_por_bloque[seccion].append((
                numlinea,
                linealimpia,
                descripcion,
                None 
            ))
    
    # Después de procesar, vaciar el diccionario original y ordenar
    # (Lo moveremos a la función principal para mantener la claridad)
    pass
# ======================================================================
#                        FUNCIONES DE DETECCIÓN
# ======================================================================

def detectar_tipo_archivo(codigo_lineas):
    """
    Detecta si es un archivo CL, PF o RPG basándose en el contenido.
    """
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
    
    # Patrones específicos de archivos RPG
    patrones_rpg = [
        re.compile(r'^\s*[HFDICOPPR]\s+.*', re.IGNORECASE),  # Especificaciones RPG
        re.compile(r'^\s*D\s+\w+\s+DS\s+', re.IGNORECASE),  # Data Structure
        re.compile(r'^\s*D\s+\w+\s+PR\s+', re.IGNORECASE),  # Procedure Prototype  
        re.compile(r'^\s*P\s+\w+\s+B\s+', re.IGNORECASE),   # Procedure Begin
        re.compile(r'^\s*C\s+(?:EVAL|IF|DOW|DOU|FOR|SELECT|CHAIN|READ|WRITE)\s+', re.IGNORECASE),
        re.compile(r'^\s*/copy\s+', re.IGNORECASE),          # Copy statements
        re.compile(r'^\s*/free\s*$', re.IGNORECASE),         # Free format
        re.compile(r'^\s*/end-free\s*$', re.IGNORECASE),     # End free format
    ]
    
    puntos_pf = 0
    puntos_clp = 0
    puntos_rpg = 0
    
    for linea in codigo_lineas[:100]:
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
# Función para detectar patrones especiales en una línea
def detectar_patrones_especiales(linea):
    tipos = []
    for nombre, patron in patrones_especiales.items():
        if patron.search(linea):
            tipos.append(nombre)
    return tipos
    
def detectar_tipo_archivo_avanzado(codigo_lineas, ruta_archivo):
    """
    Versión avanzada que combina análisis de contenido con heurísticas adicionales.
    """
    tipo_detectado = detectar_tipo_archivo(codigo_lineas)
    
    if tipo_detectado == 'DESCONOCIDO':
        # Heurísticas adicionales
        lineas_con_posiciones = 0
        lineas_con_especificaciones = 0
        
        for linea in codigo_lineas[:50]:
            linea_limpia = linea.strip()
            if not linea_limpia:
                continue
            
            # Buscar patrones de posición (típico de PF)
            if re.search(r'\s+\d{1,3}\s+[APSBFLTZHGO]\s*\d*', linea_limpia, re.IGNORECASE):
                lineas_con_posiciones += 1
            
            # Buscar especificaciones RPG
            if re.search(r'^\s*[HFDICO]\s+', linea_limpia, re.IGNORECASE):
                lineas_con_especificaciones += 1
        
        if lineas_con_posiciones >= 2:
            return 'PF'
        elif lineas_con_especificaciones >= 2:
            return 'RPG'
    
    return tipo_detectado

# ======================================================================
#                        FUNCIONES DE ANÁLISIS
# ======================================================================

def analizar_archivo_cl(codigo_lineas):
    """
    Analiza específicamente archivos Control Language (CL).
    """
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
    """
    Analiza específicamente archivos Physical File (PF).
    """
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
    Analiza específicamente archivos RPG.
    """
    patron_especificacion = re.compile(r'^\s*(?P<tipo>[HFDICOPPR])\s+(?P<contenido>.*)', re.IGNORECASE)
    patron_calc_libre = re.compile(r'^\s*(?P<comando>EVAL|IF|ELSE|ENDIF|DOW|DOU|ENDDO|FOR|ENDFOR|SELECT|WHEN|OTHER|ENDSL|CHAIN|READ|WRITE|UPDATE|DELETE|OPEN|CLOSE|MONITOR|ON-ERROR|ENDMON)\s+(?P<contenido>.*)', re.IGNORECASE)
    patron_copy = re.compile(r'^\s*/copy\s+(?P<archivo>.*)', re.IGNORECASE)
    patron_free = re.compile(r'^\s*/(?P<comando>free|end-free)\s*$', re.IGNORECASE)
    patron_funciones_rpg = re.compile(r'.*(%SUBST|%SIZE|%TRIM|%SCAN|%CHECK|%XLATE)\s*\(', re.IGNORECASE)
 
    resultados_por_bloque = {'ESPECIFICACIONES': [], 'CALCULOS': [], 'COPIAS': []}
    lineas_no_analizadas_por_bloque = {'ESPECIFICACIONES': [], 'CALCULOS': [], 'COPIAS': []}
    elementos_definidos = {}
    estadisticas_elementos = Counter()
    comentarios_encontrados = []
    comentarios_por_bloque = {}
    
    en_free_format = False
    
    for num_linea, linea in enumerate(codigo_lineas, 1):
        linea_limpia = linea.strip()
        
        if not linea_limpia or linea_limpia.startswith('*'):
            if linea_limpia.startswith('*'):
                comentarios_encontrados.append((num_linea, linea_limpia[1:].strip()))
            continue
        
        linea_procesada = False
        
        # Free format
        match_free = patron_free.match(linea_limpia)
        if match_free:
            comando = match_free.group('comando').upper()
            if comando == 'FREE':
                en_free_format = True
                descripcion = "Inicia formato libre de RPG"
            else:
                en_free_format = False
                descripcion = "Finaliza formato libre de RPG"
            
            resultados_por_bloque['ESPECIFICACIONES'].append((num_linea, linea_limpia, descripcion, None))
            estadisticas_elementos['FREE_FORMAT'] += 1
            linea_procesada = True
        
        # Copy statements  
        if not linea_procesada:
            match_copy = patron_copy.match(linea_limpia)
            if match_copy:
                archivo = match_copy.group('archivo')
                descripcion = f"Incluye el archivo **{archivo}**"
                resultados_por_bloque['COPIAS'].append((num_linea, linea_limpia, descripcion, None))
                estadisticas_elementos['COPY'] += 1
                linea_procesada = True
        
        # Especificaciones RPG
        if not linea_procesada:
            match_esp = patron_especificacion.match(linea_limpia)
            if match_esp:
                tipo = match_esp.group('tipo').upper()
                contenido = match_esp.group('contenido')
                
                descripcion_base = descripciones_comandos_rpg.get(tipo, f'Especificación {tipo}')
                if len(contenido) > 30:
                    descripcion = f"{descripcion_base}: **{contenido[:30]}...**"
                else:
                    descripcion = f"{descripcion_base}: **{contenido}**"
                
                resultados_por_bloque['ESPECIFICACIONES'].append((num_linea, linea_limpia, descripcion, None))
                estadisticas_elementos[f'SPEC_{tipo}'] += 1
                linea_procesada = True
        
        # Cálculos en formato libre
        if not linea_procesada and en_free_format:
            match_calc = patron_calc_libre.match(linea_limpia)
            if match_calc:
                comando = match_calc.group('comando').upper()
                contenido = match_calc.group('contenido')
                
                descripcion_cmd = descripciones_comandos_rpg.get(comando, f'Comando RPG {comando}')
                if len(contenido) > 30:
                    descripcion = f"{descripcion_cmd}: **{contenido[:30]}...**"
                else:
                    descripcion = f"{descripcion_cmd}: **{contenido}**"
                
                resultados_por_bloque['CALCULOS'].append((num_linea, linea_limpia, descripcion, None))
                estadisticas_elementos[comando] += 1
                linea_procesada = True
        
        if not linea_procesada:
            # Determinar en qué bloque poner las líneas no analizadas
            if linea_limpia.startswith(('/copy', '/free', '/end-free')):
                lineas_no_analizadas_por_bloque['COPIAS'].append((num_linea, linea_limpia))
            elif en_free_format:
                lineas_no_analizadas_por_bloque['CALCULOS'].append((num_linea, linea_limpia))
            else:
                lineas_no_analizadas_por_bloque['ESPECIFICACIONES'].append((num_linea, linea_limpia))
    
    return resultados_por_bloque, lineas_no_analizadas_por_bloque, elementos_definidos, estadisticas_elementos, comentarios_encontrados, comentarios_por_bloque

# ======================================================================
#                        FUNCIONES DE ESCRITURA DE REPORTES
# ======================================================================

def escribir_reporte_desconocido(f_salida, ruta_archivo):
    """
    Escribe un reporte básico para archivos de tipo DESCONOCIDO.
    """
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

def _preparar_datos_archivos(archivos_encontrados, ruta_carpeta):
    """
    Recorre todos los archivos, calcula estadísticas (tipo, líneas, hash, tamaño) 
    y organiza los datos por carpeta.
    Retorna: archivos_por_carpeta, extensiones, tipos_detectados, lista_detalles
    """
    archivos_por_carpeta = {}
    extensiones = {}
    tipos_detectados = {'CL': 0, 'PF': 0, 'RPG': 0, 'DESCONOCIDO': 0}
    lista_detalles = [] # Almacena todos los detalles calculados

    for ruta_archivo in archivos_encontrados:
        try:
            nombre_archivo = os.path.basename(ruta_archivo)
            extension = os.path.splitext(nombre_archivo)[1].lower() or 'sin extensión'
            
            # Detección de tipo, líneas y hash (asumiendo helpers externos)
            with open(ruta_archivo, 'r', encoding='utf-8') as f:
                codigo_lineas = f.readlines()
                
            # NOTA: Las funciones 'detectar_tipo_archivo_avanzado' y 'obtener_hash_archivo' 
            # se asumen definidas en otra parte de tu script.
            tipo_archivo = detectar_tipo_archivo_avanzado(codigo_lineas, ruta_archivo) 
            tipos_detectados[tipo_archivo] += 1
            num_lineas = len(codigo_lineas)
            hash_completo = obtener_hash_archivo(ruta_archivo) 
            size_bytes = os.path.getsize(ruta_archivo)

            # Formatear tamaño
            if size_bytes >= 1024 * 1024:
                size_str = f"{size_bytes / (1024 * 1024):.2f} MB"
            elif size_bytes >= 1024:
                size_str = f"{size_bytes / 1024:.2f} KB"
            else:
                size_str = f"{size_bytes} bytes"

            # Agrupar por carpeta y contar extensión
            carpeta_relativa = os.path.relpath(os.path.dirname(ruta_archivo), ruta_carpeta)
            carpeta_relativa = 'RAÍZ' if carpeta_relativa == '.' else carpeta_relativa
            
            archivos_por_carpeta.setdefault(carpeta_relativa, []).append(ruta_archivo)
            extensiones[extension] = extensiones.get(extension, 0) + 1

            # Almacenar detalles
            lista_detalles.append({
                'ruta': ruta_archivo, 'carpeta': carpeta_relativa, 'nombre': nombre_archivo,
                'extension': extension, 'tipo': tipo_archivo, 'lineas': num_lineas,
                'hash': hash_completo, 'size_str': size_str,
            })

        except Exception as e:
            # Manejo de error para el archivo actual
            lista_detalles.append({
                'ruta': ruta_archivo, 'carpeta': 'ERROR_PROCESS', 'nombre': os.path.basename(ruta_archivo),
                'extension': 'ERROR', 'tipo': 'ERROR', 'lineas': 'ERROR',
                'hash': f'ERROR: {str(e)}', 'size_str': 'ERROR',
            })

    return archivos_por_carpeta, extensiones, tipos_detectados, lista_detalles
def _escribir_seccion_resumen(f_header, total_archivos, extensiones, tipos_detectados):
    """Escribe las tablas de resumen por extensiones y tipos."""

    # Resumen de extensiones
    f_header.write("\n## 📊 RESUMEN POR EXTENSIONES\n")
    f_header.write("-" * 40 + "\n")
    for ext, count in sorted(extensiones.items(), key=lambda x: x[1], reverse=True):
        porcentaje = (count / total_archivos) * 100
        f_header.write(f"  {ext:<15}: {count:>3} archivos ({porcentaje:5.1f}%)\n")
    
    # Resumen por tipo detectado
    f_header.write("\n## 🔍 RESUMEN POR TIPO DETECTADO\n")
    f_header.write("-" * 40 + "\n")
    for tipo, cantidad in sorted(tipos_detectados.items(), key=lambda x: x[1], reverse=True):
        if cantidad > 0:
            porcentaje = (cantidad / total_archivos) * 100
            f_header.write(f"  {tipo:<15}: {cantidad:>3} archivos ({porcentaje:5.1f}%)\n")
def _escribir_seccion_archivos(f_header, lista_detalles):
    """Escribe la sección detallada de archivos y sus propiedades, agrupados por carpeta."""
    f_header.write("## 📁 ESTRUCTURA DE CARPETAS Y ARCHIVOS\n")
    f_header.write("-" * 120 + "\n")
    
    # Agrupar detalles por carpeta para mantener la estructura en la escritura
    detalles_por_carpeta = {}
    for detalle in lista_detalles:
        detalles_por_carpeta.setdefault(detalle['carpeta'], []).append(detalle)

    for carpeta in sorted(detalles_por_carpeta.keys()):
        archivos = detalles_por_carpeta[carpeta]
        f_header.write(f"### 📂 {carpeta} ({len(archivos)} archivos)\n\n")
        
        # Ordenar archivos dentro de la carpeta
        for detalle in sorted(archivos, key=lambda x: x['nombre']):
            f_header.write(f"  #### 📄 {detalle['nombre']}\n")
            f_header.write(f"    - **Ruta completa:** {detalle['ruta']}\n")
            f_header.write(f"    - **Extensión:** {detalle['extension']}\n")
            f_header.write(f"    - **Tipo detectado:** {detalle['tipo']}\n")
            
            # Formato de líneas con separador de miles si es un número
            lineas_str = f"{detalle['lineas']:,}" if isinstance(detalle['lineas'], int) else detalle['lineas']
            f_header.write(f"    - **Líneas:** {lineas_str}\n")
            
            f_header.write(f"    - **Tamaño:** {detalle['size_str']}\n")
            f_header.write(f"    - **SHA-256 Hash:** {detalle['hash']}\n")
            f_header.write("\n")
            
        f_header.write("-" * 80 + "\n")            
# ======================================================================
#                        FUNCIONES DE GESTIÓN DE ARCHIVOS
# ======================================================================
def generar_nombre_salida(nombre_base, tipo_archivo, sufijo_analisis, sufijo_modo, ruta_salida, incluir_carpeta_reporte=True):
    """
    Genera un nombre de archivo de salida único.
    Si incluir_carpeta_reporte es True, lo guarda en la subcarpeta 'Reporte/'.
    """
    
    # CORRECCIÓN DE ERROR CRÍTICO: Se llama correctamente a datetime.now()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S") 

    # 1. Construir el nombre del archivo (sin ruta aún)
    nombre_final = f"{nombre_base}_{tipo_archivo}_{sufijo_analisis}_{sufijo_modo}_{timestamp}.txt"
    
    # 2. Determinar el directorio final
    if incluir_carpeta_reporte:
        # Los reportes individuales van en [ruta_salida]/Reporte/
        ruta_directorio_final = os.path.join(ruta_salida, CARPETA_REPORTE)
        
        # Asegurar que el directorio 'Reporte' exista
        if not os.path.exists(ruta_directorio_final):
            try:
                os.makedirs(ruta_directorio_final, exist_ok=True)
            except OSError as e:
                print(f"🚨 Error al crear el directorio de reportes '{ruta_directorio_final}': {e}")
                # Si falla la creación, revertimos a la ruta base para no fallar el script.
                ruta_directorio_final = ruta_salida 
    else:
        # El Reporte de Encabezado (Header) se queda en la ruta_salida
        ruta_directorio_final = ruta_salida 
        
    # 3. Combinar la ruta del directorio con el nombre del archivo
    ruta_completa_salida = os.path.join(ruta_directorio_final, nombre_final)

    return ruta_completa_salida

def obtener_ruta_salida(opcion_ruta):
    """Obtiene o crea la ruta de salida basada en la opción del usuario."""
    if opcion_ruta == '1':
        return os.getcwd()
    elif opcion_ruta == '2':
        fecha_hora = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        ruta_salida = os.path.join(os.getcwd(), f"salida_{fecha_hora}")
        if not os.path.exists(ruta_salida):
            os.makedirs(ruta_salida)
            print(f"✅ Se ha creado la carpeta de salida: '{ruta_salida}'")
        return ruta_salida
    else:
        return None
def procesar_archivo_individual(ruta_archivo, archivo_salida, tipo_archivo):
    """Procesa un archivo y escribe el análisis según su tipo."""
    try:
        # Para archivos DESCONOCIDO, usar el nuevo reporte básico
        if tipo_archivo == 'DESCONOCIDO':
            with open(archivo_salida, 'w', encoding='utf-8') as f_salida:
                escribir_reporte_desconocido(f_salida, ruta_archivo)
            print(f"✅ Análisis básico completado. Resultados guardados en '{archivo_salida}'.")
            return
        
        # Para archivos conocidos, usar el análisis completo
        with open(ruta_archivo, 'r', encoding='utf-8') as f_entrada:
            codigo_lineas = f_entrada.readlines()
        
        # Seleccionar función de análisis según el tipo
        if tipo_archivo == 'PF':
            analisis_resultado = analizar_archivo_pf(codigo_lineas)
            analisis_por_bloque, no_analizadas_por_bloque, elementos, estadisticas, comentarios_encontrados, comentarios_por_bloque = analisis_resultado[:6]
            registros_definidos = analisis_resultado[6] if len(analisis_resultado) > 6 else {}
            claves_definidas = analisis_resultado[7] if len(analisis_resultado) > 7 else []

            # === CLASIFICACIÓN SECUNDARIA ===
            clasificar_lineas_no_analizadas(analisis_por_bloque, no_analizadas_por_bloque)
            # ==============================
            
            # Ajustes finales de reporte
            no_analizadas_por_bloque = {} 
            for seccion in analisis_por_bloque:
                analisis_por_bloque[seccion].sort(key=lambda x: x[0])
            
            with open(archivo_salida, 'w', encoding='utf-8') as f_salida:
                escribir_reporte_pf(f_salida, ruta_archivo, analisis_por_bloque, no_analizadas_por_bloque, 
                                    elementos, estadisticas, comentarios_encontrados, comentarios_por_bloque,
                                    registros_definidos, claves_definidas)
                                    
        elif tipo_archivo == 'RPG':
            analisis_por_bloque, no_analizadas_por_bloque, elementos, estadisticas, comentarios_encontrados, comentarios_por_bloque = analizar_archivo_rpg(codigo_lineas)
            
            # === CLASIFICACIÓN SECUNDARIA ===
            clasificar_lineas_no_analizadas(analisis_por_bloque, no_analizadas_por_bloque)
            # ==============================
            
            # Ajustes finales de reporte
            no_analizadas_por_bloque = {} 
            for seccion in analisis_por_bloque:
                analisis_por_bloque[seccion].sort(key=lambda x: x[0])

            with open(archivo_salida, 'w', encoding='utf-8') as f_salida:
                escribir_reporte_rpg(f_salida, ruta_archivo, analisis_por_bloque, no_analizadas_por_bloque, 
                                     elementos, estadisticas, comentarios_encontrados, comentarios_por_bloque)
                                        
        else:  # CL
            analisis_por_bloque, no_analizadas_por_bloque, variables, estadisticas, comentarios_encontrados, comentarios_por_bloque = analizar_archivo_cl(codigo_lineas)
            
            # === CLASIFICACIÓN SECUNDARIA ===
            clasificar_lineas_no_analizadas(analisis_por_bloque, no_analizadas_por_bloque)
            # ==============================

            # Ajustes finales de reporte
            no_analizadas_por_bloque = {} 
            for seccion in analisis_por_bloque:
                analisis_por_bloque[seccion].sort(key=lambda x: x[0])

            with open(archivo_salida, 'w', encoding='utf-8') as f_salida:
                escribir_reporte_cl(f_salida, ruta_archivo, analisis_por_bloque, no_analizadas_por_bloque, 
                                     variables, estadisticas, comentarios_encontrados, comentarios_por_bloque)
        
        print(f"✅ Análisis completado. Resultados guardados en '{archivo_salida}'.")
        
    except FileNotFoundError:
        print(f"🚨 Error: El archivo '{ruta_archivo}' no se encontró.")
    except Exception as e:
        print(f"🚨 Ocurrió un error inesperado al procesar '{ruta_archivo}': {e}")
def generar_header_carpeta_recursivo(ruta_carpeta, ruta_salida, archivos_encontrados):
    """
    [CORRECCIÓN FINAL DE RUTA] Genera un header completo con análisis RECURSIVO.
    Ahora incluye la subcarpeta 'Reporte/' para agruparlo con los reportes individuales.
    """
    try:
        # 1. GENERAR NOMBRE DEL ARCHIVO (Ruta corregida para incluir 'Reporte/')
        nombre_header = generar_nombre_salida(
            nombre_base="HEADER_analisis_recursivo", 
            tipo_archivo="SUM", 
            sufijo_analisis="RECURSIVO", 
            sufijo_modo="GLOBAL", 
            ruta_salida=ruta_salida, 
            incluir_carpeta_reporte=True # <--- ¡CLAVE! CAMBIO a True
        )

        print(f"📋 Generando header de análisis recursivo...")

        # 2. PREPARAR LOS DATOS DE TODOS LOS ARCHIVOS (Se asume que esta lógica funciona)
        archivos_por_carpeta, extensiones, tipos_detectados, lista_detalles = \
            _preparar_datos_archivos(archivos_encontrados, ruta_carpeta)
        
        total_archivos = len(archivos_encontrados)

        # 3. ESCRIBIR EL ARCHIVO (Lógica de escritura no necesita cambios)
        with open(nombre_header, 'w', encoding='utf-8') as f_header:
            
            # --- Encabezado Estático ---
            f_header.write("=" * 120 + "\n")
            f_header.write("                           ANÁLISIS RECURSIVO DE CARPETA - HEADER COMPLETO\n")
            f_header.write("=" * 120 + "\n")
            f_header.write(f"📂 Carpeta analizada: {os.path.abspath(ruta_carpeta)}\n")
            f_header.write(f"🕒 Fecha y hora: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f_header.write(f"📊 Total de archivos encontrados (recursivo): {total_archivos}\n")
            f_header.write("=" * 120 + "\n\n")

            # --- Sección Detallada de Archivos ---
            _escribir_seccion_archivos(f_header, lista_detalles)
            
            # --- Sección de Resumen (Estadísticas) ---
            _escribir_seccion_resumen(f_header, total_archivos, extensiones, tipos_detectados)
            
            # --- Pie de página ---
            f_header.write("\n" + "=" * 120 + "\n")
            f_header.write("                                    FIN DEL HEADER RECURSIVO\n")
            f_header.write("=" * 120 + "\n")
        
        print(f"✅ Header recursivo generado: '{nombre_header}'")
        return nombre_header
        
    except Exception as e:
        print(f"🚨 Error generando header recursivo: {e}")
        return None

# ======================================================================
#                          FUNCIÓN PRINCIPAL
# ======================================================================

def main():
    parser = argparse.ArgumentParser(description="Analizador de comandos RPG/CL/PF para archivos o carpetas.")
    grupo = parser.add_mutually_exclusive_group(required=True)
    grupo.add_argument('-a', '--archivo', type=str, help='Ruta del archivo a analizar.')
    grupo.add_argument('-f', '--carpeta', type=str, help='Ruta de la carpeta a analizar.')
    parser.add_argument('-o', '--salida', type=str, help='Nombre del archivo de salida.')
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("     ANALIZADOR DE CÓDIGO IBM RPG/CL/PF v4.1.1")
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
        # Análisis de archivo individual
        ruta_absoluta = os.path.abspath(args.archivo)
        
        try:
            with open(ruta_absoluta, 'r', encoding='utf-8') as f:
                codigo_lineas = f.readlines()
            
            tipo_archivo = detectar_tipo_archivo_avanzado(codigo_lineas, ruta_absoluta)
            
            extension = os.path.splitext(ruta_absoluta)[1]
            print(f"\n📄 Archivo: {os.path.basename(ruta_absoluta)} (extensión: {extension or 'sin extensión'})")
            print(f"🔍 Tipo detectado por contenido: {tipo_archivo}")
            print(f"📏 Número de líneas: {len(codigo_lineas)}")
            
            if tipo_archivo == 'DESCONOCIDO':
                print("⚠️  Tipo desconocido. Se generará solo información básica del archivo.")
                
        except Exception as e:
            print(f"🚨 Error al detectar tipo de archivo: {e}")
            return
        
        nombre_base_salida = args.salida or os.path.splitext(os.path.basename(args.archivo))[0]
        nombre_salida = generar_nombre_salida(nombre_base_salida, tipo_archivo, "detallado", "individual", ruta_salida)
        
        procesar_archivo_individual(ruta_absoluta, nombre_salida, tipo_archivo)
        
    elif args.carpeta:
        # ANÁLISIS RECURSIVO DE CARPETA
        print(f"\n🔍 Analizando carpeta recursivamente: {os.path.abspath(args.carpeta)}")
        
        # BUSCAR ARCHIVOS RECURSIVAMENTE EN TODAS LAS SUBCARPETAS
        archivos_encontrados = []
        for raiz, dirs, files in os.walk(args.carpeta):
            for archivo in files:
                ruta_completa = os.path.join(raiz, archivo)
                archivos_encontrados.append(ruta_completa)
        
        if not archivos_encontrados:
            print(f"❌ No se encontraron archivos en la carpeta '{args.carpeta}' ni en sus subcarpetas.")
            return
        
        print(f"📁 Se encontraron {len(archivos_encontrados)} archivos en total")
        
        # Generar header de análisis RECURSIVO
        generar_header_carpeta_recursivo(args.carpeta, ruta_salida, archivos_encontrados)
        
        # Procesar archivos individualmente
        try:
            tipos_detectados = {'CL': 0, 'PF': 0, 'RPG': 0, 'DESCONOCIDO': 0}
            archivos_procesados = 0
            total_lineas = 0
            
            print(f"\n📋 Procesando {len(archivos_encontrados)} archivos...")
            
            for ruta_archivo in archivos_encontrados:
                nombre_archivo = os.path.basename(ruta_archivo)
                carpeta_relativa = os.path.relpath(os.path.dirname(ruta_archivo), args.carpeta)
                
                try:
                    with open(ruta_archivo, 'r', encoding='utf-8') as f:
                        codigo_lineas = f.readlines()
                    
                    tipo_archivo = detectar_tipo_archivo_avanzado(codigo_lineas, ruta_archivo)
                    tipos_detectados[tipo_archivo] += 1
                    num_lineas = len(codigo_lineas)
                    total_lineas += num_lineas
                    
                    extension = os.path.splitext(nombre_archivo)[1]
                    if carpeta_relativa != '.':
                        print(f"📄 {carpeta_relativa}/{nombre_archivo} ({extension or 'sin ext'}) -> {tipo_archivo} ({num_lineas} líneas)")
                    else:
                        print(f"📄 {nombre_archivo} ({extension or 'sin ext'}) -> {tipo_archivo} ({num_lineas} líneas)")
                    
                    # Generar nombre único para evitar sobreescritura
                    nombre_base = f"{carpeta_relativa.replace(os.sep, '_')}_{nombre_archivo}" if carpeta_relativa != '.' else nombre_archivo
                    nombre_salida = generar_nombre_salida(nombre_base, tipo_archivo, "detallado", "individual", ruta_salida)
                    procesar_archivo_individual(ruta_archivo, nombre_salida, tipo_archivo)
                    archivos_procesados += 1
                    
                except Exception as e:
                    print(f"🚨 Error procesando {nombre_archivo}: {e}")
            
            # Mostrar resumen final
            print(f"\n📊 RESUMEN DEL ANÁLISIS RECURSIVO:")
            print(f"  Archivos encontrados: {len(archivos_encontrados)}")
            print(f"  Archivos procesados: {archivos_procesados}")
            print(f"  Total de líneas procesadas: {total_lineas:,}")
            for tipo, cantidad in tipos_detectados.items():
                if cantidad > 0:
                    print(f"  {tipo}: {cantidad} archivo(s)")
            print(f"  Reportes guardados en: {ruta_salida}")
            
        except Exception as e:
            print(f"🚨 Error accediendo a la carpeta: {e}")

if __name__ == "__main__":
    main()
