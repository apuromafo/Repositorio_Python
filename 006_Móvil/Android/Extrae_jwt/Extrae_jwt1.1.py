# ==============================================================================
# --- HISTORIAL DE VERSIONES ---
# ==============================================================================
# v1.1.0 (2025-09-23) - [ESTABLE]
#   ✅ Añadido: Control de rutas absolutas para escanear archivos desde cualquier directorio.
#   ✅ Mejorado: Manejo de errores para rutas de archivo no encontradas.
#   ✅ Ajustado: Lógica para la creación de archivos de salida en el mismo directorio del archivo de entrada por defecto.
#
# v1.0.0 (2025-09-19) - [INICIO]
#   ✅ Prototipo inicial para extracción y decodificación de JWTs.
#   ✅ Funcionalidad básica para escanear archivos locales.
#   ❌ No maneja rutas relativas fuera del directorio de ejecución.
# ==============================================================================
import re
import json
import base64
import sys
import logging
import os
from datetime import datetime

# --- Configuración del Logging ---
# El formato incluye la fecha y hora para la auditoría en el archivo de log
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Handler para el archivo de log (FileHandler)
log_file_name = f"auditoria_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.log"
file_handler = logging.FileHandler(log_file_name, encoding='utf-8')
log_format = '%(asctime)s | %(levelname)s | %(message)s'
file_handler.setFormatter(logging.Formatter(log_format))
logger.addHandler(file_handler)

# Este logger es para la consola, solo muestra el mensaje
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(logging.Formatter('%(message)s'))
logger.addHandler(console_handler)

def decodificar_base64_url(data):
    """
    Decodifica una cadena Base64Url y retorna el resultado como un string JSON.
    Retorna None si la decodificación o el parsing JSON falla.
    """
    longitud_extra = len(data) % 4
    if longitud_extra > 0:
        data += '=' * (4 - longitud_extra)
    try:
        decodificado = base64.urlsafe_b64decode(data.encode('utf-8'))
        return json.loads(decodificado.decode('utf-8'))
    except Exception as e:
        logger.debug(f"Error decodificando Base64Url: {e}")
        return None

def procesar_archivo(archivo_entrada, archivo_salida):
    """
    Procesa un archivo en busca de JWTs, los decodifica y los guarda en un archivo de salida.
    """
    
    # Manejar las rutas de archivo de forma robusta
    ruta_absoluta_entrada = os.path.abspath(archivo_entrada)
    if not os.path.isabs(archivo_salida):
        directorio_entrada = os.path.dirname(ruta_absoluta_entrada)
        ruta_absoluta_salida = os.path.join(directorio_entrada, archivo_salida)
    else:
        ruta_absoluta_salida = archivo_salida

    if not os.path.exists(ruta_absoluta_entrada):
        logger.error(f"Error: El archivo de entrada '{ruta_absoluta_entrada}' no se encontró.")
        return

    logger.info(f"Iniciando el procesamiento del archivo de entrada: '{ruta_absoluta_entrada}'")
    logger.info(f"El archivo de salida se guardará en: '{ruta_absoluta_salida}'")
    
    try:
        with open(ruta_absoluta_entrada, 'r', encoding='utf-8') as f:
            contenido = f.read()
    except Exception as e:
        logger.error(f"Error al leer el archivo '{ruta_absoluta_entrada}': {e}")
        return

    # Expresión regular para encontrar JWTs
    patron_jwt = r'([A-Za-z0-9\-_~]+\.[A-Za-z0-9\-_~]+\.[A-Za-z0-9\-_~]+)'
    jwt_encontrados = re.findall(patron_jwt, contenido)
    salida_decodificada = []

    if not jwt_encontrados:
        logger.info("😔 No se encontraron cadenas con el formato de JWT en el archivo.")
        return

    logger.info(f"Se encontraron {len(jwt_encontrados)} posibles JWTs. Decodificando...")
    
    for i, token in enumerate(jwt_encontrados, 1):
        partes = token.split('.')
        if len(partes) != 3:
            logger.debug(f"Saltando el token {i} (formato incorrecto).")
            continue

        header_b64, payload_b64, firma = partes
        header = decodificar_base64_url(header_b64)
        payload = decodificar_base64_url(payload_b64)
        
        if header and payload:
            output_string = (
                f"=== JWT ENCONTRADO #{i} ===\n"
                f"Token: {token}\n"
                f"Header:\n{json.dumps(header, indent=2, ensure_ascii=False)}\n"
                f"Payload:\n{json.dumps(payload, indent=2, ensure_ascii=False)}\n"
                f"---\n"
            )
            print(output_string)
            salida_decodificada.append(output_string)
        else:
            logger.debug(f"Saltando el token {i} (no decodificable).")

    if salida_decodificada:
        try:
            with open(ruta_absoluta_salida, 'w', encoding='utf-8') as f:
                for item in salida_decodificada:
                    f.write(f"{item}\n")
            logger.info(f"✅ Proceso completado. Se extrajeron {len(salida_decodificada)} JWTs válidos.")
            logger.info(f"Contenido decodificado guardado en: '{ruta_absoluta_salida}'.")
        except IOError as e:
            logger.error(f"Error al escribir en el archivo '{ruta_absoluta_salida}': {e}")
    else:
        logger.info("😔 No se encontraron JWTs válidos y decodificables en el archivo.")

if __name__ == "__main__":
    VERSION = "v1.1.0"
    print(f"EXTRAE JWT SCRIPT - {VERSION}")

    if len(sys.argv) != 3:
        logger.error("Uso incorrecto del script. Debe proporcionar un archivo de entrada y un archivo de salida.")
        logger.error(f"Uso: python {os.path.basename(sys.argv[0])} <archivo_entrada.txt> <archivo_salida.txt>")
        sys.exit(1)
        
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    
    procesar_archivo(input_file, output_file)