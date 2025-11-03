#-------------------------------------------------------------------------------------------------
#   Convierte un archivo de texto de encabezados HTTP (obtenidos de una herramienta como Burp Suite o proxy)
#   a un archivo JSON para facilitar su posterior análisis de seguridad.
#
# Uso: python convert_headers.py <archivo_de_entrada.txt> <archivo_de_salida.json>
# Ejemplo: python convert_headers.py demo.txt demo.json
# Validación: Para validar el JSON generado, puedes usar otro script como 'cabeceras_de_seguridad.py -j demo.json'.
#
# Versión: 1.1
#-------------------------------------------------------------------------------------------------
# -------------------------------------------------------------------------------
# --- EJEMPLO DE ENTRADA (demo.txt) ---
# -------------------------------------------------------------------------------
# HTTP/1.1 200 OK
# Content-Type: text/html; charset=utf-8
# X-Frame-Options: SAMEORIGIN
# Server: Apache/2.4.1 (Unix)
# Set-Cookie: sessionid=abc123xyz; HttpOnly; Secure
# Set-Cookie: user_pref=darkmode; Secure
# Transfer-Encoding: chunked
#
# NOTA: La primera línea es la 'Línea de Estado'. Las líneas vacías al final se ignoran.
# -------------------------------------------------------------------------------
#
# ==============================================================================
# --- HISTORIAL DE VERSIONES ---
# ==============================================================================
# v1.1.0 (2025-11-03) - [MEJORA DE DOC]
#   ✅ Añadido ejemplo de archivo de entrada (headers.txt) al encabezado del script.
#   ✅ Documentación mejorada para mayor claridad.
# ------------------------------------------------------------------------------
# v1.0.0 (2025-09-04) - [LANZAMIENTO]
#   ✅ Creación del script inicial.
#   ✅ Añadida la lógica para convertir cabeceras de texto a JSON.
#   ✅ Permite ingresar una URL o usar una por defecto.
#   ✅ Manejo de errores para archivos no encontrados.
#   ✅ Formato de salida JSON con sangría.
# ------------------------------------------------------------------------------
# v0.1.0 (2025-09-03) - [INICIO]
#   ✅ Prototipo inicial del script.
#   ❌ No maneja URLs ni errores de archivo.
# ==============================================================================

import json
import sys

def convert_to_json(input_file, output_file):
    """
    Convierte un archivo de texto de encabezados HTTP a un archivo JSON.
    El JSON contendrá 'status_code', 'url' y 'headers'.
    """
    headers = {}
    status_line = ""

    # Preguntar al usuario por la URL, con un valor por defecto
    url = input("Por favor, ingrese la URL (o presione Enter para usar https://example.com): ").strip()
    if not url:
        url = "https://example.com"

    try:
        with open(input_file, 'r') as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"Error: El archivo '{input_file}' no fue encontrado.")
        return

    # Analizar la línea de estado
    if lines:
        status_line = lines[0].strip()
        parts = status_line.split(' ')
        # Se asume que la línea de estado tiene el formato: PROTOCOLO CÓDIGO_ESTADO MENSAJE
        if len(parts) >= 2:
            try:
                status_code = int(parts[1])
            except ValueError:
                status_code = None
                print(f"Advertencia: No se pudo parsear el código de estado de la línea: '{status_line}'")
        else:
            status_code = None
            print(f"Advertencia: Formato de línea de estado inesperado: '{status_line}'")
    else:
        status_code = None
        print("Advertencia: El archivo de entrada está vacío.")


    # Analizar los encabezados
    # Ignoramos la primera línea (línea de estado)
    for line in lines[1:]:
        line = line.strip()
        if not line:
            continue
        
        # Buscar el primer ':' para separar clave y valor
        try:
            key, value = line.split(':', 1)
            key = key.strip()
            value = value.strip()
            
            # Manejo de encabezados duplicados (como Set-Cookie)
            if key in headers:
                if isinstance(headers[key], list):
                    headers[key].append(value)
                else:
                    # Convierte el valor existente en una lista y añade el nuevo
                    headers[key] = [headers[key], value]
            else:
                headers[key] = value
        except ValueError:
            # Ignorar líneas que no tienen el formato 'Clave: Valor'
            print(f"Advertencia: Línea de encabezado ignorada por formato incorrecto: '{line}'")
            continue
    
    output_data = {
        "url": url,
        "status_code": status_code,
        "headers": headers
    }
    
    try:
        with open(output_file, 'w') as json_file:
            # El indent=4 facilita la lectura del JSON
            json.dump(output_data, json_file, indent=4)
        
        print(f"Éxito: Se ha creado el archivo '{output_file}' para su análisis.")
    except Exception as e:
        print(f"Error: No se pudo escribir en el archivo '{output_file}'. Detalles: {e}")

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Uso: python convert_headers.py <archivo_de_entrada.txt> <archivo_de_salida.json>")
        print("Ejemplo: python convert_headers.py demo.txt demo.json")
    else:
        input_filename = sys.argv[1]
        output_filename = sys.argv[2]
        convert_to_json(input_filename, output_filename)