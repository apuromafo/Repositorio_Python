#-------------------------------------------------------------------------------------------------
#    Convierte un archivo de texto de encabezados HTTP (obtenidos en burp por ejemplo) a un archivo JSON.
#
# Uso: python convert_headers.py <archivo_de_entrada.txt> <archivo_de_salida.json>
# Ejemplo: python convert_headers.py demo.txt demo.json
# Validación: Para validar el JSON generado, puedes usar otro script como 'cabeceras_de_seguridad.py -j demo.json'.
#
# Versión: 1.0
#-------------------------------------------------------------------------------------------------
# ==============================================================================
# --- HISTORIAL DE VERSIONES ---
# ==============================================================================
# v1.0.0 (2025-09-04) - [LANZAMIENTO]
#    ✅ Creación del script inicial.
#    ✅ Añadida la lógica para convertir cabeceras de texto a JSON.
#    ✅ Permite ingresar una URL o usar una por defecto.
#    ✅ Manejo de errores para archivos no encontrados.
#    ✅ Formato de salida JSON con sangría.
# ------------------------------------------------------------------------------
# v0.1.0 (2025-09-03) - [INICIO]
#    ✅ Prototipo inicial del script.
#    ❌ No maneja URLs ni errores de archivo.
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
        if len(parts) >= 2:
            try:
                status_code = int(parts[1])
            except ValueError:
                status_code = None
        else:
            status_code = None
    else:
        status_code = None

    # Analizar los encabezados
    for line in lines[1:]:
        line = line.strip()
        if not line:
            continue
        
        try:
            key, value = line.split(':', 1)
            key = key.strip()
            value = value.strip()
            if key in headers:
                if isinstance(headers[key], list):
                    headers[key].append(value)
                else:
                    headers[key] = [headers[key], value]
            else:
                headers[key] = value
        except ValueError:
            continue
    
    output_data = {
        "url": url,
        "status_code": status_code,
        "headers": headers
    }
    
    with open(output_file, 'w') as json_file:
        json.dump(output_data, json_file, indent=4)
    
    print(f"Éxito: Se ha creado el archivo '{output_file}' para su análisis.")

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Uso: python convert_headers.py <archivo_de_entrada.txt> <archivo_de_salida.json>")
    else:
        input_filename = sys.argv[1]
        output_filename = sys.argv[2]
        convert_to_json(input_filename, output_filename)