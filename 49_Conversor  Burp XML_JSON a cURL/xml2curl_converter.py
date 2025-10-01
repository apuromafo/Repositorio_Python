import sys
import xml.etree.ElementTree as ET
import json
import base64
import os
import re
import urllib.parse
from datetime import datetime
from collections import defaultdict
import argparse

# --- Configuración del Logging y Versión ---
VERSION = "v2.2.3"
import logging
logger = logging.getLogger("XML2cURL")
logger.setLevel(logging.INFO)
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter('[%(asctime)s] %(message)s', "%Y-%m-%d %H:%M:%S"))
logger.addHandler(console_handler)

BASE_OUTPUT_DIRECTORY = "output/curl"
HTTP_METHODS_ORDER = ["GET", "POST", "DELETE", "PUT", "PATCH", "OPTIONS", "HEAD", "TRACE", "CONNECT"]
IGNORED_HEADERS = ['host', 'content-length', 'user-agent', 'accept-encoding', 'connection', 'postman-token', 'cache-control', 'pragma', 'accept']

def sanitize_filename(name):
    """Sanitiza un string para que sea un nombre de archivo/directorio válido."""
    # Reemplaza cualquier carácter no alfanumérico (excepto '.') con un guion bajo.
    return re.sub(r'[^\w\.-]', '_', name)

def decode_body(body_text):
    """Decodifica un cuerpo de solicitud de Base64 si es necesario."""
    if not body_text:
        return ""
    try:
        decoded = base64.b64decode(body_text).decode("utf-8")
        if len(decoded) >= len(body_text) / 2:
            return decoded
    except Exception:
        return body_text

def extract_body_and_headers(text, base64_encoded):
    """Extrae las cabeceras y el cuerpo del request HTTP."""
    if not text:
        return {}, ""

    raw_text = decode_body(text) if base64_encoded else text
    parts = re.split(r'\r\n\r\n|\n\n', raw_text, maxsplit=1)
    
    headers_raw = parts[0]
    body_content = parts[1].strip() if len(parts) > 1 else ""
    
    headers = {}
    for line in headers_raw.splitlines():
        if ':' in line:
            k, v = line.split(':', 1)
            headers[k.strip()] = v.strip()
    
    return headers, body_content

def create_curl_command(req):
    """Crea un comando cURL a partir de una petición."""
    curl_parts = [f"curl -X {req['method']} '{req['url']}'"]
    for header_name, header_value in req['headers'].items():
        if header_name.lower() in IGNORED_HEADERS:
            continue
        curl_parts.append(f"-H '{header_name}: {header_value}'")

    if req['body']:
        content_type = req['headers'].get('Content-Type', '').lower()
        if 'application/json' in content_type:
            try:
                json_body = json.loads(req['body'])
                escaped_body = json.dumps(json_body, separators=(',', ':'))
                curl_parts.append(f"--data-raw '{escaped_body}'")
            except json.JSONDecodeError:
                logger.warning(f"Cuerpo JSON inválido. Se usará como texto plano.")
                curl_parts.append(f"--data-raw '{req['body']}'")
        elif 'application/x-www-form-urlencoded' in content_type:
            curl_parts.append(f"-d '{req['body']}'")
        else:
            curl_parts.append(f"--data-raw '{req['body']}'")

    return " \\\n  ".join(curl_parts)

def parse_xml_file(file_path):
    """Procesa el archivo XML y extrae las peticiones."""
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        requests_list = []
        for item in root.findall("item"):
            method = (item.findtext("method") or "GET").upper()
            url_str = item.findtext("url")
            
            if not url_str or method == "OPTIONS":
                continue
            
            try:
                url_parsed = urllib.parse.urlparse(url_str)
                host = url_parsed.netloc
            except (ValueError, IndexError):
                logger.warning(f"URL inválida, saltando: {url_str}")
                continue

            request_el = item.find("request")
            base64_encoded = request_el.get('base64', 'false').lower() == 'true'
            headers, body = extract_body_and_headers(request_el.text, base64_encoded)
            
            requests_list.append({
                "method": method,
                "url": url_str,
                "host": host,
                "headers": headers,
                "body": body
            })
        return requests_list
    except ET.ParseError as e:
        logger.error(f"Error al procesar el archivo XML: {e}")
        return None

def parse_json_file(file_path):
    """Procesa el archivo JSON (OpenAPI) y extrae las peticiones."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        requests_list = []
        base_url = data.get('servers', [{}])[0].get('url', '')
        
        for path, path_data in data.get('paths', {}).items():
            for method, method_data in path_data.items():
                if method.upper() in HTTP_METHODS_ORDER:
                    url_str = base_url + path
                    
                    try:
                        url_parsed = urllib.parse.urlparse(url_str)
                        host = url_parsed.netloc
                    except (ValueError, IndexError):
                        logger.warning(f"URL inválida, saltando: {url_str}")
                        continue

                    headers = {}
                    if 'parameters' in method_data:
                        for param in method_data['parameters']:
                            if param.get('in') == 'header':
                                headers[param.get('name')] = param.get('example', '')
                    
                    body = ''
                    if 'requestBody' in method_data:
                        content_type = next(iter(method_data['requestBody']['content']), None)
                        if content_type:
                            headers['Content-Type'] = content_type
                            if 'example' in method_data['requestBody']['content'][content_type]:
                                example_data = method_data['requestBody']['content'][content_type]['example']
                                if isinstance(example_data, (dict, list)):
                                    body = json.dumps(example_data)
                                else:
                                    body = str(example_data)

                    requests_list.append({
                        "method": method.upper(),
                        "url": url_str,
                        "host": host,
                        "headers": headers,
                        "body": body
                    })
        return requests_list
    except json.JSONDecodeError as e:
        logger.error(f"Error al procesar el archivo JSON: {e}")
        return None
    except IOError as e:
        logger.error(f"Error de E/S al leer el archivo JSON: {e}")
        return None

def output_option1_ordered(requests):
    """Opción 1: cURL numerados en orden de aparición."""
    output_dir = os.path.join(BASE_OUTPUT_DIRECTORY, "orden_aparicion")
    os.makedirs(output_dir, exist_ok=True)
    timestamp_str = datetime.now().strftime("%Y%m%d")
    for i, req in enumerate(requests, 1):
        curl_command = create_curl_command(req)
        output_filename = os.path.join(output_dir, f"Curl{i}_{req['method'].lower()}_{timestamp_str}.txt")
        with open(output_filename, "w", encoding="utf-8") as f:
            f.write(curl_command)
        logger.info(f"✅ Guardado: {output_filename}")

def output_option2_by_verb(requests):
    """Opción 2: cURL ordenados por verbo."""
    output_dir = os.path.join(BASE_OUTPUT_DIRECTORY, "por_verbo")
    os.makedirs(output_dir, exist_ok=True)
    timestamp_str = datetime.now().strftime("%Y%m%d")
    requests_by_verb = defaultdict(list)
    for req in requests:
        requests_by_verb[req['method'].lower()].append(req)
    
    for verb, reqs in requests_by_verb.items():
        verb_dir = os.path.join(output_dir, verb)
        os.makedirs(verb_dir, exist_ok=True)
        for i, req in enumerate(reqs, 1):
            curl_command = create_curl_command(req)
            output_filename = os.path.join(verb_dir, f"Curl{i}_{verb}_{timestamp_str}.txt")
            with open(output_filename, "w", encoding="utf-8") as f:
                f.write(curl_command)
            logger.info(f"✅ Guardado: {output_filename}")

def output_option3_by_host_verb(requests):
    """Opción 3: cURL ordenado por host y verbo."""
    output_dir = os.path.join(BASE_OUTPUT_DIRECTORY, "por_host_y_verbo")
    os.makedirs(output_dir, exist_ok=True)
    timestamp_str = datetime.now().strftime("%Y%m%d")
    counts_by_host_and_method = defaultdict(lambda: defaultdict(int))
    
    for req in requests:
        # Sanitizar el nombre del host para evitar caracteres inválidos en directorios.
        sanitized_host = sanitize_filename(req['host'])
        host_dir = os.path.join(output_dir, sanitized_host)
        verb_dir = os.path.join(host_dir, req['method'].lower())
        os.makedirs(verb_dir, exist_ok=True)
        
        counts_by_host_and_method[req['host']][req['method'].lower()] += 1
        curl_count = counts_by_host_and_method[req['host']][req['method'].lower()]
        
        output_filename = os.path.join(verb_dir, f"Curl{curl_count}_{req['method'].lower()}_{timestamp_str}.txt")
        curl_command = create_curl_command(req)
        with open(output_filename, "w", encoding="utf-8") as f:
            f.write(curl_command)
        logger.info(f"✅ Guardado: {output_filename}")

def output_option4_single_file(requests):
    """Opción 4: cURL todo en un solo archivo."""
    os.makedirs(BASE_OUTPUT_DIRECTORY, exist_ok=True)
    timestamp_str = datetime.now().strftime("%Y%m%d-%H%M%S")
    output_filename = os.path.join(BASE_OUTPUT_DIRECTORY, f"all_curls_{timestamp_str}.txt")
    
    with open(output_filename, "w", encoding="utf-8") as f:
        for i, req in enumerate(requests, 1):
            f.write(f"### REQUEST {i} - {req['method']} {req['url']}\n")
            f.write(create_curl_command(req) + "\n\n")
    logger.info(f"✅ Todos los comandos cURL guardados en un solo archivo: {output_filename}")

def get_file_type(file_path):
    """Determina el tipo de archivo (XML o JSON) basándose en su contenido."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read(4096).strip() # Lee los primeros 4KB
    except Exception as e:
        logger.error(f"Error al leer el archivo para la detección de tipo: {e}")
        return 'unsupported'

    # Detección de XML
    if content.startswith('<') and ('<items>' in content or '<item>' in content or '<?xml' in content):
        return 'xml'
    # Detección de JSON
    elif content.startswith('{') or content.startswith('['):
        return 'json'
    return 'unsupported'

def main():
    logger.info(f"=== Burp XML/JSON a cURL Converter - {VERSION} ===")
    
    parser = argparse.ArgumentParser(description="Convierte un archivo XML de Burp Suite o JSON de OpenAPI a comandos cURL.")
    parser.add_argument("-i", "--input", help="Ruta al archivo de entrada (XML o JSON).")
    parser.add_argument("-o", "--output", type=int, choices=[1, 2, 3, 4], help="Opción de salida (1-4).")
    args = parser.parse_args()

    input_file = args.input
    output_option = args.output
    
    # Modo interactivo si no hay argumentos
    if not input_file or not output_option:
        while not input_file:
            input_file = input("Ingrese la ruta al archivo de entrada (XML, .burp o JSON): ").strip()
            if not os.path.isfile(input_file):
                logger.error(f"Archivo no encontrado: {input_file}. Por favor, intente de nuevo.")
                input_file = None

        while not output_option:
            print("\nSeleccione la opción de salida:")
            print("1. cURL numerados en orden de aparición.")
            print("2. cURL ordenados por verbo.")
            print("3. cURL ordenado por host y verbo.")
            print("4. cURL todo en un solo archivo.")
            try:
                choice = int(input("Ingrese su opción (1-4): ").strip())
                if choice in [1, 2, 3, 4]:
                    output_option = choice
                else:
                    print("Opción inválida. Por favor, ingrese un número del 1 al 4.")
            except ValueError:
                print("Entrada inválida. Por favor, ingrese un número.")
    
    file_type = get_file_type(input_file)
    requests_data = None

    if file_type == 'xml':
        requests_data = parse_xml_file(input_file)
    elif file_type == 'json':
        requests_data = parse_json_file(input_file)
    else:
        logger.error("Formato de archivo no soportado o no reconocido por el contenido. Por favor, asegúrese de que el archivo es un XML o JSON válido.")
        return

    if not requests_data:
        logger.error("No se pudo procesar el archivo. Saliendo.")
        return

    logger.info(f"Se encontraron {len(requests_data)} peticiones para procesar.")

    if output_option == 1:
        output_option1_ordered(requests_data)
    elif output_option == 2:
        output_option2_by_verb(requests_data)
    elif output_option == 3:
        output_option3_by_host_verb(requests_data)
    elif output_option == 4:
        output_option4_single_file(requests_data)

    logger.info("Proceso finalizado exitosamente.")

if __name__ == "__main__":
    main()