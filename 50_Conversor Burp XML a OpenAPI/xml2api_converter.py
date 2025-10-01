import sys
import xml.etree.ElementTree as ET
import json
import base64
import re
import os
import urllib.parse
from datetime import datetime
import logging
from collections import defaultdict
import hashlib

# --- Configuración del Logging y Versión ---
VERSION = "v1.7.5"
logger = logging.getLogger("Burp2API")
logger.setLevel(logging.INFO)
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter('[%(asctime)s] %(message)s', "%Y-%m-%d %H:%M:%S"))
logger.addHandler(console_handler)

BASE_OUTPUT_DIRECTORY = "output"
HTTP_METHODS_ORDER = ["GET", "POST", "DELETE", "PUT", "PATCH", "OPTIONS", "HEAD", "TRACE", "CONNECT"]
IGNORED_HEADERS = [
    'host', 'content-length', 'user-agent', 'accept-encoding', 'accept-language',
    'cookie', 'connection', 'sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform',
    'upgrade-insecure-requests', 'postman-token', 'cache-control', 'pragma', 'accept', 'rut', 'origin'
]

def sanitize_filename(name, max_len=50):
    """Sanitiza un string para que sea un nombre de archivo/directorio válido y manejable."""
    sanitized = re.sub(r'[^\w\.-]', '_', name)
    if len(sanitized) > max_len:
        path_hash = hashlib.sha256(name.encode('utf-8')).hexdigest()[:8]
        return f"{sanitized[:max_len]}_{path_hash}"
    return sanitized

def decode_base64_url(data):
    """Decodifica una cadena Base64Url."""
    try:
        rem = len(data) % 4
        if rem > 0:
            data += "=" * (4 - rem)
        return base64.urlsafe_b64decode(data).decode("utf-8")
    except Exception as e:
        logger.debug(f"Error decodificando Base64Url: {e}")
        return None

def decode_jwt(token):
    """Decodifica un token JWT."""
    parts = token.split(".")
    if len(parts) != 3:
        return None, None
    header_b64, payload_b64, _ = parts
    header_json = decode_base64_url(header_b64)
    payload_json = decode_base64_url(payload_b64)
    try:
        header = json.loads(header_json) if header_json else None
        payload = json.loads(payload_json) if payload_json else None
        return header, payload
    except Exception as e:
        logger.debug(f"Error al decodificar JWT: {e}")
        return None, None

def decode_body(body_text):
    """Decodifica el cuerpo si está en Base64."""
    if not body_text:
        return ""
    try:
        decoded = base64.b64decode(body_text).decode("utf-8")
        if len(decoded) >= len(body_text) / 2:
            return decoded
    except Exception:
        pass
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
    for line in headers_raw.splitlines()[1:]:
        if ':' in line:
            k, v = line.split(':', 1)
            headers[k.strip().lower()] = v.strip()
    return headers, body_content

def is_json(text):
    """Verifica si un string es JSON válido."""
    try:
        json.loads(text)
        return True
    except (json.JSONDecodeError, TypeError):
        return False

def is_xml(text):
    """Verifica si un string es XML válido."""
    try:
        ET.fromstring(text)
        return True
    except ET.ParseError:
        return False

def parse_params_to_schema(params):
    """Convierte parámetros de URL a un esquema de OpenAPI."""
    schema_props = {}
    if not params:
        return schema_props
    for param in params.split('&'):
        if '=' in param:
            k, v = param.split('=', 1)
            k, v = k.strip(), v.strip()
            schema_props[k] = {"type": "string", "example": urllib.parse.unquote(v)}
        else:
            schema_props[param] = {"type": "string"}
    return schema_props

def dict_to_schema_props(d):
    """Convierte un diccionario a un esquema de propiedades de OpenAPI."""
    props = {}
    for k, v in d.items():
        if isinstance(v, dict):
            props[k] = {"type": "object", "example": v}
        elif isinstance(v, list):
            props[k] = {"type": "array", "example": v}
        elif isinstance(v, (int, float)):
            props[k] = {"type": "number", "example": v}
        elif isinstance(v, bool):
            props[k] = {"type": "boolean", "example": v}
        else:
            props[k] = {"type": "string", "example": str(v)}
    return props

def convert_to_openapi(items, base_url, tag_name=None):
    """
    Convierte una lista de ítems a un objeto OpenAPI.
    Modificado para manejar parámetros de consulta y path.
    """
    openapi_dict = {
        "paths": {},
        "components": {"securitySchemes": {}},
        "security": [],
        "servers": [{"url": base_url}]
    }
    
    bearer_token_example = None
    bearer_token_payload = None
    for item in items:
        request_el = item.find("request")
        if request_el is not None and request_el.text:
            base64_encoded = request_el.get('base64', 'false').lower() == 'true'
            headers, _ = extract_body_and_headers(request_el.text, base64_encoded)
            auth_header = headers.get("authorization")
            if auth_header and auth_header.startswith("bearer "):
                bearer_token_example = auth_header
                token = auth_header[len("bearer "):].strip()
                _, payload_decoded = decode_jwt(token)
                if payload_decoded:
                    bearer_token_payload = payload_decoded
                break

    seen_paths_methods = set()
    for item in items:
        full_url = item.findtext("url")
        parsed_url = urllib.parse.urlparse(full_url)
        uPath = parsed_url.path
        query_string = parsed_url.query
        
        method = (item.findtext("method") or "get").lower()
        
        if (uPath, method) in seen_paths_methods:
            continue
        seen_paths_methods.add((uPath, method))

        request_el = item.find("request")
        
        path_item = openapi_dict["paths"].setdefault(uPath, {})
        method_item = path_item.setdefault(method, {"responses": {}})

        if tag_name:
            method_item["tags"] = [tag_name]
            method_item["summary"] = f"[{tag_name}] {method.upper()} {uPath}"


        statuses = defaultdict(list)
        for response_item in items:
            if response_item.findtext("url") == full_url and (response_item.findtext("method") or "").lower() == method:
                status = response_item.findtext("status") or "200"
                statuses[status].append(response_item)
        
        for status_code, status_items in statuses.items():
            if status_code not in method_item["responses"]:
                method_item["responses"][status_code] = {"description": f"Response status {status_code}"}
            
            response_body = status_items[0].findtext("response")
            base64_encoded_response = status_items[0].find("response").get('base64', 'false').lower() == 'true'
            response_headers, response_body = extract_body_and_headers(response_body, base64_encoded_response)
            response_content_type = response_headers.get('content-type', '').lower()

            content_dict = {}
            if 'application/json' in response_content_type:
                if is_json(response_body):
                    content_dict["application/json"] = {"example": json.loads(response_body)}
                else:
                    content_dict["text/plain"] = {"example": response_body}
            elif 'application/xml' in response_content_type:
                content_dict["application/xml"] = {"example": response_body}
            elif response_body:
                content_dict["text/plain"] = {"example": response_body}

            if content_dict:
                method_item["responses"][status_code]["content"] = content_dict

        request_body = ""
        request_headers = {}
        if request_el is not None and request_el.text:
            base64_encoded = request_el.get('base64', 'false').lower() == 'true'
            request_headers, request_body = extract_body_and_headers(request_el.text, base64_encoded)

        parameters = []
        path_parts = uPath.split('/')
        for part in path_parts:
            if part.startswith("{") and part.endswith("}"):
                parameters.append({
                    "name": part[1:-1],
                    "in": "path",
                    "required": True,
                    "schema": {"type": "string"}
                })

        if query_string:
            for param in query_string.split('&'):
                if '=' in param:
                    k, v = param.split('=', 1)
                    parameters.append({
                        "name": k,
                        "in": "query",
                        "schema": {"type": "string"},
                        "example": urllib.parse.unquote(v)
                    })

        for header_name, header_value in request_headers.items():
            if header_name in IGNORED_HEADERS:
                continue
            
            example_auth = header_value
            if header_name == 'authorization' and bearer_token_example:
                if header_value == bearer_token_example:
                    example_auth = "Bearer {{bearerToken}}"
            
            parameters.append({
                "name": header_name,
                "in": "header",
                "required": False,
                "schema": {"type": "string"},
                "example": example_auth
            })

        if request_body:
            requestBody_openapi = {"content": {}}
            content_type = request_headers.get('content-type', '').lower()
            if 'application/json' in content_type and is_json(request_body):
                json_obj = json.loads(request_body)
                requestBody_openapi["content"]["application/json"] = {
                    "schema": {"type": "object", "properties": dict_to_schema_props(json_obj)},
                    "example": json_obj
                }
            elif 'application/xml' in content_type and is_xml(request_body):
                requestBody_openapi["content"]["application/xml"] = {
                    "schema": {"type": "object"},
                    "example": request_body
                }
            elif 'x-www-form-urlencoded' in content_type:
                requestBody_openapi["content"]["application/x-www-form-urlencoded"] = {
                    "schema": {"type": "object", "properties": parse_params_to_schema(request_body)},
                    "example": request_body
                }
            elif request_body:
                requestBody_openapi["content"]["text/plain"] = {"example": request_body}
            
            if requestBody_openapi["content"]:
                method_item["requestBody"] = requestBody_openapi
        
        if parameters:
            method_item["parameters"] = parameters

    if bearer_token_example:
        openapi_dict.setdefault("components", {}).setdefault("securitySchemes", {})["bearerAuth"] = {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT"
        }
        openapi_dict.setdefault("security", []).append({"bearerAuth": []})
        
    return openapi_dict

def get_file_type(file_path):
    """Determina el tipo de archivo (XML o JSON) basándose en su contenido."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read(4096).strip()
    except Exception as e:
        logger.error(f"Error al leer el archivo para la detección de tipo: {e}")
        return 'unsupported'

    if content.startswith('<') and ('<items>' in content or '<item>' in content or '<?xml' in content):
        return 'xml'
    elif content.startswith('{') or content.startswith('['):
        return 'json'
    return 'unsupported'

def write_to_file(data, filename):
    """Guarda un string en un archivo."""
    with open(filename, "w", encoding="utf-8") as f:
        f.write(data)
    logger.info(f"✅ Archivo guardado: {filename}")

def output_option1_single_file(requests, timestamp_str):
    """Genera un solo archivo OpenAPI JSON, organizado por hosts usando tags."""
    os.makedirs(BASE_OUTPUT_DIRECTORY, exist_ok=True)
    
    requests_by_host = defaultdict(list)
    for item in requests:
        url = item.findtext("url")
        base_url_match = re.match(r"(https?://[^/]+)", url)
        if base_url_match:
            requests_by_host[base_url_match.group(0)].append(item)

    final_openapi_dict = {
        "openapi": "3.0.0",
        "info": {
            "title": f"Burp2API - All Hosts ({timestamp_str})",
            "version": VERSION,
            "description": "API generada automáticamente a partir de XML exportado de Burp Suite, con soporte completo para respuestas."
        },
        "tags": [],
        "paths": {},
        "components": {"securitySchemes": {}}
    }
    
    sorted_hosts = sorted(requests_by_host.keys())
    
    for base_url in sorted_hosts:
        host_items = requests_by_host[base_url]
        host_tag_name = urllib.parse.urlparse(base_url).netloc
        
        if not any(tag['name'] == host_tag_name for tag in final_openapi_dict['tags']):
            final_openapi_dict['tags'].append({"name": host_tag_name, "description": f"API para el host: {base_url}"})
        
        host_openapi = convert_to_openapi(host_items, base_url, tag_name=host_tag_name)
        
        for path, path_item in host_openapi["paths"].items():
            path_item["servers"] = [{"url": base_url}]
            final_openapi_dict["paths"][path] = path_item

        final_openapi_dict["components"]["securitySchemes"].update(host_openapi["components"]["securitySchemes"])
    
    output_json = json.dumps(final_openapi_dict, indent=2, ensure_ascii=False)
    output_json_file = os.path.join(BASE_OUTPUT_DIRECTORY, f"all_api_{timestamp_str}.json")
    write_to_file(output_json, output_json_file)

def output_option2_by_host(requests, timestamp_str):
    """Genera archivos OpenAPI JSON separados, organizados por host."""
    output_dir = os.path.join(BASE_OUTPUT_DIRECTORY, "por_host")
    os.makedirs(output_dir, exist_ok=True)
    
    requests_by_host = defaultdict(list)
    for item in requests:
        url = item.findtext("url")
        base_url_match = re.match(r"(https?://[^/]+)", url)
        if base_url_match:
            requests_by_host[base_url_match.group(0)].append(item)
    
    for base_url, host_items in requests_by_host.items():
        sanitized_host = sanitize_filename(base_url.replace('https://', '').replace('http://', ''), max_len=100)
        host_dir = os.path.join(output_dir, sanitized_host)
        os.makedirs(host_dir, exist_ok=True)
        
        # Crear un nuevo diccionario OpenAPI completo para cada host
        openapi_dict = {
            "openapi": "3.0.0",
            "info": {
                "title": f"Burp2API - {sanitized_host} ({timestamp_str})",
                "version": VERSION,
                "description": f"API para el host: {base_url}"
            },
            "tags": [{"name": sanitized_host, "description": f"API para el host: {base_url}"}],
            "paths": {},
            "components": {"securitySchemes": {}},
            "servers": [{"url": base_url}]
        }

        # Llenar el diccionario con los datos del host específico
        host_openapi = convert_to_openapi(host_items, base_url)
        openapi_dict["paths"] = host_openapi["paths"]
        openapi_dict["components"]["securitySchemes"].update(host_openapi["components"]["securitySchemes"])
        
        openapi_json = json.dumps(openapi_dict, indent=2, ensure_ascii=False)
        output_filename = os.path.join(host_dir, f"{sanitized_host}_api.json")
        write_to_file(openapi_json, output_filename)


def main():
    logger.info(f"=== Burp2API Converter - {VERSION} ===")
    
    input_file = None
    output_option = None

    while not input_file:
        input_file = input("Ingrese la ruta al archivo de entrada (XML o .burp): ").strip()
        if not os.path.isfile(input_file):
            logger.error(f"Archivo no encontrado: {input_file}. Por favor, intente de nuevo.")
            input_file = None
    
    while not output_option:
        print("\nSeleccione la opción de salida:")
        print("1. Un solo archivo OpenAPI JSON para todas las peticiones (organizado por host).")
        print("2. Archivos OpenAPI JSON separados, organizados por host.")
        try:
            choice = int(input("Ingrese su opción (1-2): ").strip())
            if choice in [1, 2]:
                output_option = choice
            else:
                print("Opción inválida. Por favor, ingrese 1 o 2.")
        except ValueError:
            print("Entrada inválida. Por favor, ingrese un número.")

    file_type = get_file_type(input_file)
    if file_type != 'xml':
        logger.error("Formato de archivo no soportado. Este script solo procesa archivos XML de Burp Suite.")
        return

    try:
        tree = ET.parse(input_file)
        requests_data = tree.getroot().findall("item")
    except ET.ParseError as e:
        logger.error(f"Error al procesar el archivo XML: {e}")
        return

    if not requests_data:
        logger.error("No se encontraron peticiones para procesar en el archivo. Saliendo.")
        return

    logger.info(f"Se encontraron {len(requests_data)} peticiones para procesar.")
    timestamp_str = datetime.now().strftime("%Y%m%d-%H%M%S")

    if output_option == 1:
        output_option1_single_file(requests_data, timestamp_str)
    elif output_option == 2:
        output_option2_by_host(requests_data, timestamp_str)

    logger.info("Proceso finalizado exitosamente.")

if __name__ == "__main__":
    main()