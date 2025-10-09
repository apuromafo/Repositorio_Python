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

# --- Configuración de Versión y Strings (i18n) ---
VERSION = "v2.4.0" 

STRINGS = {
    # LOGS y MENÚ
    "MENU_TITLE": "=== Burp2API Converter - {version} ===",
    "PROMPT_INPUT": "Ingrese la ruta al archivo de entrada (XML o .burp): ",
    "ERROR_FILE_NOT_FOUND": "Archivo no encontrado: {file}. Por favor, intente de nuevo.",
    "PROMPT_CHOICE": "Seleccione la opción de salida:",
    "OPTION_1_NAME": "1. Un solo archivo OpenAPI JSON (Organizado y Desduplicado - **Recomendado para API Design**).",
    "OPTION_2_NAME": "2. Archivos OpenAPI JSON separados, por host.",
    "OPTION_3_NAME": "3. **Colección Postman RAW (Contiene TODAS las peticiones/fuzzing, 100% importable, numerada Y CON RESPUESTA).**",
    "PROMPT_ENTER_CHOICE": "Ingrese su opción (1-3): ",
    "ERROR_INVALID_CHOICE": "Opción inválida. Por favor, ingrese 1, 2 o 3.",
    "ERROR_INVALID_INPUT": "Entrada inválida. Por favor, ingrese un número.",
    "ERROR_UNSUPPORTED_FORMAT": "Formato de archivo no soportado. Este script solo procesa archivos XML de Burp Suite.",
    "ERROR_NO_REQUESTS": "No se encontraron peticiones para procesar en el archivo. Saliendo.",
    "INFO_REQUESTS_FOUND": "Se encontraron {count} peticiones para procesar.",
    "INFO_FILE_SAVED": " Archivo guardado: {filename}",
    "INFO_PROCESS_COMPLETE": "Proceso finalizado exitosamente.",
    
    # DESCRIPCIONES DE SALIDA (Postman/OpenAPI)
    "OUTPUT_TITLE_ALL_HOSTS": "Burp2API - All Hosts ({timestamp})",
    "OUTPUT_DESCRIPTION_ALL_HOSTS": "API generada a partir de Burp Suite. Archivo único en formato OpenAPI 3.0 para Postman.",
    "OUTPUT_TAG_DESCRIPTION": "API para el host: {base_url}",
    
    # OPCIÓN 3 ESPECÍFICA
    "POSTMAN_COLLECTION_TITLE": "Burp RAW Requests (Colección Postman - {timestamp})",
    "POSTMAN_COLLECTION_DESCRIPTION": "Colección generada con TODAS ({count} peticiones) de Burp. Cada petición incluye la **Respuesta Original** guardada como un Postman Example.",
    "POSTMAN_ITEM_NAME_PATTERN": "Petición {number}: {method} {path}",
    "POSTMAN_ITEM_DESCRIPTION_PATTERN": "Solicitud original de Burp. Número de Petición: **{number}**.\nMétodo: {method}\nURL Completa: {url}\nTimestamp Burp: {timestamp_burp}",
    "POSTMAN_RESPONSE_NAME": "Respuesta Original ({status_str})",
    "INFO_POSTMAN_GENERATED": " Se generó la colección Postman RAW con {count} peticiones, cada una con su Respuesta Original como Ejemplo.",
    "OUTPUT_TITLE_BY_HOST": "Burp2API - {host} ({timestamp})",
    "OUTPUT_DESCRIPTION_BY_HOST": "API para el host: {base_url}",
}
# --- Configuración de Logging ---
logger = logging.getLogger("Burp2API")
logger.setLevel(logging.INFO)
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter('[%(asctime)s] %(message)s', "%Y-%m-%d %H:%M:%S"))
logger.addHandler(console_handler)

BASE_OUTPUT_DIRECTORY = "output"
IGNORED_HEADERS = [
    'host', 'content-length', 'user-agent', 'accept-encoding', 'accept-language',
    'cookie', 'connection', 'sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform',
    'upgrade-insecure-requests', 'postman-token', 'cache-control', 'pragma', 'accept', 'rut', 'origin'
]

# --- CONSTANTE para Ordenamiento (Restaurada del script base) ---
# Define el orden preferido para los métodos HTTP en la salida OpenAPI
HTTP_METHODS_ORDER = ["GET", "POST", "DELETE", "PUT", "PATCH", "OPTIONS", "HEAD", "TRACE", "CONNECT"]
# ----------------------------------------------------------------

# --- Funciones Auxiliares (Restauradas del script base) ---

def sanitize_filename(name, max_len=50):
    """Sanitiza un string para que sea un nombre de archivo/directorio válido y manejable."""
    sanitized = re.sub(r'[^\w\.-]', '_', name)
    if len(sanitized) > max_len:
        path_hash = hashlib.sha256(name.encode('utf-8')).hexdigest()[:8]
        return f"{sanitized[:max_len]}_{path_hash}"
    return sanitized

def decode_base64_url(data):
    """Decodifica una cadena Base64Url."""
    if not data:
        return None
    try:
        rem = len(data) % 4
        if rem > 0:
            data += "=" * (4 - rem)
        return base64.urlsafe_b64decode(data).decode("utf-8")
    except Exception as e:
        logger.debug(f"Error decodificando Base64Url: {e}")
        return None

def decode_jwt(token):
    """Decodifica un token JWT (solo header y payload)."""
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
    """Intenta decodificar el cuerpo de base64 si parece estar codificado."""
    if not body_text:
        return ""
    try:
        decoded = base64.b64decode(body_text).decode("utf-8")
        if len(decoded) >= len(body_text) / 2: # Heurística simple para evitar decodificar texto plano a basura.
            return decoded
    except Exception:
        pass
    return body_text

def extract_body_and_headers(text, base64_encoded):
    """Divide la petición/respuesta RAW en headers y cuerpo, manejando la codificación base64."""
    if not text:
        return {}, ""
    raw_text = decode_body(text) if base64_encoded else text
    
    # Busca la doble línea en blanco para dividir headers y body
    parts = re.split(r'\r\n\r\n|\n\n', raw_text, maxsplit=1)
    
    headers_raw = parts[0]
    body_content = parts[1].strip() if len(parts) > 1 else ""
    
    # Parsea los headers (la primera línea es la línea de estado/método)
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
    if not text: return False
    try:
        ET.fromstring(text)
        return True
    except ET.ParseError:
        return False
    except Exception:
        return False

def parse_params_to_schema(params):
    """Convierte parámetros de URL o form-urlencoded a un esquema de OpenAPI."""
    schema_props = {}
    if not params:
        return schema_props
    for param in params.split('&'):
        if '=' in param:
            k, v = param.split('=', 1)
            k, v = k.strip(), v.strip()
            # Se usa unquote para manejar los valores codificados en la URL
            schema_props[k] = {"type": "string", "example": urllib.parse.unquote(v)}
        else:
            schema_props[param] = {"type": "string"}
    return schema_props

def dict_to_schema_props(d):
    """Convierte un diccionario JSON de ejemplo a propiedades de esquema OpenAPI."""
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

# --- Función de Conversión a OpenAPI (Opción 1 y 2) ---

def convert_to_openapi(items, base_url, tag_name=None):
    """
    Convierte una lista de ítems de Burp a un objeto OpenAPI 3.0 válido. 
    Aplica desduplicación por (ruta + método) y normalización de rutas con IDs.
    Incluye análisis JWT y soporte para XML/form-urlencoded.
    """
    openapi_dict = {
        "paths": {},
        "components": {"securitySchemes": {}},
        "security": [],
    }
    
    # 1. Busca un token de ejemplo (y su payload decodificado) para la seguridad
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
                # Decodifica el payload JWT
                token = auth_header[len("bearer "):].strip()
                _, payload_decoded = decode_jwt(token)
                if payload_decoded:
                    bearer_token_payload = payload_decoded
                break 

    seen_paths_methods = set()
    for item in items:
        full_url = item.findtext("url")
        parsed_url = urllib.parse.urlparse(full_url)
        
        uPath = parsed_url.path.rstrip('/')
        if not uPath: uPath = '/'
        # Normaliza rutas como /api/users/12345 a /api/users/{id}
        uPath_normalized = re.sub(r'/([0-9a-fA-F-]{4,})(/|$)', '/{id}\\2', uPath)
        
        method = (item.findtext("method") or "get").lower()
        query_string = parsed_url.query 
        
        # Lógica de desduplicación
        if (uPath_normalized, method) in seen_paths_methods:
            continue
        seen_paths_methods.add((uPath_normalized, method))

        request_el = item.find("request")
        path_item = openapi_dict["paths"].setdefault(uPath_normalized, {})
        method_item = path_item.setdefault(method, {"responses": {}})

        if tag_name:
            method_item["tags"] = [tag_name]
        
        path_parts = [p for p in uPath_normalized.split('/') if p and p != '{id}']
        operation_name = path_parts[-1] if path_parts else "root"
        operation_id = f"{method}{operation_name.capitalize().replace('-', '_').replace('.', '_')}"
        if '{id}' in uPath_normalized:
             operation_id += "ById"
        method_item["operationId"] = operation_id 
        method_item["summary"] = f"[{method.upper()}] {uPath_normalized}"

        request_body = ""
        request_headers = {}
        if request_el is not None and request_el.text:
            base64_encoded = request_el.get('base64', 'false').lower() == 'true'
            request_headers, request_body = extract_body_and_headers(request_el.text, base64_encoded)

        parameters = []
        
        # Parámetros de Ruta (Path)
        for part in uPath_normalized.split('/'):
            if part.startswith("{") and part.endswith("}"):
                parameters.append({
                    "name": part[1:-1],
                    "in": "path",
                    "required": True,
                    "schema": {"type": "string"}
                })

        # Parámetros de Query
        if query_string:
            for param in query_string.split('&'):
                if '=' in param:
                    k, v = param.split('=', 1)
                    if not any(p["name"] == k and p["in"] == "query" for p in parameters):
                        parameters.append({
                            "name": k,
                            "in": "query",
                            "schema": {"type": "string"},
                            "example": urllib.parse.unquote(v)
                        })

        # Parámetros de Header
        for header_name, header_value in request_headers.items():
            if header_name in IGNORED_HEADERS:
                continue
            
            example_auth = header_value
            if header_name == 'authorization' and bearer_token_example and header_value == bearer_token_example:
                example_auth = "Bearer {{bearerToken}}" 
            
            if not any(p["name"] == header_name and p["in"] == "header" for p in parameters):
                parameters.append({
                    "name": header_name,
                    "in": "header",
                    "required": False,
                    "schema": {"type": "string"},
                    "example": example_auth
                })

        # Request Body (Manejo de JSON, XML y Form-urlencoded)
        if request_body:
            requestBody_openapi = {"content": {}}
            content_type = request_headers.get('content-type', '').lower()
            
            # JSON
            if 'application/json' in content_type and is_json(request_body):
                json_obj = json.loads(request_body)
                requestBody_openapi["content"]["application/json"] = {
                    "schema": {"type": "object", "properties": dict_to_schema_props(json_obj)},
                    "example": json_obj
                }
            # XML (Restaurado)
            elif 'application/xml' in content_type and is_xml(request_body):
                requestBody_openapi["content"]["application/xml"] = {
                    "schema": {"type": "object"}, # No generamos el esquema XML, solo ejemplo
                    "example": request_body
                }
            # Form-URL Encoded (Restaurado)
            elif 'x-www-form-urlencoded' in content_type:
                requestBody_openapi["content"]["application/x-www-form-urlencoded"] = {
                    "schema": {"type": "object", "properties": parse_params_to_schema(request_body)},
                    "example": request_body
                }
            # Texto Plano/Otros
            elif request_body:
                 requestBody_openapi["content"]["text/plain"] = {"example": request_body}
            
            if requestBody_openapi["content"]:
                method_item["requestBody"] = requestBody_openapi
        
        if parameters:
            method_item["parameters"] = parameters
            
        # Lógica de Respuestas
        response_el = item.find("response")
        if response_el is not None:
            status_code = item.findtext("status").split(' ')[0] if item.findtext("status") else "200"
            if status_code.isdigit():
                status_code = status_code
            else:
                status_code = "200"
            
            response_headers, response_body = extract_body_and_headers(response_el.text, response_el.get('base64', 'false').lower() == 'true')
            
            response_item = method_item["responses"].setdefault(status_code, {"description": f"Response {status_code}"})
            
            if response_body:
                response_item.setdefault("content", {})
                content_type = response_headers.get('content-type', '').lower()
                
                if 'application/json' in content_type and is_json(response_body):
                    try:
                        json_obj = json.loads(response_body)
                        response_item["content"]["application/json"] = {
                            "schema": {"type": "object", "properties": dict_to_schema_props(json_obj)},
                            "example": json_obj
                        }
                    except:
                        response_item["content"]["application/json"] = {"example": response_body}
                # XML en Respuesta
                elif 'application/xml' in content_type and is_xml(response_body):
                    response_item["content"]["application/xml"] = {"example": response_body}
                # Texto plano en Respuesta
                elif response_body:
                    response_item["content"]["text/plain"] = {"example": response_body}

    # Configuración de Seguridad
    if bearer_token_example:
        openapi_dict.setdefault("components", {}).setdefault("securitySchemes", {})["bearerAuth"] = {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT"
        }
        openapi_dict.setdefault("security", []).append({"bearerAuth": []})
        
        # Agrega el esquema del payload decodificado si está disponible
        if bearer_token_payload:
            openapi_dict.setdefault("components", {}).setdefault("schemas", {})["JWTPayload"] = {
                "type": "object",
                "description": "Decoded payload from a sample JWT token used in the Authorization header.",
                "properties": dict_to_schema_props(bearer_token_payload)
            }
        
    return openapi_dict

# --- Función Auxiliar para extraer TODOS los datos (Base para Opción 3) ---

def convert_to_request_list(items, timestamp_str):
    """Extrae TODOS los ítems de Burp (incluyendo duplicados) a una lista JSON personalizada."""
    request_list = []
    
    for item in items:
        request_el = item.find("request")
        response_el = item.find("response")
        
        # Extracción de datos básicos
        full_url = item.findtext("url")
        method = (item.findtext("method") or "GET").upper()
        status = item.findtext("status")
        time = item.findtext("time")
        
        # Extracción de Request
        request_data = {"headers": {}, "body": None}
        if request_el is not None and request_el.text:
            base64_encoded = request_el.get('base64', 'false').lower() == 'true'
            request_data["headers"], request_data["body"] = extract_body_and_headers(request_el.text, base64_encoded)
        
        # Extracción de Response
        response_data = {"status": status, "headers": {}, "body": None}
        if response_el is not None:
            response_body_text = response_el.text
            base64_encoded = response_el.get('base64', 'false').lower() == 'true'
            if response_body_text:
                 response_data["headers"], response_data["body"] = extract_body_and_headers(response_body_text, base64_encoded)
            
        request_item = {
            "timestamp_burp": time,
            "method": method,
            "url": full_url,
            "request": request_data,
            "response": response_data
        }
        request_list.append(request_item)
        
    return {"requests": request_list}

# --- FUNCIÓN DE SALIDA: Opción 3 (Postman Collection con Respuesta y i18n) ---

def output_option3_postman_raw_collection(requests_data, timestamp_str):
    """
    Genera un archivo Postman Collection v2.1 que contiene TODAS las peticiones
    en orden secuencial, con numeración, y la respuesta original guardada como un 'Example'.
    """
    os.makedirs(BASE_OUTPUT_DIRECTORY, exist_ok=True)
    
    raw_list_data = convert_to_request_list(requests_data, timestamp_str)["requests"]

    postman_items = []
    
    for i, req_item in enumerate(raw_list_data):
        request_number = i + 1 

        postman_headers = []
        for name, value in req_item["request"]["headers"].items():
            if name.lower() not in ['host', 'content-length']:
                postman_headers.append({"key": name, "value": value, "type": "text"})

        url_parsed = urllib.parse.urlparse(req_item["url"])
        
        # Generación del nombre con el número de petición (usando STRINGS)
        request_name = STRINGS["POSTMAN_ITEM_NAME_PATTERN"].format(
            number=request_number, method=req_item['method'], path=url_parsed.path
        )
        
        postman_item = {
            "name": request_name,
            "request": {
                # Descripción interna (usando STRINGS)
                "description": STRINGS["POSTMAN_ITEM_DESCRIPTION_PATTERN"].format(
                    number=request_number, method=req_item['method'], url=req_item['url'], timestamp_burp=req_item['timestamp_burp']
                ),
                "method": req_item["method"],
                "header": postman_headers,
                "url": {
                    "raw": req_item["url"],
                    "protocol": url_parsed.scheme,
                    "host": url_parsed.netloc.split('.'),
                    "path": url_parsed.path.strip('/').split('/'),
                    "query": [{"key": k, "value": v[0] if v else ""} for k, v in urllib.parse.parse_qs(url_parsed.query).items()]
                }
            },
            "response": [] 
        }
        
        # Lógica del Cuerpo de Petición (Request Body)
        if req_item["request"]["body"]:
            body_content = req_item["request"]["body"]
            content_type = req_item["request"]["headers"].get('content-type', '').lower()
            
            body_mode = "raw"
            body_options = {}

            if 'application/json' in content_type and is_json(body_content):
                 body_options = {"raw": {"language": "json"}}
            
            postman_item["request"]["body"] = {"mode": body_mode, "raw": body_content, "options": body_options}

        # Lógica de la Respuesta (Guardar como Postman Example)
        response_data = req_item["response"]
        response_status_code_str = response_data.get("status", "0")
        response_status_code = int(response_status_code_str.split(' ')[0]) if response_status_code_str.split(' ')[0].isdigit() else 0
        response_headers = response_data.get("headers", {})
        response_body = response_data.get("body", "")

        if response_status_code > 0:
            postman_response_headers = []
            response_content_type = response_headers.get('content-type', '').lower()

            for name, value in response_headers.items():
                postman_response_headers.append({"key": name, "value": value, "name": name, "description": ""})

            postman_example = {
                "_postman_id": hashlib.sha256(f"{request_name}{response_body}".encode('utf-8')).hexdigest(), 
                "name": STRINGS["POSTMAN_RESPONSE_NAME"].format(status_str=response_status_code_str),
                "originalRequest": postman_item["request"],
                "status": response_status_code_str,
                "code": response_status_code,
                "header": postman_response_headers,
                "body": response_body,
                "_postman_previewlanguage": "json" if 'json' in response_content_type else "text" 
            }
            
            postman_item["response"].append(postman_example)

        postman_items.append(postman_item)

    postman_collection = {
        "info": {
            "_postman_id": hashlib.sha256(timestamp_str.encode('utf-8')).hexdigest(),
            "name": STRINGS["POSTMAN_COLLECTION_TITLE"].format(timestamp=timestamp_str),
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
            "description": STRINGS["POSTMAN_COLLECTION_DESCRIPTION"].format(count=len(postman_items))
        },
        "item": postman_items
    }
    
    output_json = json.dumps(postman_collection, indent=2, ensure_ascii=False)
    output_json_file = os.path.join(BASE_OUTPUT_DIRECTORY, f"postman_raw_collection_{timestamp_str}.json")
    write_to_file(output_json, output_json_file)
    logger.info(STRINGS["INFO_POSTMAN_GENERATED"].format(count=len(postman_items)))

# --- Funciones de Salida 1 y 2 ---

def output_option1_single_file(requests, timestamp_str):
    """
    Genera un solo archivo OpenAPI JSON, desduplicado y organizado por hosts usando tags.
    Aplica orden canónico de métodos HTTP.
    """
    os.makedirs(BASE_OUTPUT_DIRECTORY, exist_ok=True)
    requests_by_host = defaultdict(list)
    base_urls = set()
    for item in requests:
        url = item.findtext("url")
        base_url_match = re.match(r"(https?://[^/]+)", url)
        if base_url_match:
            base_url = base_url_match.group(0)
            requests_by_host[base_url].append(item)
            base_urls.add(base_url)

    final_openapi_dict = {
        "openapi": "3.0.0", 
        "info": {
            "title": STRINGS["OUTPUT_TITLE_ALL_HOSTS"].format(timestamp=timestamp_str),
            "version": VERSION,
            "description": STRINGS["OUTPUT_DESCRIPTION_ALL_HOSTS"]
        },
        "tags": [],
        "paths": {},
        "components": {"securitySchemes": {}},
        "servers": [{"url": base_url} for base_url in sorted(list(base_urls))] 
    }
    
    sorted_hosts = sorted(requests_by_host.keys())
    
    for base_url in sorted_hosts:
        host_items = requests_by_host[base_url]
        host_tag_name = urllib.parse.urlparse(base_url).netloc
        
        if not any(tag['name'] == host_tag_name for tag in final_openapi_dict['tags']):
            final_openapi_dict['tags'].append({"name": host_tag_name, "description": STRINGS["OUTPUT_TAG_DESCRIPTION"].format(base_url=base_url)})
        
        host_openapi = convert_to_openapi(host_items, base_url, tag_name=host_tag_name)
        
        for path, path_item in host_openapi["paths"].items():
            # Ordena los métodos dentro del path para una salida canónica (usando el orden HTTP_METHODS_ORDER)
            sorted_methods = {k: v for k, v in sorted(path_item.items(), key=lambda item: HTTP_METHODS_ORDER.index(item[0].upper()))}
            
            current_path_item = final_openapi_dict["paths"].setdefault(path, {})
            current_path_item.update(sorted_methods)

        final_openapi_dict["components"]["securitySchemes"].update(host_openapi["components"]["securitySchemes"])
        final_openapi_dict["components"].setdefault("schemas", {}).update(host_openapi.get("components", {}).get("schemas", {}))
    
    output_json = json.dumps(final_openapi_dict, indent=2, ensure_ascii=False)
    output_json_file = os.path.join(BASE_OUTPUT_DIRECTORY, f"all_api_{timestamp_str}.json")
    write_to_file(output_json, output_json_file)


def output_option2_by_host(requests, timestamp_str):
    """Genera archivos OpenAPI JSON separados, desduplicados y organizados por host. Aplica orden canónico de métodos HTTP."""
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
        host_openapi = convert_to_openapi(host_items, base_url)

        # Aplicar el ordenamiento de métodos en cada path
        for path, path_item in host_openapi["paths"].items():
            host_openapi["paths"][path] = {k: v for k, v in sorted(path_item.items(), key=lambda item: HTTP_METHODS_ORDER.index(item[0].upper()))}


        openapi_dict = {
            "openapi": "3.0.0",
            "info": {
                "title": STRINGS["OUTPUT_TITLE_BY_HOST"].format(host=sanitized_host, timestamp=timestamp_str),
                "version": VERSION,
                "description": STRINGS["OUTPUT_DESCRIPTION_BY_HOST"].format(base_url=base_url)
            },
            "tags": [{"name": sanitized_host, "description": STRINGS["OUTPUT_TAG_DESCRIPTION"].format(base_url=base_url)}],
            "paths": host_openapi["paths"],
            "components": host_openapi["components"],
            "servers": [{"url": base_url}]
        }
        
        openapi_json = json.dumps(openapi_dict, indent=2, ensure_ascii=False)
        output_filename = os.path.join(host_dir, f"{sanitized_host}_api.json")
        write_to_file(openapi_json, output_filename)


def get_file_type(file_path):
    """Determina si el archivo es XML, JSON, o no soportado."""
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
    """Escribe el contenido en el archivo especificado."""
    with open(filename, "w", encoding="utf-8") as f:
        f.write(data)
    logger.info(STRINGS["INFO_FILE_SAVED"].format(filename=filename))


# --- Función Principal ---

def main():
    """Función principal del script que maneja la entrada, selección de opciones y salida."""
    logger.info(STRINGS["MENU_TITLE"].format(version=VERSION))
    
    input_file = None
    output_option = None

    # Lógica de entrada de archivo
    while not input_file:
        input_file = input(STRINGS["PROMPT_INPUT"]).strip()
        if not os.path.isfile(input_file):
            logger.error(STRINGS["ERROR_FILE_NOT_FOUND"].format(file=input_file))
            input_file = None
    
    # Lógica de selección de opción
    while not output_option:
        print(f"\n{STRINGS['PROMPT_CHOICE']}")
        print(STRINGS["OPTION_1_NAME"])
        print(STRINGS["OPTION_2_NAME"])
        print(STRINGS["OPTION_3_NAME"])
        try:
            choice = input(STRINGS["PROMPT_ENTER_CHOICE"]).strip()
            if choice.isdigit():
                choice_int = int(choice)
                if choice_int in [1, 2, 3]:
                    output_option = choice_int
                else:
                    print(STRINGS["ERROR_INVALID_CHOICE"])
            else:
                print(STRINGS["ERROR_INVALID_INPUT"])
        except ValueError:
            print(STRINGS["ERROR_INVALID_INPUT"])

    # Validación de tipo de archivo
    file_type = get_file_type(input_file)
    if file_type != 'xml':
        logger.error(STRINGS["ERROR_UNSUPPORTED_FORMAT"])
        return

    # Parseo y procesamiento del XML
    try:
        tree = ET.parse(input_file)
        requests_data = tree.getroot().findall("item")
    except ET.ParseError as e:
        logger.error(f"Error al procesar el archivo XML: {e}")
        return

    if not requests_data:
        logger.error(STRINGS["ERROR_NO_REQUESTS"])
        return

    logger.info(STRINGS["INFO_REQUESTS_FOUND"].format(count=len(requests_data)))
    timestamp_str = datetime.now().strftime("%Y%m%d-%H%M%S")

    # Ejecución de la opción seleccionada
    if output_option == 1:
        output_option1_single_file(requests_data, timestamp_str)
    elif output_option == 2:
        output_option2_by_host(requests_data, timestamp_str)
    elif output_option == 3:
        output_option3_postman_raw_collection(requests_data, timestamp_str)

    logger.info(STRINGS["INFO_PROCESS_COMPLETE"])

if __name__ == "__main__":
    main()