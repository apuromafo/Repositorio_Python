import sys
import os
import re
import csv
import json
import argparse
import logging
import urllib.parse
import xml.etree.ElementTree as ET
from datetime import datetime
from urllib.parse import urlparse
from base64 import b64decode
#TODO indicar una herramienta que filtre segun el nivel de riesgo o deje organizado por ese nivel de riesgo 
# Configuración logging
logger = logging.getLogger("Burp2Risk")
logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
ch.setFormatter(logging.Formatter('[%(asctime)s] %(message)s', "%Y-%m-%d %H:%M:%S"))
logger.addHandler(ch)

VERSION = "1.7.6"
OUTPUT_DIR = "output"

# Diccionarios de palabras clave para clasificación de riesgo
KEYWORDS = {
    "financial_risk": {
        "en": ["payment", "billing", "refund", "invoice", "transaction", "checkout"],
        "es": ["pago", "facturacion", "reembolso", "factura", "transaccion", "caja"]
    },
    "high_risk": {
        "en": ["admin", "login", "password", "passwd", "user", "account", "profile", "token", "session", "authenticate",
               "auth", "reset", "delete", "identity", "logout", "oauth", "permission", "policy", "register", "role",
               "ticket", "access", "secrets", "proxy", "permissions", "groups", "api_key", "credentials", "whoami", "me"],
        "es": ["administrador", "autenticacion", "login", "contraseña", "clave", "usuario", "cuenta", "perfil", "token",
               "sesion", "autenticar", "auth", "restablecer", "eliminar", "identidad", "desconectar", "oauth", "permiso",
               "politica", "registrar", "rol", "ticket", "acceso", "secretos", "proxy", "permisos", "grupos", "api_key", "credenciales", "quiensoy"]
    },
    "medium_risk": {
        "en": ["upload", "audit", "order", "report", "reports", "data", "file", "files", "download", "notification", "subscription", "tracking", "analytics", "catalog", "config", "settings"],
        "es": ["subir", "auditoria", "pedido", "informe", "informes", "datos", "archivo", "archivos", "descarga", "notificacion", "suscripcion", "rastreo", "analisis", "catalogo", "configuracion", "ajustes"]
    },
    "low_risk": {
        "en": ["public", "info", "status", "health", "ping", "docs", "faq", "blog", "news", "events", "terms", "version", "weather", "contact", "about", "support", "widget", "resources", "list"],
        "es": ["publico", "informacion", "estado", "salud", "ping", "documentos", "faq", "blog", "noticias", "eventos", "terminos", "version", "clima", "contacto", "acerca", "soporte", "widget", "recursos", "lista"]
    },
    "id_keywords": {
        "en": ["user", "users", "client", "customer", "employee", "patient", "student", "child", "staff", "id", "uuid", "salary", "id_empleado"],
        "es": ["usuario", "usuarios", "cliente", "id_cliente", "cliente", "id_cliente", "empleado", "id_empleado", "paciente", "id_paciente", "id", "uuid", "salario"]
    },
    "body_sensitive": {
        "en": ["password", "token", "session", "credential", "key", "secret", "jwt", "oauth", "apikey", "ssn", "credit_card", "pin", "cvv", "email", "phone_number", "address", "username"],
        "es": ["contraseña", "token", "sesion", "credencial", "clave", "secreto", "jwt", "oauth", "apikey", "dni", "tarjeta", "pin", "cvv", "correo", "telefono", "direccion", "usuario"]
    }
}

# Explicaciones y sugerencias para keywords
EXPLANATIONS = {
    # Riesgo Financiero (10)
    "payment": "Manejo de pagos y transacciones financieras críticas.",
    "billing": "Endpoint relacionado con facturación y cobros.",
    "refund": "Procesamiento de reembolsos con impacto financiero importante.",
    "transaction": "Manejo de transacciones, riesgo inherente de fraude.",
    "checkout": "Proceso de finalización de compra, manejo de datos de pago.",
    "invoice": "Generación o manejo de facturas, posible exposición de datos financieros.",
    # Alto riesgo (10)
    "admin": "Contiene funciones administrativas, posible acceso a datos sensibles.",
    "login": "Manejo de autenticación y sesiones.",
    "password": "Manejo de contraseñas sensibles.",
    "token": "Manejo de tokens de seguridad y sesiones.",
    "user": "Manipulación de usuarios y perfiles, riesgo alto de acceso no autorizado.",
    "policy": "Gestión de políticas de seguridad o privacidad.",
    "api_key": "Manejo de claves de API, información sensible.",
    "delete": "Operación destructiva, alto riesgo de pérdida de datos.",
    "whoami": "Endpoint de información de sesión, puede exponer datos de usuario.",
    "me": "Endpoint de información de sesión, puede exponer datos de usuario.",
    # IDOR (8)
    "id": "Exposición de identificadores, posible riesgo de IDOR.",
    "uuid": "Identificador único, potencial riesgo de IDOR.",
    # ID de riesgo alto (9)
    "salary": "Manejo de información salarial sensible.",
    # Medio riesgo (6)
    "upload": "Permite subir archivos, potencial vector de ataque (carga maliciosa).",
    "audit": "Operaciones de auditoría, acceso a registros de eventos.",
    "order": "Gestión de pedidos, puede exponer datos de compra.",
    "report": "Generación o acceso a reportes, puede contener datos confidenciales.",
    "data": "Manejo de datos, potencialmente sensible.",
    "analytics": "Manejo de análisis y métricas, puede revelar información de negocio.",
    "catalog": "Exposición del catálogo de productos.",
    "config": "Manejo de configuraciones del sistema.",
    "settings": "Manejo de ajustes del sistema.",
    # Bajo riesgo (2)
    "public": "Funcionalidad pública o que expone información no sensible.",
    "info": "Información general o estática.",
    "status": "Estado del sistema o servicio.",
    "health": "Estado de salud del sistema, no debería exponer detalles.",
    "docs": "Endpoint para documentación.",
    "blog": "Contenido de blog.",
    "contact": "Información de contacto.",
}

SUGGESTIONS = {
    # Riesgo Financiero (10)
    "payment": "Usar proveedores certificados y nunca almacenar datos sensibles.",
    "billing": "Seguridad reforzada en datos y procesos de facturación.",
    "refund": "Auditar cambios y aprobaciones para prevenir fraudes.",
    "transaction": "Asegurar integridad de la transacción con validaciones.",
    "checkout": "Validar y cifrar todos los datos de pago.",
    "invoice": "Restringir acceso y auditar la creación/visualización.",
    # Alto riesgo (10)
    "admin": "Implementar autenticación multifactor y monitoreo de accesos.",
    "login": "Almacenar credenciales cifradas y limitar intentos de acceso.",
    "password": "Almacenar contraseñas usando hashing seguro y políticas fuertes.",
    "token": "Implementar expiración y revocación de tokens.",
    "user": "Controlar accesos y realizar auditorías frecuentes sobre datos personales.",
    "policy": "Asegurar integridad y acceso controlado a políticas de seguridad.",
    "api_key": "Rotar claves regularmente y auditar uso.",
    "delete": "Implementar controles estrictos y confirmaciones de usuario.",
    "whoami": "Restringir la información expuesta a lo estrictamente necesario.",
    "me": "Restringir la información expuesta a lo estrictamente necesario.",
    # IDOR (8)
    "id": "Validar que el acceso a identificadores esté restringido para evitar IDOR.",
    "uuid": "Validar que el acceso a identificadores esté restringido para evitar IDOR.",
    # ID de riesgo alto (9)
    "salary": "Restringir acceso y cifrar datos salariales sensibles.",
    # Medio riesgo (6)
    "upload": "Validar y filtrar tipos de archivos y tamaño, escanear por malware.",
    "audit": "Limitar y monitorear acceso a funciones de auditoría.",
    "order": "Control de acceso y validación de integridad.",
    "report": "Restringir accesos y auditar cambios en la generación de reportes.",
    "data": "Asegurar la validación y el cifrado adecuado de los datos.",
    "analytics": "Minimizar la exposición de datos de usuarios.",
    "catalog": "Asegurar que no se expongan detalles sensibles de productos.",
    "config": "Proteger el acceso a la configuración del sistema.",
    "settings": "Verificar accesos con autenticación multifactor y registro estricto.",
    # Bajo riesgo (2)
    "generic_low_risk": "Revisar políticas para evitar exposición accidental de información interna."
}


def word_in_path(word, path):
    # Match whole word separated by /, -, _
    pattern = r'(^|[\/\-_])' + re.escape(word) + r'($|[\/\-_])'
    return re.search(pattern, path) is not None

def classify_endpoint(endpoint, params=None, body=None):
    path = endpoint.split('://', 1)[-1].split('?', 1)[0].lower().strip()
    param_str = urllib.parse.unquote(params or "")
    
    # Priorizar la clasificación de riesgo con un diccionario temporal para encontrar el mayor riesgo
    scores = {}

    # Chequeo 1: Datos sensibles en el cuerpo (Máxima prioridad)
    combined_text = param_str.lower()
    if body:
        try:
            combined_text += body.decode('utf-8', errors='ignore').lower()
        except Exception:
            combined_text += str(body).lower()

    for lang in KEYWORDS['body_sensitive']:
        for word in KEYWORDS['body_sensitive'][lang]:
            if word in combined_text:
                scores[10] = {"reason": f"Contiene datos sensibles en el cuerpo: '{word}'.", "suggestion": SUGGESTIONS.get(word, "Cifrar datos sensibles y validar la entrada.")}
                # Si se encuentra, no necesitamos buscar más
                highest_score = 10
                return {
                    'endpoint': endpoint,
                    'parameters': param_str,
                    'risk': highest_score,
                    'reason': scores[highest_score]["reason"],
                    'suggestions': scores[highest_score]["suggestion"]
                }
    
    # Chequeo 2: Patrón de IDOR (Alta prioridad)
    if re.search(r'/\w+/\d+$|/\w+/[a-f0-9\-]{36}$', path):
        scores[8] = {"reason": EXPLANATIONS.get("id", "Exposición de identificadores, posible riesgo de IDOR."), "suggestion": SUGGESTIONS.get("id", "Validar accesos para evitar IDOR.")}
    
    # Chequeo 3: Palabras clave por categoría de riesgo (Prioridad descendente)
    score_map = {"financial_risk": 10, "high_risk": 10, "id_keywords": 9, "medium_risk": 6, "low_risk": 2}
    
    for risk_category in ["financial_risk", "high_risk", "id_keywords", "medium_risk", "low_risk"]:
        keywords_group = KEYWORDS.get(risk_category, {})
        current_score = score_map.get(risk_category)
        for lang in keywords_group:
            for word in keywords_group[lang]:
                if word_in_path(word, path):
                    explanation = EXPLANATIONS.get(word, f"Funcionalidad de {risk_category.replace('_', ' ')}: '{word}'.")
                    suggestion = SUGGESTIONS.get(word, SUGGESTIONS["generic_low_risk"] if current_score < 4 else "Considerar revisión general de seguridad.")
                    if current_score not in scores or explanation not in scores[current_score]["reason"]:
                        scores.setdefault(current_score, {"reason": "", "suggestion": ""})
                        scores[current_score]["reason"] = (scores[current_score]["reason"] + " | " + explanation).strip(" | ")
                        scores[current_score]["suggestion"] = (scores[current_score]["suggestion"] + " | " + suggestion).strip(" | ")

    if not scores:
        highest_score = 2
        final_reason = EXPLANATIONS.get("info", "No se detectaron palabras clave ni patrones relevantes.")
        final_suggestion = SUGGESTIONS.get("generic_low_risk")
    else:
        highest_score = max(scores.keys())
        final_reason = scores[highest_score]["reason"]
        final_suggestion = scores[highest_score]["suggestion"]
        
    return {
        'endpoint': endpoint,
        'parameters': param_str,
        'risk': highest_score,
        'reason': final_reason,
        'suggestions': final_suggestion
    }

def is_valid_url(url):
    try:
        parsed = urlparse(url)
        return parsed.scheme in ('http', 'https') and parsed.netloc != ''
    except Exception:
        return False

def parse_xml_for_endpoints(file_path):
    endpoints = []
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        for item in root.findall('item'):
            url = item.findtext('url')
            req_base64 = item.findtext('request')
            if url:
                params = ''
                if '?' in url:
                    params = url.split('?', 1)[1]
                body = None
                if req_base64:
                    try:
                        decoded = b64decode(req_base64)
                        match = re.search(b'\r\n\r\n(.*)', decoded, re.DOTALL)
                        if match:
                            body = match.group(1)
                    except Exception:
                        body = None
                endpoints.append({'url': url.strip(), 'params': params, 'body': body})
    except Exception as e:
        logger.error(f"Error leyendo XML: {e}")
    return endpoints

def parse_json_for_endpoints(file_path):
    endpoints = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            spec = json.load(f)
        base_url = spec.get('servers', [{}])[0].get('url', '')
        for path, methods in spec.get('paths', {}).items():
            url = urllib.parse.urljoin(base_url, path)
            for method_info in methods.values():
                params = ''
                if 'parameters' in method_info:
                    query_params = [p.get('name', '') for p in method_info['parameters'] if p.get('in') == 'query']
                    if query_params:
                        params = '&'.join([f"{p}=value" for p in query_params])
                body = None
                if 'requestBody' in method_info:
                    content = method_info['requestBody'].get('content', {})
                    if 'application/json' in content:
                        example = content['application/json'].get('example')
                        if example:
                            body = json.dumps(example).encode('utf-8')
                endpoints.append({'url': url, 'params': params, 'body': body})
    except Exception as e:
        logger.error(f"Error leyendo JSON: {e}")
    return endpoints

def parse_txt_for_endpoints(file_path):
    endpoints = []
    with open(file_path, 'r', encoding='utf-8') as f:
        for idx, line in enumerate(f, 1):
            url = line.strip()
            if url.startswith('[') and url.endswith(']'):
                url = url[1:-1]
            if is_valid_url(url):
                endpoints.append({'url': url, 'params': '', 'body': None})
            else:
                logger.warning(f"Línea {idx} ignorada, no es URL válida: {line.strip()}")
            if idx % 100 == 0:
                logger.info(f"Procesadas {idx} líneas...")
    return endpoints

def get_file_type(file_path):
    if not os.path.isfile(file_path):
        return 'unsupported'
    with open(file_path, 'r', encoding='utf-8') as f:
        start = f.read(2048).strip()
    if start.startswith('<'):
        return 'xml'
    if start.startswith('{') or start.startswith('['):
        return 'json'
    if 'http://' in start or 'https://' in start:
        return 'txt'
    return 'unsupported'

def write_output(output_dir, data, formats, orders):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")

    for order in orders:
        # Aquí se aplica el ordenamiento
        sorted_data = data
        if order == 'host':
            sorted_data = sorted(data, key=lambda x: urllib.parse.urlparse(x['endpoint']).hostname or '')

        filename_suffix = f"_{order}" if len(orders) > 1 else ""
        base_name = f"api_risks_{timestamp}{filename_suffix}"

        if 'csv' in formats:
            with open(os.path.join(output_dir, f"{base_name}.csv"), 'w', newline='', encoding='utf-8') as f:
                fieldnames = ['endpoint', 'parameters', 'risk', 'reason', 'suggestions']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for item in sorted_data:
                    writer.writerow(item)
            logger.info(f"Archivo CSV guardado: {base_name}.csv")

        if 'json' in formats:
            with open(os.path.join(output_dir, f"{base_name}.json"), 'w', encoding='utf-8') as f:
                json.dump(sorted_data, f, indent=4)
            logger.info(f"Archivo JSON guardado: {base_name}.json")

        if 'txt' in formats:
            with open(os.path.join(output_dir, f"{base_name}.txt"), 'w', encoding='utf-8') as f:
                f.write(f"Análisis de Riesgos de Endpoints - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 70 + "\n\n")

                for i, item in enumerate(sorted_data, 1):
                    f.write(f"Endpoint {i}:\n")
                    f.write(f"  URL: {item['endpoint']}\n")
                    f.write(f"  Riesgo: {item['risk']}/10\n")
                    f.write(f"  Razón: {item['reason'].replace(' | ', ' y ')}\n")
                    f.write(f"  Sugerencias: {item['suggestions'].replace(' | ', ' y ')}\n")
                    f.write("-" * 50 + "\n\n")
            logger.info(f"Archivo TXT guardado: {base_name}.txt")

def set_log_level(verbose):
    if verbose:
        logger.setLevel(logging.DEBUG)
        ch.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)
        ch.setLevel(logging.INFO)

def main():
    parser = argparse.ArgumentParser(
        description="Clasifica riesgos de endpoints desde archivos XML, JSON o TXT.",
        epilog="Ejemplo: python burp_risk.py -f endpoints.txt -o csv txt --order host appearance"
    )
    parser.add_argument("-f", "--file", required=True, help="Archivo fuente con endpoints.")
    parser.add_argument("-o", "--output", nargs="+", choices=["csv", "json", "txt"], default=["csv"], help="Formatos de salida.")
    parser.add_argument("--verbose", action="store_true", help="Activar modo verbose.")
    parser.add_argument("--order", nargs="+", choices=["host", "appearance"], default=["appearance"],
                         help="Orden de la salida. Opciones: 'host' para agrupar por dominio, 'appearance' para el orden de aparición. Se pueden combinar.")
    args = parser.parse_args()

    set_log_level(args.verbose)

    if not os.path.isfile(args.file):
        logger.error(f"Archivo no encontrado: {args.file}")
        sys.exit(1)

    file_type = get_file_type(args.file)

    if file_type == "xml":
        logger.info("Procesando archivo XML...")
        raw_endpoints = parse_xml_for_endpoints(args.file)
    elif file_type == "json":
        logger.info("Procesando archivo JSON...")
        raw_endpoints = parse_json_for_endpoints(args.file)
    elif file_type == "txt":
        logger.info("Procesando archivo TXT...")
        raw_endpoints = parse_txt_for_endpoints(args.file)
    else:
        logger.error("Formato de archivo no soportado.")
        sys.exit(1)

    filtered = [e for e in raw_endpoints if e['url']]
    logger.info(f"Extraídos {len(filtered)} endpoints (antes deduplicación).")
    unique = { (e['url'], e['params']): e for e in filtered }
    logger.info(f"Totales únicos tras deduplicación: {len(unique)}.")

    hosts = set()
    for e in unique.values():
        try:
            hosts.add(urllib.parse.urlparse(e['url']).hostname or '')
        except:
            pass
    logger.info(f"Número de hosts únicos: {len(hosts)}")

    results = []
    total = len(unique)
    for idx, e in enumerate(unique.values(), 1):
        if idx % 50 == 0 or idx == total:
            logger.info(f"Procesando endpoint {idx}/{total}...")
        results.append(classify_endpoint(e['url'], e.get('params'), e.get('body')))

    write_output(OUTPUT_DIR, results, args.output, args.order)

    count_high = sum(1 for r in results if r['risk'] >= 8)
    count_med = sum(1 for r in results if 4 <= r['risk'] < 8)
    count_low = sum(1 for r in results if r['risk'] < 4)
    logger.info(f"Resumen: {count_high} alto riesgo, {count_med} medio, {count_low} bajo, total {len(results)}.")
    logger.info("Análisis completado.")

if __name__ == "__main__":
    main()
