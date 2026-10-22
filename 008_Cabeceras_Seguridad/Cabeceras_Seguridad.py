# =============================================================================
# AVISO LEGAL / LEGAL NOTICE
# -----------------------------------------------------------------------------
# Esta herramienta es unicamente para fines educativos y de auditoria de
# seguridad autorizada. El uso no autorizado contra sistemas sin el
# consentimiento explicito del propietario es ilegal.
# El usuario asume toda responsabilidad por el uso indebido.
#
# This tool is for educational and authorized security auditing purposes only.
# Unauthorized use against systems without the owner's explicit consent is
# illegal. The user assumes all responsibility for misuse.
# =============================================================================

import logging
logger = logging.getLogger(__name__)
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
logger.addHandler(handler)
logger.setLevel(logging.INFO)

__version__ = "1.4.3"
#-------------------------------------------------------------------------------------------------
#
#otras formas de validar o ver cabeceras SecurityHeaders.com
#curl -I https://yourdomain.com
#DevTools > Network > Response Headers
#
# Ahora con esta herramienta: 
#Cabeceras de seguridad - Analizador de encabezados HTTP.
#
# Descripción:
#       Este script se conecta a una URL o lee un archivo JSON para analizar los encabezados de
#       respuesta HTTP en busca de configuraciones relacionadas con la seguridad.
#       Ofrece sugerencias para mejorar la seguridad, identificar encabezados faltantes
#       y señalar **configuraciones de seguridad débiles o peligrosas (ej. 'unsafe-' en CSP)**.
#
# Forma de uso:
#       - Analizar una URL en vivo:
#           python Cabeceras_Seguridad.py <URL> [opciones]
#           Ejemplo: python Cabeceras_Seguridad.py https://ejemplo.com -i
#
#       - Analizar un archivo JSON (generado con 'convert_headers.py'):
#           python Cabeceras_Seguridad.py -j <archivo.json> [opciones]
#           Ejemplo: python Cabeceras_Seguridad.py -j demo.json -i
#
#       - Opciones comunes:
#           -i, --info      Mostrar todos los encabezados presentes.
#           -v, --verb      Especificar el verbo HTTP (ej: POST).
#           -H, --header    Añadir encabezados personalizados.
# -------------------------------------------------------------------------------------------------
# ==============================================================================
# --- HISTORIAL DE VERSIONES ---
# ==============================================================================
# v1.4.3 (2026-10-21) - [RESCATE: CHECK HTTP->HTTPS + SERVER-TIMING + GMT-3]
#       OK Rescate desde script ancestral (Cabeceras_Seguridad.py pre-_f):
#                  - `verificar_redireccion_http_https(url)`: chequeo de que HTTP
#                    redirija a HTTPS, ahora llamando http:// con timeout y
#                    distinguindo 30X+Location https:// / 30X sin Location https /
#                    sitio en claro / puerto 80 no alcanzable. Se emite en modo
#                    URL junto a la URL objetivo. Fix del original, que probaba
#                    https:// y el test era ambiguo.
#                  - `Server-Timing` incorporada a la lista de divulgación
#                    (suggest_headers_to_remove + nota con observation/riesgo/
#                    sugerencia; fingerprinting de middleware).
#                  - `print_tiempo` vuelto a mostrar offset "(HH:MM GMT-3)".
#       OK Ajustado: dedupe en HEADER_REMOVE_NOTES (Via/X-Amz-Cf-Pop/
#                    X-Amzn-RequestId estaban duplicados en el dict).
# ==============================================================================
# v1.4.2 (2026-10-21) - [UI/UX: SALIDA 100% ASCII EN CONSOLA]
#       OK Ajustado: Reemplazo de caracteres Unicode decorativos por ASCII puro
#                    ([OK] en verde para mitigaciones/leyenda, '-' en metadatos
#                    de ficha), banner ASCII final normalizado a espacios
#                    regulares (214 NBSP U+00A0 eliminados). Consistencia visual
#                    en consolas sin soporte de emoji/wide chars.
# ==============================================================================
# v1.4.1 (2026-10-21) - [UI/UX: CIERRE VISUAL DEL ANALISIS PROFUNDO CSP]
#       OK Ajustado: `analizar_csp_profundo` cierra su sección con barra de
#                    separación (mismo ancho `=`*70 que la apertura) y línea
#                    "[Resumen] Análisis profundo CSP: <conteo por severidad>",
#                    delimitando el bloque del resto del reporte (caché, plan).
# ==============================================================================
# v1.4.0 (2026-10-21) - [REMEDIACIÓN MULTI-STACK: NGINX/APACHE/CLOUDFLARE/AKAMAI]
#       OK Añadido: Snippets reales por tecnología en las fichas de remediation:
#                  - Ficha CSP PASO 2: nginx (CSP-Report-Only + enforce con
#                    add_header...always), Apache (mod_headers), Cloudflare WAF
#                    (Transform Rules estático + Worker con nonce dinámico y la
#                    nota de HTMLRewriter/app para inyectarlo al HTML), Akamai
#                    WAF/CDN (Property Manager Modify Response Header + EdgeWorkers
#                    onClientResponse; secuelas de crypto delegada a la app).
#                  - Ficha HSTS PASO 1: Cloudflare (Dashboard SSL/TLS Edge
#                    Certificates + Transform Rule) y Akamai (PM + behavior HSTS).
#                  - Ficha stack PASO 3: limpieza de cabeceras en Akamai
#                    (removeHeader en EdgeWorkers) junto a Cloudflare/CloudFront.
#       OK Ajustado: Corrige snippets con continuaciones de línea inválidas y
#                    aclaraciones honestas sobre límites de cada plataforma
#                    (nginx/Apache no computan nonces; CF TR tampoco).
# ------------------------------------------------------------------------------
# v1.3.1 (2026-10-21) - [UI/UX: FORMATO FICHA DE INCIDENCIA]
#       OK Reorganizado: plan_remediacion ahora emite cada tema como "Ficha de
#                  Incidencia": encabezado [Ficha N] remarcado, línea 'Estado
#                  actual' y 'Normativa' (SOC 2 | PCI DSS), separadores '-', pasos
#                  [PASO n] y cierre '='; riesgos con [!] (amarillo) y mitigaciones
#                  con [OK] (verde).
#       OK Ajustado: snippets agrupados explícitamente por tecnología (Nginx,
#                  Apache, Node.js/Express, PHP, ASP.NET, Cloudflare/CloudFront)
#                  con etiqueta de sub-sección para salto directo al stack del
#                  cliente.
# ------------------------------------------------------------------------------
# v1.3.0 (2026-10-21) - [PLAN DE REMEDIACIÓN ACCIONABLE]
#       OK Añadido: plan_remediacion(headers) + detectar_temas_remediacion():
#                  genera al final del reporte fases y pasos concretos según lo
#                  observado (CSP con flags/wildcards/data:, HSTS corto/sin
#                  includeSubDomains/preload, stack expuesto, señales de CMS),
#                  con snippets por tecnología (nginx/Apache/Express/PHP/ASP.NET/
#                  CloudFront-Cloudflare) y mapeo de apoyo a SOC 2 (CC6.6, CC7.1,
#                  CC8.1) y PCI DSS v4.0 (Req 4.2.1, 6.2.3, 6.2.4, 6.4.2).
#       OK Añadido: Fase de auditoría CSP vía Report-Only con recolección own logs,
#                  migración a nonce/hash, restricción de comodines y política objetivo.
#       OK Añadido: Sección HSTS con validaciones previas (includeSubDomains es
#                  irreversible a corto plazo; preload via hstspreload.org).
# ------------------------------------------------------------------------------
# v1.2.0 (2026-10-21) - [ORDEN DE LECTURA DEL REPORTE + FIX CACHÉ]
#       OK Reorganizado: Flujo del reporte para lectura lineal (reduce fatiga
#                  cognitiva): [1] contexto (banner+estado HTTP) -> [2] inventario/
#                  resumen ejecutivo (resumen_inventario_cabeceras NUEVA, al inicio)
#                  -> [3] evaluación estándar bloque a bloque -> [4] deep dive CSP
#                  directiva por directiva + análisis de caché -> [5] endurecimiento
#                  (recomendadas faltantes antes de exposición tech) -> [6] cierre.
#       OK Ajustado: print_security_headers ahora devuelve (csp, xfo) al caller y
#                  ya NO emite ni el resumen de inventario ni el deep dive,
#                  permitiendo ordenarlos desde main().
#       OK Corregido: suggest_cache_headers recibía las cabeceras de la PETICIÓN
#                  en modo URL en vivo (se mostraba vacío/sin Cache-Control de la
#                  respuesta); ahora siempre usa las cabeceras de la RESPUESTA.
# ------------------------------------------------------------------------------
# v1.1.1 (2026-10-21) - [UI/UX: ESQUEMA CROMÁTICO DE HALLAZGOS]
#       OK Ajustado: Semántica de color en la sección de análisis profundo de CSP:
#                  Rojo exclusivo de hallazgos Alta; Amarillo para Media y
#                  Posible alta; Cian para Baja/Info y metadatos (Actual:);
#                  Verde para sugerencias/OK; Magenta para referencias.
#       OK Añadido: _COLOR_RIESGO - la etiqueta 'Riesgo:' solo satura en rojo
#                  cuando el hallazgo es de severidad Alta.
# ------------------------------------------------------------------------------
# v1.1.0 (2026-10-21) - [ANÁLISIS CSP PROFUNDO]
#       OK Añadido: Motor de análisis profundo de CSP (analizar_csp_profundo):
#                  parseo real de directivas + resolución de herencia (CSP3) y
#                  evaluación directiva por directiva alineada con CSP Evaluator:
#                  'unsafe-inline'/'unsafe-eval'/data:/wildcards/esquemas sueltos
#                  (Alta), allowlists de hosts ('self' JSONP/AngularJS/uploads) como
#                  Posible alta, hosts externos como Info (sin bypass conocido) y
#                  estilo 'unsafe-inline'/data:/* como Media (exfil por estilos).
#       OK Añadido: Chequeo de directivas recomendables ausentes: form-action,
#                  base-uri, object-src 'none', frame-ancestors (NO hereda de
#                  default-src, se respeta X-Frame-Options presente),
#                  upgrade-insecure-requests y report-uri/report-to.
#       OK Mejorado: Comentario de frame-ancestors ahora reconoce X-Frame-Options
#                  (DENY/SAMEORIGIN) presente y no lo marca como gap redundante.
#       OK Refactor: se reemplaza check_for_unsafe_csp (código muerto, matching por
#                  substring global con falsos positivos tipo font-src data:) por
#                  el motor nuevo con análisis por token y por directiva.
# ------------------------------------------------------------------------------
# v0.1.2 (2025-11-03) - [CORRECCIÓN CSP]
#       OK Corregido: La función check_for_unsafe_csp ahora tiene en cuenta la directiva 
#                  'strict-dynamic'. Si está presente, ignora las alertas para 
#                  'unsafe-inline' y 'http:'/`https:` en 'script-src', alineándose con 
#                  las prácticas modernas de seguridad de CSP.
# ------------------------------------------------------------------------------
# v0.1.1 (2025-11-03) - [ACTUALIZACIÓN DE SEGURIDAD]
#       OK Añadido: Detección y alerta de directivas inseguras en Content-Security-Policy 
#                  (ej., 'unsafe-inline', 'unsafe-eval').
#       OK Añadido: Análisis y advertencia sobre configuraciones débiles en HSTS (max-age bajo)
#                  y Referrer-Policy (unsafe-url).
#       OK Mejorado: Lógica para la cabecera X-XSS-Protection. Ahora se omite como "faltante"
#                  si la cabecera Content-Security-Policy está presente (práctica moderna).
#       OK Actualizado: User-Agent y Bloque de Historial.
# ------------------------------------------------------------------------------
# v0.1.0 (2025-09-04) - [LANZAMIENTO]
#       OK Añadido: Bloque de 'Forma de uso' para una referencia rápida.
#       OK Mejorado: Lógica de análisis de JSON para la 'Descripción' del estado HTTP.
#       OK Corregido: Errores menores en el código y la presentación.
# ------------------------------------------------------------------------------
# v0.0.7 (2025-07-15) - [INICIO]
#       OK Prototipo funcional inicial.
#       OK Análisis de cabeceras de seguridad comunes.
#       OK Soporte para solicitudes web y archivos JSON.
# ==============================================================================
#!/usr/bin/env python
"""
Cabeceras de seguridad inspirado en OWASP Secure Headers
Autor: Apuromafo
"""
import argparse
import requests
from requests.auth import HTTPProxyAuth
import json
from tabulate import tabulate
from colorama import Fore, Style, init
import random
import socket
from urllib.parse import urlparse, urlunparse
import ipaddress
import locale
import urllib3
import sys
from datetime import datetime, timezone, timedelta
import logging
import os
import hashlib
import re

# Inicializar colorama
init(autoreset=True)

# Desactivar warnings de SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Constantes
TIMEOUT = 10  # segundos
VERSION = f'v{__version__}'
DEFAULT_USER_AGENT = f'CabecerasSegurasScript/{__version__}'

# Colores para banner
colores = {
    "rojo": (255, 0, 0),
    "naranja": (255, 165, 0),
    "amarillo": (255, 255, 0),
    "verde": (0, 255, 0),
    "azul": (0, 0, 255),
    "morado": (128, 0, 128),
}

# Funciones de banner
def interpolar_color(color_inicio, color_fin, posicion):
    r_inicio, g_inicio, b_inicio = color_inicio
    r_fin, g_fin, b_fin = color_fin
    r_nuevo = int(r_inicio + (posicion * (r_fin - r_inicio)))
    g_nuevo = int(g_inicio + (posicion * (g_fin - g_inicio)))
    b_nuevo = int(b_inicio + (posicion * (b_fin - b_inicio)))
    return (r_nuevo, g_nuevo, b_nuevo)

def rgb_a_codigo_ansi(rgb):
    r, g, b = rgb
    return f"\033[38;2;{r};{g};{b}m"

def generar_degradado_colores(color_inicio, color_fin, pasos):
    degradado = []
    for i in range(pasos + 1):
        posicion = i / pasos
        color = interpolar_color(color_inicio, color_fin, posicion)
        codigo_ansi = rgb_a_codigo_ansi(color)
        degradado.append(codigo_ansi)
    return degradado

def print_banner():
    global VERSION 
    banner = f"""
 ::::::::    :::      :::::::::  :::::::::: ::::::::  :::::::::: :::::::::     :::      ::::::::  
:+:   :+:    :+: :+:    :+:   :+: :+:          :+:   :+: :+:          :+:   :+:     :+: :+:    :+: 
+:+          +:+   +:+  +:+   +:+ +:+          +:+           +:+          +:+   +:+    +:+   
+#+          +#++:++#++:+#++:++#+  +#++:++#  +#+           +#++:++#      +#++:++#:  +#++:++#++:+#++:++#++
+#+          +#+   +#+ +#+   +#+ +#+          +#+           +#+          +#+   +#+  +#+   +#+     +#+
#+#   #+# #+#   #+# #+#   #+# #+#          #+#   #+# #+#          #+#   #+#  #+#   #+# #+#   #+#
 ########  ###   ### #########  ########## ########  ########## ###   ###  ###   ###  ########  
                                                                                             {VERSION}
    """   
    color_inicio = colores[random.choice(list(colores.keys()))]
    color_fin = colores[random.choice(list(colores.keys()))]
    degradado = generar_degradado_colores(color_inicio, color_fin, len(banner.splitlines()))
    for i, line in enumerate(banner.splitlines()):
        print(degradado[i % len(degradado)] + line + "\033[0m")

# Funciones de procesamiento
def normalize_url(url):
    parsed_url = urlparse(url)
    if not parsed_url.scheme:
        parsed_url = parsed_url._replace(scheme='http')
    if parsed_url.port is None:
        if parsed_url.scheme == 'http':
            port = 80
        elif parsed_url.scheme == 'https':
            port = 443
        else:
            raise ValueError("Esquema no soportado. Usa 'http' o 'https'.")
        netloc = f"{parsed_url.hostname}:{port}"
        normalized_url = urlunparse(parsed_url._replace(netloc=netloc))
    else:
        normalized_url = url
    return normalized_url

def get_ip(url):
    if not url or not url.startswith(("http://", "https://")):
        return None
    parsed_url = urlparse(url)
    if not parsed_url.netloc:
        return None
    try:
        domain = parsed_url.netloc.split(':')[0]
        addr_info = socket.getaddrinfo(domain, None)
        ip = addr_info[0][4][0]
        return f"{ip} ({get_ip_type(ip)})"
    except (socket.gaierror, IndexError):
        return None

def get_ip_type(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return "IPv4" if ip_obj.version == 4 else "IPv6"
    except ValueError:
        return "Invalid IP"

def parse_headers(header_strings):
    headers = {}
    for raw_header in header_strings:
        try:
            key, value = raw_header.split(':', 1)
            headers[key.strip()] = value.strip()
        except ValueError:
            print(f"{Fore.YELLOW}[!] Error: Formato inválido en cabecera: {raw_header}{Style.RESET_ALL}")
    return headers

def load_body(body_arg):
    try:
        with open(body_arg, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, IsADirectoryError):
        try:
            return json.loads(body_arg)
        except json.JSONDecodeError:
            print(f"{Fore.RED}[!] Error: Formato JSON inválido: {body_arg}{Style.RESET_ALL}")
            return None

def verificar_redireccion_http_https(url):
    """Rescatado del script ancestral: verifica que HTTP redirija a HTTPS.

    Fix sobre la original: se solicita explícitamente el endpoint http://
    (la versión vieja pedía la URL https://, haciendo el test ambiguo).
    Verificación: status 301/302/307/308 con Location https://. Solo modo URL
    (no aplica a analisis desde JSON). Devuelve dict con claves:
      verificado (bool: se pudo realizar la prueba), redirige (bool/None), detalle (str).
    """
    resultado = {"verificado": False, "redirige": None, "detalle": ""}
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.netloc:
        resultado["detalle"] = "Solo se puede verificar sobre una URL https:// valida."
        return resultado
    try:
        resp = requests.get(f"http://{parsed.netloc}", allow_redirects=False, timeout=10)
        code = resp.status_code
        loc = (resp.headers.get("Location") or "").strip()
        if code in (301, 302, 307, 308) and loc.lower().startswith("https://"):
            resultado.update({"verificado": True, "redirige": True,
                              "detalle": f"HTTP responde {code} y redirige a {loc}"})
        elif code in (301, 302, 307, 308):
            resultado.update({"verificado": True, "redirige": False,
                              "detalle": f"HTTP responde {code} pero Location no es HTTPS: {loc or '(vacío)'}"})
        else:
            resultado.update({"verificado": True, "redirige": False,
                              "detalle": f"HTTP responde {code} sin redirección (sitio accesible en claro)"})
    except requests.RequestException as e:
        resultado["detalle"] = f"No se pudo conectar por HTTP (puerto 80 cerrado o filtrado): {type(e).__name__}"
    return resultado


def print_status(response_data):
    data = []
    if 'url' in response_data:
        data.append(["URL", response_data['url']])
    if 'http_version' in response_data:
        data.append(["HTTP", response_data['http_version']])
    if 'status_code' in response_data:
        data.append(["Código de estado", response_data['status_code']])
    if 'location' in response_data:
        data.append(["Location", response_data['location']])
    if 'status_description' in response_data:
        data.append(["Descripción", response_data['status_description']])
    
    if data:
        table = tabulate(data, tablefmt="grid", stralign="left", numalign="right")
        print(f"\n{Fore.CYAN}[+] Información de respuesta{Style.RESET_ALL}")
        print(table)

def print_header(headers):
    total_headers = len(headers)
    print(f"\n{Fore.CYAN}[+] Total de Headers: {total_headers}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[+] Headers actuales{Style.RESET_ALL}")
    for i, (key, value) in enumerate(headers.items(), start=1):
        print(f"[{str(i).zfill(2)}] {key}: {value}")

 
HEADER_REMOVE_NOTES = {
    "Server": {
        "observation": "Expone el servidor web utilizado por la aplicación.",
        "risk": "Puede facilitar fingerprinting del stack tecnológico, aunque no se observa versión explícita en el valor.",
        "suggestion": "Evaluar ocultar o suprimir esta cabecera si no es necesaria operativamente."
    },
    "X-Powered-By": {
        "observation": "Expone la tecnología, framework o plataforma que procesa la respuesta.",
        "risk": "Puede facilitar fingerprinting y, en algunos casos, revelar versión o componente interno.",
        "suggestion": "Eliminarla desde el framework, proxy inverso o servidor web cuando sea posible."
    },
    "X-AspNet-Version": {
        "observation": "Expone la versión del framework ASP.NET.",
        "risk": "Facilita enumeración tecnológica y correlación con vulnerabilidades conocidas.",
        "suggestion": "Deshabilitar su envío desde la configuración de la aplicación o servidor."
    },
    "X-Php-Version": {
        "observation": "Expone la versión de PHP.",
        "risk": "Permite identificar con precisión la plataforma y su posible superficie de ataque.",
        "suggestion": "Removerla si no es requerida por compatibilidad."
    },
    "Via": {
        "observation": "Expone el uso de proxies o CDNs (como CloudFront) y sus nombres de host internos.",
        "risk": "Revela detalles de la topología de red y puntos de presencia (PoP).",
        "suggestion": "Configurar CloudFront para omitir o anonimizar la cabecera Via."
    },
    "X-Amz-Cf-Pop": {
        "observation": "Identifica el punto de presencia (Edge Location) específico de CloudFront.",
        "risk": "Proporciona información geográfica y de infraestructura de la CDN.",
        "suggestion": "Eliminar mediante funciones Edge (Lambda@Edge o CloudFront Functions) antes de entregar al cliente."
    },
    "X-Amzn-RequestId": {
        "observation": "Expone el ID de solicitud generado por AWS API Gateway.",
        "risk": "Aunque es para tracking, revela el uso de servicios específicos de AWS.",
        "suggestion": "Mapear o eliminar esta cabecera en la respuesta del API Gateway si no es necesaria para el cliente."
    },
    "Server-Timing": {
        "observation": "Filtra el rendimiento de middleware/componentes internos (nombres de handlers, pipelines).",
        "risk": "Fingerprinting del stack: revela el uso del middleware Server Timing y detalles de tiempos internos.",
        "suggestion": "Remover o anonimizar en produccion; habilitarlo solo en ambientes de desarrollo/diagnostico."
    }
}

def suggest_headers_to_remove(headers):
    suggest_remove = [
        "$wsep", "Host-Header", "K-Proxy-Request", "Liferay-Portal", "OracleCommerceCloud-Version",
        "Pega-Host", "Powered-By", "Product", "Server", "Server-Timing", "SourceMap", "X-AspNet-Version",
        "X-AspNetMvc-Version", "X-Atmosphere-error", "X-Atmosphere-first-request",
        "X-Atmosphere-tracking-id", "X-B3-ParentSpanId", "X-B3-Sampled", "X-B3-SpanId",
        "X-B3-TraceId", "X-BEServer", "X-Backside-Transport", "X-CF-Powered-By", "X-CMS",
        "X-CalculatedBETarget", "X-Cocoon-Version", "X-Content-Encoded-By", "X-DiagInfo",
        "X-Envoy-Attempt-Count", "X-Envoy-External-Address", "X-Envoy-Internal",
        "X-Envoy-Original-Dst-Host", "X-Envoy-Upstream-Service-Time", "X-FEServer",
        "X-Framework", "X-Generated-By", "X-Generator", "X-Jitsi-Release", "X-Magento-Tags",
        "X-Joomla-Version", "X-Kubernetes-PF-FlowSchema-UI", "X-Kubernetes-PF-PriorityLevel-UID",
        "X-LiteSpeed-Cache", "X-LiteSpeed-Purge", "X-LiteSpeed-Tag", "X-LiteSpeed-Vary",
        "X-Litespeed-Cache-Control", "X-Mod-Pagespeed", "X-Nextjs-Cache",
        "X-Nextjs-Matched-Path", "X-Nextjs-Page", "X-Nextjs-Redirect", "X-OWA-Version",
        "X-Old-Content-Length", "X-OneAgent-JS-Injection", "X-Page-Speed", "X-Php-Version",
        "X-Powered-By", "X-Powered-By-Plesk", "X-Powered-CMS", "X-Redirect-By",
        "X-Server-Powered-By", "X-SourceFiles", "X-SourceMap", "X-Turbo-Charged-By",
        "X-Umbraco-Version", "X-Varnish-Backend", "X-Varnish-Server", "X-dtAgentId",
        "X-dtHealthCheck", "X-dtInjectedServlet", "X-ruxit-JS-Agent", "Via", "X-Amz-Cf-Pop", 
        "X-Amz-Cf-Id", "X-Amzn-RequestId", "X-Amz-Apigw-Id",
        "X-Amzn-Remapped-Connection", "X-Amzn-Remapped-Date"
    ]

    normalized_headers = {k.lower(): v for k, v in headers.items()}
    present_suggestions = {
        header: normalized_headers[header.lower()]
        for header in suggest_remove
        if header.lower() in normalized_headers
    }

    if present_suggestions:
        print(f"{Fore.CYAN}\n[!] Información Adicional:  Cabeceras que podrían eliminarse (Exposición de Tecnología):{Style.RESET_ALL} ")
        for header, value in present_suggestions.items():
            note = HEADER_REMOVE_NOTES.get(header, {
                "observation": "Expone información de tecnología, proxy o componentes internos.",
                "risk": "Puede facilitar fingerprinting y enumeración del stack tecnológico.",
                "suggestion": "Evaluar su eliminación si no es estrictamente necesaria."
            })

            print(f"[!] Cabecera: {Fore.RED}{header}{Style.RESET_ALL} = {value}")
            print(f"    {Fore.YELLOW}Observación:{Style.RESET_ALL} {note['observation']}")
            print(f"    {Fore.RED}Riesgo:{Style.RESET_ALL} {note['risk']}")
            print(f"    {Fore.GREEN}Sugerencia:{Style.RESET_ALL} {note['suggestion']}")
    else:
        print("\n[+] No se detectaron cabeceras de exposición tecnológica sugeridas para remoción.")
        
        
def print_security_headers(headers):
    findings = 0    
    security_headers = [
        "Content-Security-Policy",
        "X-XSS-Protection",
        "X-Frame-Options",
        "Referrer-Policy",
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "Permissions-Policy"
    ]

    normalized_headers = {k.lower(): v for k, v in headers.items()}
    present_headers = [h for h in security_headers if h.lower() in normalized_headers]
    missing_headers = [h for h in security_headers if h.lower() not in normalized_headers]

    def get_header(name):
        return normalized_headers.get(name.lower())

    def remove_from_missing(header_name):
        if header_name in missing_headers:
            missing_headers.remove(header_name)

    def print_block(title, level="warn", actual=None, risk=None, suggestion=None, comment=None, refs=None):
        if level == "warn":
            prefix = f"[!] {Fore.RED}"
        elif level == "info":
            prefix = f"[*] {Fore.CYAN}"
        else:
            prefix = f"[*] {Fore.GREEN}"

        print(f"{prefix}{title}{Style.RESET_ALL}")
        if actual is not None:
            print(f"    {Fore.YELLOW}Actual:{Style.RESET_ALL} {actual}")
        if risk:
            print(f"    {Fore.RED}Riesgo:{Style.RESET_ALL} {risk}")
        if suggestion:
            print(f"    {Fore.GREEN}Sugerencia:{Style.RESET_ALL} {suggestion}")
        if comment:
            print(f"    {Fore.CYAN}Comentario:{Style.RESET_ALL} {comment}")
        if refs:
            print(f"    {Fore.MAGENTA}Referencias:{Style.RESET_ALL}")
            for ref in refs:
                print(f"      - {ref}")

    # X-Frame-Options
    xfo = get_header("X-Frame-Options")
    if xfo:
        xfo_upper = xfo.strip().upper()
        if "ALLOW-FROM" in xfo_upper:
            print_block(
                "Observación en X-Frame-Options",
                level="warn",
                actual=xfo,
                risk="Cabecera presente con una directiva obsoleta o con soporte limitado en navegadores modernos.",
                suggestion="Usar 'DENY' o 'SAMEORIGIN'. Si se requiere permitir orígenes específicos, implementar 'Content-Security-Policy' con 'frame-ancestors'.",
                comment="La cabecera existe, pero su valor actual no ofrece una protección confiable y consistente frente a Clickjacking.",
                refs=[
                    "MDN X-Frame-Options: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Frame-Options",
                    "OWASP Clickjacking Defense Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html"
                ]
            )
        elif xfo_upper not in ["DENY", "SAMEORIGIN"]:
            print_block(
                "Observación en X-Frame-Options",
                level="warn",
                actual=xfo,
                risk="Cabecera presente con un valor no estándar o no ideal para protección frente a Clickjacking.",
                suggestion="Definir 'DENY' o 'SAMEORIGIN' según la necesidad funcional de la aplicación.",
                comment="Si la aplicación debe ser embebida solo por orígenes específicos, preferir CSP con 'frame-ancestors'.",
                refs=[
                    "MDN X-Frame-Options: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Frame-Options"
                ]
            )
        else:
            print_block(
                "Cabecera aplicada correctamente",
                level="ok",
                actual=xfo,
                comment="La configuración es consistente con buenas prácticas para mitigación de Clickjacking.",
                refs=[
                    "MDN X-Frame-Options: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Frame-Options"
                ]
            )

    # X-XSS-Protection
    x_xss_protection = get_header("X-XSS-Protection")
    if x_xss_protection:
        findings += 1
        val = x_xss_protection.strip().lower()

        if val not in ["0", "1; mode=block"]:
            print_block(
                "Observación en X-XSS-Protection",
                level="info",
                actual=x_xss_protection,
                risk="La cabecera corresponde a un mecanismo heredado y su valor actual puede no alinearse con buenas prácticas modernas.",
                suggestion="Mantenerla solo si existe una necesidad de compatibilidad legacy; priorizar CSP como control principal frente a XSS.",
                comment="No debe considerarse una medida de seguridad principal en navegadores modernos.",
                refs=[
                    "MDN X-XSS-Protection: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-XSS-Protection",
                    "OWASP HTTP Headers Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"
                ]
            )
        else:
            print_block(
                "Cabecera legacy implementada",
                level="info",
                actual=x_xss_protection,
                comment="La cabecera está presente, pero se considera obsoleta y no debe tratarse como control principal.",
                refs=[
                    "MDN X-XSS-Protection: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-XSS-Protection"
                ]
            )
    # Strict-Transport-Security
    hsts = get_header("Strict-Transport-Security")
    if hsts:
        hsts_lower = hsts.lower()
        if "max-age=" not in hsts_lower:
            print_block(
                "Observación en Strict-Transport-Security",
                level="warn",
                actual=hsts,
                risk="La política HSTS puede no aplicarse correctamente si no define un max-age explícito.",
                suggestion="Definir al menos 'max-age=31536000' y evaluar 'includeSubDomains' según el alcance del dominio.",
                comment="La ausencia de max-age limita la efectividad del mecanismo.",
                refs=[
                    "MDN Strict-Transport-Security: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Strict-Transport-Security"
                ]
            )
        elif "includeSubDomains" not in hsts and "includesubdomains" not in hsts_lower:
            print_block(
                "Observación en Strict-Transport-Security",
                level="info",
                actual=hsts,
                risk="La política protege el dominio principal, pero no necesariamente todos los subdominios.",
                suggestion="Evaluar 'includeSubDomains' si corresponde al alcance operativo.",
                comment="La configuración actual es válida, aunque puede fortalecerse.",
                refs=[
                    "MDN Strict-Transport-Security: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Strict-Transport-Security"
                ]
            )
        elif "preload" not in hsts_lower:
            print_block(
                "Observación en Strict-Transport-Security",
                level="info",
                actual=hsts,
                risk="La configuración es sólida, aunque no participa en el programa de precarga del navegador.",
                suggestion="Evaluar opcionalmente 'preload' si el dominio cumple requisitos operativos y se desea endurecer aún más el uso exclusivo de HTTPS.",
                comment="La política actual puede considerarse correcta; 'preload' corresponde a una mejora opcional.",
                refs=[
                    "MDN Strict-Transport-Security: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Strict-Transport-Security",
                    "HSTS Preload: https://hstspreload.org"
                ]
            )
        else:
            print_block(
                "Cabecera aplicada correctamente",
                level="ok",
                actual=hsts,
                comment="La configuración HSTS es sólida y adecuada para forzar HTTPS.",
                refs=[
                    "MDN Strict-Transport-Security: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Strict-Transport-Security"
                ]
            )

    # X-Content-Type-Options
    xcto = get_header("X-Content-Type-Options")
    if xcto:
        if xcto.strip().lower() != "nosniff":
            print_block(
                "Observación en X-Content-Type-Options",
                level="warn",
                actual=xcto,
                risk="Un valor distinto a 'nosniff' puede permitir interpretación errónea del tipo de contenido por parte del navegador.",
                suggestion="Usar 'nosniff'.",
                comment="Ayuda a mitigar escenarios de MIME sniffing.",
                refs=[
                    "OWASP HTTP Headers Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"
                ]
            )
        else:
            print_block(
                "Cabecera aplicada correctamente",
                level="ok",
                actual=xcto,
                comment="La cabecera está bien configurada y reduce riesgos asociados a MIME sniffing.",
                refs=[
                    "OWASP HTTP Headers Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"
                ]
            )

    # Referrer-Policy
    referrer = get_header("Referrer-Policy")
    if referrer:
        rp = referrer.strip().lower()
        if rp not in ["strict-origin-when-cross-origin", "strict-origin", "same-origin", "no-referrer"]:
            print_block(
                "Observación en Referrer-Policy",
                level="warn",
                actual=referrer,
                risk="La política puede exponer más información de referencia de la necesaria hacia dominios externos.",
                suggestion="Configurar 'strict-origin-when-cross-origin' o 'no-referrer' según el nivel de privacidad requerido.",
                comment="El valor actual debería revisarse para evitar filtración de URLs o rutas internas.",
                refs=[
                    "MDN Referrer-Policy: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referrer-Policy",
                    "W3C Referrer Policy: https://www.w3.org/TR/referrer-policy/"
                ]
            )
        else:
            print_block(
                "Cabecera aplicada correctamente",
                level="ok",
                actual=referrer,
                comment="La política actual es razonable y acorde a buenas prácticas de privacidad.",
                refs=[
                    "MDN Referrer-Policy: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referrer-Policy"
                ]
            )

    # Content-Security-Policy
    xfo_ok_csp = xfo is not None and xfo.strip().upper() in ("DENY", "SAMEORIGIN")
    csp = get_header("Content-Security-Policy")
    if csp:
        csp_lower = csp.lower()
        comments = []
        if "default-src" not in csp_lower:
            comments.append("No se observa 'default-src', recomendable como base de restricción.")
        if "frame-ancestors" not in csp_lower:
            if xfo_ok_csp:
                comments.append("Sin 'frame-ancestors'; la protección frente a Clickjacking la aporta hoy X-Frame-Options.")
            else:
                comments.append("No se observa 'frame-ancestors' ni una X-Frame-Options restrictiva; riesgo de Clickjacking.")
        if "object-src" not in csp_lower:
            comments.append("No se observa 'object-src', recomendable para restringir contenido embebido legado.")
        if comments:
            print_block(
                "Observación en Content-Security-Policy",
                level="info",
                actual=csp,
                suggestion="Revisar la política actual y fortalecerla según los recursos legítimos requeridos por la aplicación.",
                comment=" ".join(comments),
                refs=[
                    "OWASP CSP Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
                    "MDN CSP Guide: https://developer.mozilla.org/en-US/docs/Web/Security/Practical_implementation_guides/CSP"
                ]
            )
        else:
            print_block(
                "Cabecera aplicada correctamente",
                level="ok",
                actual=csp,
                comment="La política CSP observada contiene directivas base razonables y aporta una capa fuerte de endurecimiento.",
                refs=[
                    "OWASP CSP Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"
                ]
            )
        # Nota: el análisis profundo directiva por directiva (v1.1+) se emite desde
        # main() justo después de esta sección, siguiendo el orden de lectura del reporte.

    # Permissions-Policy
    permissions = get_header("Permissions-Policy")
    if permissions:
        print_block(
            "Observación en Permissions-Policy",
            level="info",
            actual=permissions,
            comment="La cabecera está presente; conviene revisar que solo habilite capacidades estrictamente necesarias.",
            refs=[
                "OWASP Secure Headers Project: https://owasp.org/www-project-secure-headers/"
            ]
        )

    return csp, xfo


def resumen_inventario_cabeceras(headers):
    """Inventario y resumen ejecutivo de cabeceras de seguridad (v1.2.0).

    Se emite AL INICIO del reporte (justo tras el estado HTTP) para dar panorama
    general antes de los bloques detallados: qué está implementado, qué falta y
    el conteo rápido. Reduce la fatiga cognitiva de lectura del reporte."""
    security_headers = [
        "Content-Security-Policy",
        "X-Frame-Options",
        "Referrer-Policy",
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "Permissions-Policy",
    ]
    normalized_headers = {k.lower(): v for k, v in headers.items()}
    presentes = [h for h in security_headers if h.lower() in normalized_headers]
    faltantes = [h for h in security_headers if h.lower() not in normalized_headers]

    print(f"\n{Fore.CYAN}{Style.BRIGHT}Inventario de cabeceras de seguridad (resumen ejecutivo){Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'-' * 56}{Style.RESET_ALL}")
    if presentes:
        for header in presentes:
            print(f"[*] {Fore.GREEN}{header}{Style.RESET_ALL} presente.")
    else:
        print(f"{Fore.YELLOW}No se encontraron cabeceras de seguridad implementadas.{Style.RESET_ALL}")
    if faltantes:
        for header in faltantes:
            print(f"[!] Falta la cabecera de seguridad: {Fore.YELLOW}{header}{Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}Todas las cabeceras relevantes evaluadas están presentes.{Style.RESET_ALL}")
    print(f"\nTotal de cabeceras implementadas: {Fore.GREEN}{len(presentes)}{Style.RESET_ALL}")
    print(f"Total de cabeceras faltantes: {Fore.RED}{len(faltantes)}{Style.RESET_ALL}")

def suggest_cache_headers(headers):
    cache_checks = {
        "Cache-Control": ["no-store", "no-cache", "must-revalidate", "max-age=0", "s-maxage=0"],
        "Pragma": ["no-cache"],
        "Expires": ["0"]
    }

    normalized_headers = {k.lower(): v for k, v in headers.items()}
    present_cache = {}

    for header, expected_values in cache_checks.items():
        value = normalized_headers.get(header.lower())
        if value is not None:
            present_cache[header] = value

    if present_cache:
        print(f"\n[!] Cabeceras de caché detectadas:")
        for header, value in present_cache.items():
            print(f"[!] Cabecera: {Fore.CYAN}{header}{Style.RESET_ALL} = {value}")

            if header.lower() == "cache-control":
                if "no-store" in value.lower():
                    print(f"    {Fore.GREEN}Observación:{Style.RESET_ALL} La respuesta evita almacenamiento en caché.")
                elif "no-cache" in value.lower():
                    print(f"    {Fore.YELLOW}Observación:{Style.RESET_ALL} La respuesta puede almacenarse, pero requiere revalidación antes de reutilizarse.")
                else:
                    print(f"    {Fore.RED}Observación:{Style.RESET_ALL} No se observa una directiva fuerte para proteger contenido sensible.")
                print(f"    {Fore.GREEN}Sugerencia:{Style.RESET_ALL} Mantener no-store en contenido sensible; complementar con must-revalidate, max-age=0 y s-maxage=0 según aplique.")

            elif header.lower() == "pragma":
                print(f"    {Fore.YELLOW}Observación:{Style.RESET_ALL} Directiva heredada para compatibilidad con clientes HTTP/1.0.")
                print(f"    {Fore.GREEN}Sugerencia:{Style.RESET_ALL} Usarla como complemento de Cache-Control, no como reemplazo.")

            elif header.lower() == "expires":
                print(f"    {Fore.YELLOW}Observación:{Style.RESET_ALL} Un valor 0 ayuda a invalidar contenido almacenado.")
                print(f"    {Fore.GREEN}Sugerencia:{Style.RESET_ALL} Mantenerlo alineado con Cache-Control y Pragma.")

    else:
        print(f"\n[+] No se detectaron cabeceras de caché explícitas.")
        print(f"    {Fore.YELLOW}Sugerencia:{Style.RESET_ALL} Para contenido sensible, agregar Cache-Control: no-store, no-cache, must-revalidate, max-age=0, s-maxage=0; Pragma: no-cache; Expires: 0.")
        
def print_special_headers(headers):
    special_headers = [
        "Access-Control-Allow-Origin", "Access-Control-Allow-Methods",
        "Access-Control-Allow-Headers", "Content-Security-Policy-Report-Only"
    ]
    present_headers = [header for header in special_headers if header in headers]
    if present_headers:
        print(f"\nCabeceras especiales presentes:")
        for header in present_headers:
            print(f"[*] Cabecera {Fore.GREEN}{header}{Style.RESET_ALL} está presente!")
            
            
# ============================================================
# ANÁLISIS PROFUNDO DE CSP (v1.1.0) - Evaluación directiva por directiva
# Semántica alineada con CSP Evaluator (Google, CSP v3):
#   - Familia script: 'unsafe-inline' / 'unsafe-eval' / data: / wildcard /
#     http: = Alta; 'self' = Posible alta (JSONP/AngularJS/uploads);
#     hosts allowlistados = Info (sin bypass conocido); 'https:' = Media.
#   - Familia style: 'unsafe-inline' / data: / wildcard = Media
#     (exfiltración de datos basada en estilos).
#   - Directivas recomendables ausentes: form-action, base-uri,
#     object-src 'none', frame-ancestors (NO hereda de default-src),
#     upgrade-insecure-requests, report-uri / report-to.
# ============================================================

FAMILIA_SCRIPT_CSP = ("script-src", "script-src-elem", "script-src-attr")
FAMILIA_WORKER_CSP = ("worker-src", "child-src")
FAMILIA_STYLE_CSP = ("style-src", "style-src-elem", "style-src-attr")
FAMILIA_OTRAS_CSP = ("font-src", "img-src", "media-src", "frame-src", "connect-src", "manifest-src")

_ETIQUETA_SEV = {
    "alta": "Alta",
    "posible_alta": "Posible alta",
    "media": "Media",
    "baja": "Baja",
    "info": "Info",
}
_ORDEN_SEV = {"alta": 0, "posible_alta": 1, "media": 2, "baja": 3, "info": 4}
# Esquema cromático de hallazgos (UI/UX de terminal):
#   RED    -> exclusivo de hallazgos críticos (severidad Alta)
#   YELLOW -> Media y Posible alta (advertencias que requieren contexto)
#   CYAN   -> Baja/Info, directivas y metadatos neutrales
#   GREEN  -> configuraciones correctas y sugerencias de mitigación
#   MAGENTA-> referencias/enlaces de documentación
_COLOR_SEV = {
    "alta": Fore.RED,
    "posible_alta": Fore.YELLOW,
    "media": Fore.YELLOW,
    "baja": Fore.CYAN,
    "info": Fore.CYAN,
}

# Color de la etiqueta "Riesgo:" según severidad (RED solo en criticidad Alta)
_COLOR_RIESGO = {
    "alta": Fore.RED,
    "posible_alta": Fore.YELLOW,
    "media": Fore.YELLOW,
    "baja": Fore.CYAN,
    "info": Fore.CYAN,
}
_MARCA_SEV = {"alta": "[!]", "posible_alta": "[!]", "media": "[!]", "baja": "[*]", "info": "[*]"}

_REFS_CSP_BASE = [
    "OWASP CSP Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
    "MDN CSP Guide: https://developer.mozilla.org/en-US/docs/Web/Security/Practical_implementation_guides/CSP",
    "Google CSP Evaluator: https://csp-evaluator.withgoogle.com/",
]
_REFS_CSP_NONCE = [
    "PortSwigger Web Security Academy - CSP: https://portswigger.net/web-security/content-security-policy",
]
_REFS_CSP_FORM = [
    "PortSwigger Research - Stealing passwords from infosec Mastodon without bypassing CSP: https://portswigger.net/research/stealing-passwords-from-infosec-mastodon-without-bypassing-csp",
    "PortSwigger Web Security Academy - CSP: https://portswigger.net/web-security/content-security-policy",
]


def parsear_csp(csp_value):
    """Divide una política CSP en directivas conservando el orden y los tokens
    originales ('self', 'nonce-...', hashes sha-*-). Las directivas repetidas
    combinan sus tokens (coherente con políticas compuestas / listas)."""
    directivas = {}
    orden = []
    for parte in csp_value.split(";"):
        parte = parte.strip()
        if not parte:
            continue
        tokens = parte.split()
        if not tokens:
            continue
        nombre = tokens[0].lower()
        if nombre not in directivas:
            directivas[nombre] = list(tokens[1:])
            orden.append(nombre)
        else:
            directivas[nombre].extend(list(tokens[1:]))
    return directivas, orden


def csp_efectiva(directivas, nombre, fallbacks):
    """Resolución CSP3: una directiva hereda del primer fallback declarado cuando
    no está definida. Devuelve (etiqueta_mostrada, tokens); tokens es None si no
    existe política efectiva."""
    if nombre in directivas:
        return nombre, list(directivas[nombre])
    for fb in fallbacks:
        if fb in directivas:
            return f"{nombre} (heredada de {fb})", list(directivas[fb])
    return f"{nombre} (sin política)", None


def _es_nonce_csp(tokens):
    return any(t.lower().startswith("'nonce-") for t in tokens)


def _es_hash_csp(tokens):
    return any(re.match(r"^'sha(256|384|512)-", t.lower()) for t in tokens)


def _token_host_csp(tok):
    """True si el token es un host allowlistado (no keyword, esquema suelto ni wildcard)."""
    t = tok.strip()
    if not t or t.startswith("'"):
        return False
    bajo = t.lower()
    if bajo in ("*", "http:", "https:", "ws:", "wss:", "data:", "blob:", "filesystem:"):
        return False
    return True  # hosts con o sin esquema explícito (code.iconify.design, https://cdn.x)


def evaluar_tokens_csp(nombre_directiva, tokens, familia="otras"):
    """Evalúa los tokens (fuentes) de UNA directiva CSP. Devuelve una lista de
    hallazgos dict(severidad, directiva, fuente, riesgo, sugerencia, refs, tokens).
    familia: 'script' | 'style' | 'otras'."""
    hallazgos = []

    def agregar(severidad, fuente, riesgo, sugerencia, refs=None):
        hallazgos.append({
            "severidad": severidad,
            "directiva": nombre_directiva,
            "fuente": fuente,
            "riesgo": riesgo,
            "sugerencia": sugerencia,
            "refs": list(refs or []),
            "tokens": list(tokens),
        })

    tiene_nonce = _es_nonce_csp(tokens)
    tiene_hash = _es_hash_csp(tokens)
    strict_dynamic = any(t.lower() == "'strict-dynamic'" for t in tokens)
    mitigado_nonce = tiene_nonce or tiene_hash or strict_dynamic

    for tok in tokens:
        bajo = tok.lower()

        if bajo == "'none'":
            continue  # fuente más segura posible; sin hallazgo

        elif bajo == "'unsafe-inline'":
            if familia == "script":
                if mitigado_nonce:
                    detalle = "'strict-dynamic'" if strict_dynamic else "nonce/hash"
                    agregar("info", tok,
                            f"En navegadores modernos 'unsafe-inline' queda IGNORADO cuando la directiva declara {detalle}; solo aporta el flag a navegadores antiguos.",
                            "Al retirar el soporte a navegadores legacy, eliminar 'unsafe-inline' y dejar solo el nonce/hash.")
                else:
                    agregar("alta", tok,
                            "'unsafe-inline' permite la ejecución de scripts y event handlers inseguros en la página (vector clásico de explotación de XSS).",
                            "Mitigar XSS evitando 'unsafe-inline', 'unsafe-eval', URLs data: y wildcards globales en directivas de script. Usar un nonce seguro aleatorio de al menos 8 caracteres ('nonce-RANDOM') sobre los recursos legítimos, o hashes SHA-256 si el contenido inline es estático.",
                            _REFS_CSP_NONCE)
            elif familia == "style":
                if mitigado_nonce:
                    agregar("info", tok,
                            "Con nonce/hash declarado, 'unsafe-inline' queda ignorado en navegadores modernos.",
                            "Al retirar soporte legacy, eliminar el flag y dejar solo el nonce.")
                else:
                    agregar("media", tok,
                            "'unsafe-inline' permite fuentes de estilo en línea y habilita exfiltración de datos basada en estilos (selectores y atributos CSS).",
                            "Mitigar la exfiltración de datos basada en estilos evitando 'unsafe-inline', URLs data: y wildcards globales en directivas de estilo. Usar un nonce seguro aleatorio de al menos 8 caracteres ('nonce-RANDOM') en la directiva correspondiente.",
                            _REFS_CSP_NONCE)
            else:
                if nombre_directiva == "default-src":
                    agregar("media", tok,
                            f"'unsafe-inline' en '{nombre_directiva}' queda heredado por directivas sin override (form-action, frame-src, connect-src...).",
                            "Reducir los flag inseguros de nivel base y declarar directivas explícitas ('form-action', 'frame-ancestors', 'connect-src'...) en lugar de confiar en el nivel base.")
                else:
                    agregar("media", tok,
                            f"'unsafe-inline' en '{nombre_directiva}' habilita el uso en línea de este tipo de recurso; habitualmente es innecesario y debilita la directiva.",
                            "Limitar 'unsafe-inline' a las directivas que lo exigen realmente; usar nonces para el contenido legítimo en línea.")

        elif bajo == "'unsafe-eval'":
            if familia == "script":
                agregar("alta", tok,
                        "'unsafe-eval' permite la ejecución de código inyectado en APIs del DOM, como eval().",
                        "Eliminar 'unsafe-eval' de las directivas de script y migrar los usos de eval()/new Function() a alternativas seguras (JSON.parse, mecanismos del framework).",
                        _REFS_CSP_NONCE)

        elif bajo == "data:":
            if familia == "script":
                agregar("alta", tok,
                        "Permite ejecutar scripts desde URLs 'data:' (payloads codificados en la propia URL, burlando el bloqueo por dominio).",
                        "Eliminar 'data:' de las directivas de script; servir el recurso desde un origen confiable o usar nonces/hashes para el contenido legítimo.",
                        _REFS_CSP_NONCE)
            elif familia == "style":
                agregar("media", tok,
                        "Permite inyectar hojas de estilo desde URLs 'data:', canal clásico de exfiltración de datos basada en estilos.",
                        "Eliminar 'data:' de las directivas de estilo y usar nonce para la hoja inline legítima si es imprescindible.",
                        _REFS_CSP_NONCE)
            else:
                agregar("baja", tok,
                        "Permite recursos embebidos en la propia URL (no ejecutables como scripts); se usa a veces como canal auxiliar de exfiltración.",
                        "Evaluar si 'data:' es imprescindible en esta directiva; si no lo es, eliminarlo.")

        elif bajo == "*":
            if familia == "script":
                agregar("alta", tok,
                        "Wildcard global: permite cargar y ejecutar scripts desde cualquier host.",
                        "Eliminar el wildcard; permitir solo hosts concretos y preferir nonces/hashes para los scripts legítimos.",
                        _REFS_CSP_NONCE)
            elif familia == "style":
                agregar("media", tok,
                        "Wildcard global en estilos: permite cargar estilos desde cualquier host (exfiltración basada en estilos).",
                        "Allowlist de hosts concretos para los estilos legítimos y nonces para estilos inline.")
            else:
                agregar("baja", tok,
                        "Wildcard global para esta directiva: el recurso queda disponible desde cualquier origen.",
                        "Restringir el wildcard al listado concreto de hosts que la aplicación realmente necesita.")

        elif bajo == "http:":
            if familia == "script":
                agregar("alta", tok,
                        "Esquema suelto 'http:' en scripts: permite ejecución desde cualquier host por HTTP (contenido mixto si el sitio es HTTPS).",
                        "Eliminar esquemas sueltos de las directivas de script; usar listas concretas de hosts o nonces.",
                        _REFS_CSP_NONCE)
            elif familia == "style":
                agregar("media", tok,
                        "Esquema suelto 'http:' en estilos: permite cargar estilos desde cualquier host por HTTP.",
                        "Allowlist concreta de hosts y evitar esquemas sueltos.")
            else:
                agregar("baja", tok,
                        "Esquema suelto 'http:': permite contenido mixto si el sitio se sirve por HTTPS.",
                        "Si el sitio es HTTPS, eliminar 'http:' (complementar con 'upgrade-insecure-requests').")

        elif bajo == "https:":
            if familia == "script":
                agregar("media", tok,
                        "Esquema suelto 'https:' en scripts: permite ejecutar scripts desde cualquier host HTTPS.",
                        "Sustituir por allowlists concretas de hosts y preferir nonces frente a listas estáticas.",
                        _REFS_CSP_NONCE)
            elif familia == "style":
                agregar("baja", tok,
                        "Esquema suelto 'https:' en estilos: permite cargar estilos desde cualquier host HTTPS.",
                        "Allowlist concreta de hosts para estilos.")

        elif bajo in ("blob:", "filesystem:"):
            if familia == "script":
                agregar("media", tok,
                        "Permite ejecutar código desde URLs 'blob:'/'filesystem:', patrón frecuente en cadenas de bypass.",
                        "Evaluar si Workers o recursos blob: son imprescindibles; si lo son, restringirlo solo a 'worker-src'.")
            else:
                agregar("baja", tok,
                        "Permite Workers/recursos desde URLs 'blob:' (vector auxiliar en cadenas de gadgets).",
                        "Verificar que la aplicación realmente crea Workers con blob:; en caso contrario, eliminar.")

        elif bajo == "'self'":
            if familia == "script":
                agregar("posible_alta", tok,
                        "'self' puede ser problemático si el sitio aloja JSONP, librerías AngularJS (legacy) o archivos subidos por usuarios.",
                        "Auditar endpoints same-origin con contenido controlable por el usuario (JSONP, AngularJS, uploads). Reemplazar allowlists de script por nonces ('nonce-RANDOM'); si no es viable, separar el contenido de usuario a otro origen.",
                        _REFS_CSP_NONCE)

        elif _token_host_csp(tok):
            if familia == "script":
                agregar("info", tok,
                        "No se encontró bypass conocido; verificar que el host no sirva respuestas JSONP ni librerías de Angular.",
                        "Revisar el contenido que hoy sirve el host: una respuesta JSONP o una librería Angular legacy lo convertiría en bypass de la CSP. Las allowlists estáticas envejecen; preferir nonces.",
                        _REFS_CSP_NONCE)

        elif bajo == "'strict-dynamic'":
            pass  # se emite como nota verde en analizar_csp_profundo

    return hallazgos


def analizar_csp_profundo(csp_value, xfo_value=None):
    """Evaluación profunda de Content-Security-Policy, directiva por directiva
    (estilo CSP Evaluator). Imprime el detalle y devuelve la lista de hallazgos."""
    hallazgos = []
    if not csp_value or not csp_value.strip():
        return hallazgos

    directivas, orden = parsear_csp(csp_value)
    vistos = set()

    def sumar(nuevos):
        for h in nuevos:
            clave = (h["severidad"], h["directiva"], h["fuente"], h["riesgo"])
            if clave not in vistos:
                vistos.add(clave)
                hallazgos.append(h)

    script_declaradas = [d for d in FAMILIA_SCRIPT_CSP if d in directivas]
    worker_declaradas = [d for d in FAMILIA_WORKER_CSP if d in directivas]
    style_declaradas = [d for d in FAMILIA_STYLE_CSP if d in directivas]

    # 1) Directivas de script / worker declaradas (CADA una se evalúa, incluida script-src-elem)
    for d in script_declaradas + worker_declaradas:
        sumar(evaluar_tokens_csp(d, directivas[d], "script"))

    # 2) Directivas de estilo declaradas
    for d in style_declaradas:
        sumar(evaluar_tokens_csp(d, directivas[d], "style"))

    # 2b) Familias residuales declaradas con sus PROPIOS tokens (font-src, img-src,
    #     media-src, frame-src, connect-src, manifest-src); default-src se evalúa aparte.
    for d in FAMILIA_OTRAS_CSP:
        if d in directivas and d != "default-src":
            sumar(evaluar_tokens_csp(d, directivas[d], "otras"))

    script_desde_default = not (script_declaradas or worker_declaradas) and "default-src" in directivas
    style_desde_default = not style_declaradas and "default-src" in directivas

    # 3) Herencia CSP3 desde default-src cuando no hay directiva específica
    if script_desde_default:
        etiqueta, toks = csp_efectiva(directivas, "script-src", ("default-src",))
        sumar(evaluar_tokens_csp(etiqueta, toks, "script"))
    if style_desde_default:
        etiqueta, toks = csp_efectiva(directivas, "style-src", ("default-src",))
        sumar(evaluar_tokens_csp(etiqueta, toks, "style"))

    # 4) default-src residual (aplica a directivas sin override) si no se evaluó ya como script/style
    if "default-src" in directivas and not (script_desde_default or style_desde_default):
        sumar(evaluar_tokens_csp("default-src", directivas["default-src"], "otras"))

    # 5) Casos 'sin política'
    if not script_declaradas and not worker_declaradas and "default-src" not in directivas:
        sumar([{
            "severidad": "alta", "directiva": "script-src", "fuente": "(sin política)",
            "riesgo": "La política no restringe qué scripts puede ejecutar la página (sin 'script-src' ni 'default-src').",
            "sugerencia": "Definir 'script-src' ('self' + un nonce 'nonce-RANDOM' aleatorio por respuesta) o una 'default-src' restrictiva.",
            "refs": list(_REFS_CSP_NONCE), "tokens": [],
        }])
    if not style_declaradas and "default-src" not in directivas:
        sumar([{
            "severidad": "baja", "directiva": "style-src", "fuente": "(sin política)",
            "riesgo": "Sin 'style-src' ni 'default-src', estilos desde cualquier origen y en línea quedan permitidos (exfiltración basada en estilos).",
            "sugerencia": "Definir 'style-src' con los orígenes mínimos necesarios; para estilos inline usar nonce.",
            "refs": list(_REFS_CSP_NONCE), "tokens": [],
        }])

    # 6) Directivas recomendables ausentes
    if "form-action" not in directivas:
        sumar([{
            "severidad": "media", "directiva": "form-action", "fuente": "(directiva ausente)",
            "riesgo": "Los envíos de formularios (form post) no quedan acotados a destinos confiables; payloads inyectados pueden exfiltrar datos hacia orígenes externos.",
            "sugerencia": "Usar 'form-action' para controlar los destinos de los formularios. Si no se usan form actions, fijar 'form-action' en 'none' para bloquear formularios no confiables. Para aplicaciones sin URLs de formularios externas, usar 'self'. Si se requieren envíos a hosts externos, allowlist explícita (conscientes de que esos destinos podrían ser abusados).",
            "refs": list(_REFS_CSP_FORM), "tokens": [],
        }])

    if "base-uri" not in directivas:
        sumar([{
            "severidad": "media", "directiva": "base-uri", "fuente": "(directiva ausente)",
            "riesgo": "Sin 'base-uri', HTML inyectado puede manipular la base de las URLs relativas del documento con la etiqueta <base> (hijacking de URLs relativas).",
            "sugerencia": "Fijar 'base-uri' en 'none' o 'self' (no es heredada de 'default-src').",
            "refs": list(_REFS_CSP_BASE), "tokens": [],
        }])

    if "frame-ancestors" not in directivas:
        xfo_adequada = xfo_value is not None and xfo_value.strip().upper() in ("DENY", "SAMEORIGIN")
        if xfo_adequada:
            sumar([{
                "severidad": "baja", "directiva": "frame-ancestors", "fuente": "(directiva ausente)",
                "riesgo": f"El control de embedding lo aporta hoy X-Frame-Options ({xfo_value.strip()}); 'frame-ancestors' no es imprescindible en este punto.",
                "sugerencia": "Al migrar a CSP puro, incorporar 'frame-ancestors' explícita (no es heredada de 'default-src') y eliminar la dependencia de la cabecera legacy.",
                "refs": list(_REFS_CSP_BASE), "tokens": [],
            }])
        else:
            sumar([{
                "severidad": "media", "directiva": "frame-ancestors", "fuente": "(directiva ausente)",
                "riesgo": "Sin 'frame-ancestors' ni una X-Frame-Options restrictiva, la página puede embeberse en iframes de terceros (Clickjacking).",
                "sugerencia": "Añadir 'frame-ancestors' (p. ej. 'self' o 'none') o fijar X-Frame-Options: DENY/SAMEORIGIN.",
                "refs": list(_REFS_CSP_BASE), "tokens": [],
            }])

    obj_etiqueta, obj_tokens = csp_efectiva(directivas, "object-src", ("default-src",))
    if obj_tokens is None or not any(t.lower() == "'none'" for t in obj_tokens):
        actual_obj = f"Declarada: {' '.join(obj_tokens)}" if obj_tokens is not None else "(sin 'object-src' ni 'default-src')"
        sumar([{
            "severidad": "media", "directiva": "object-src", "fuente": "(sin 'none' o sin política)",
            "riesgo": "El contenido de objetos/plugins legados (embed/object) no queda bloqueado por completo.",
            "sugerencia": "Fijar 'object-src' en 'none' (recomendación estándar); si 'default-src' no es 'none', añadir el override explícito.",
            "refs": list(_REFS_CSP_BASE), "tokens": [],
            "actual": actual_obj,
        }])

    if "upgrade-insecure-requests" not in directivas:
        sumar([{
            "severidad": "baja", "directiva": "upgrade-insecure-requests", "fuente": "(directiva ausente)",
            "riesgo": "Los subrecursos HTTP no se auto-elevan a HTTPS en el navegador.",
            "sugerencia": "Añadir 'upgrade-insecure-requests' si el sitio se sirve por HTTPS.",
            "refs": list(_REFS_CSP_BASE), "tokens": [],
        }])

    if "report-uri" not in directivas and "report-to" not in directivas:
        sumar([{
            "severidad": "baja", "directiva": "report-uri / report-to", "fuente": "(sin reportado)",
            "riesgo": "Sin envío de reportes de violación es difícil medir el impacto real de la política en producción (ajustes finos y falsos positivos).",
            "sugerencia": "Considerar 'report-to' (o 'report-uri' legacy) y una fase en 'Content-Security-Policy-Report-Only' antes de endurecer.",
            "refs": list(_REFS_CSP_BASE), "tokens": [],
        }])

    # ---------- Impresión (estilo consistente con la herramienta) ----------
    linea = "=" * 70
    print(f"\n{Fore.CYAN}{linea}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{Style.BRIGHT}  Análisis profundo de Content-Security-Policy (directiva por directiva){Style.RESET_ALL}")
    print(f"{Fore.CYAN}{linea}{Style.RESET_ALL}")

    print(f"{Fore.CYAN}[*] Directivas declaradas ({len(orden)}):{Style.RESET_ALL}")
    for nombre in orden:
        print(f"    - {Fore.CYAN}{nombre}{Style.RESET_ALL}: {' '.join(directivas[nombre])}")

    csp_lower = csp_value.lower()
    if "'strict-dynamic'" in csp_lower:
        print(f"[*] {Fore.GREEN}Nota:{Style.RESET_ALL} Se detectó '{Fore.GREEN}strict-dynamic{Style.RESET_ALL}'. Degradan o anulan 'unsafe-inline' y los esquemas http:/https: para navegadores antiguos, añadiendo la política una capa mucho más robusta frente a XSS.")
    if "'nonce-" in csp_lower:
        print(f"[+] {Fore.GREEN}La política declara nonces ('nonce-...'): mitigación fuerte frente a XSS. Verificar que el nonce sea aleatorio por respuesta y de al menos 8 caracteres.{Style.RESET_ALL}")

    hallazgos.sort(key=lambda h: (_ORDEN_SEV[h["severidad"]], h["directiva"], h["fuente"]))
    for h in hallazgos:
        sev = h["severidad"]
        color = _COLOR_SEV[sev]
        print(f"\n{_MARCA_SEV[sev]} {color}[{_ETIQUETA_SEV[sev]}]{Style.RESET_ALL} {Fore.CYAN}{h['directiva']}{Style.RESET_ALL} -> {color}{h['fuente']}{Style.RESET_ALL}")
        valor_actual = h.get("actual")
        if not valor_actual:
            valor_actual = f"{h['directiva']}: {' '.join(h['tokens'])}" if h["tokens"] else h["fuente"]
        print(f"    {Fore.CYAN}Actual:{Style.RESET_ALL} {valor_actual}")
        print(f"    {_COLOR_RIESGO[sev]}Riesgo:{Style.RESET_ALL} {h['riesgo']}")
        print(f"    {Fore.GREEN}Sugerencia:{Style.RESET_ALL} {h['sugerencia']}")
        refs = list(dict.fromkeys(list(h.get("refs", [])) + _REFS_CSP_BASE))
        print(f"    {Fore.MAGENTA}Referencias:{Style.RESET_ALL}")
        for ref in refs:
            print(f"      - {ref}")

    conteo = {}
    for h in hallazgos:
        conteo[h["severidad"]] = conteo.get(h["severidad"], 0) + 1
    resumen = ", ".join(f"{_ETIQUETA_SEV[s]}: {conteo[s]}" for s in ("alta", "posible_alta", "media", "baja", "info") if conteo.get(s))
    print(f"\n[*] Hallazgos CSP: {resumen if conteo else 'ninguno'}")

    # ---------- Cierre de la sección (separador consistente con la apertura) ----------
    print(f"\n{Fore.CYAN}{linea}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{Style.BRIGHT}  [Resumen] Análisis profundo CSP: {resumen if conteo else 'sin hallazgos'}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{linea}{Style.RESET_ALL}")

    return hallazgos


def suggest_recommended_headers(headers):
    recommended_headers = {
        "Clear-Site-Data": {
            "value": "\"cache\",\"cookies\",\"storage\"",
            "comment": "Útil para limpiar artefactos del navegador tras cierre de sesión o eventos sensibles. Debe evaluarse según el flujo de autenticación de la aplicación.",
            "ref": "OWASP Secure Headers Project: https://owasp.org/www-project-secure-headers/"
        },
        "Content-Security-Policy": {
            "value": "default-src 'self'; form-action 'self'; object-src 'none'; frame-ancestors 'none'; upgrade-insecure-requests; block-all-mixed-content",
            "comment": "La política debe ajustarse a los recursos legítimos de la aplicación. Se recomienda comenzar con una política base y endurecerla progresivamente evitando 'unsafe-inline' y 'unsafe-eval'.",
            "ref": "MDN CSP Guide: https://developer.mozilla.org/en-US/docs/Web/Security/Practical_implementation_guides/CSP"
        },
        "Cross-Origin-Embedder-Policy": {
            "value": "require-corp",
            "comment": "Relevante cuando la aplicación necesita aislamiento de contexto para ciertas capacidades avanzadas del navegador. No siempre aplica a todos los sistemas.",
            "ref": "OWASP Secure Headers Project: https://owasp.org/www-project-secure-headers/"
        },
        "Cross-Origin-Opener-Policy": {
            "value": "same-origin",
            "comment": "Ayuda a aislar el contexto de navegación y reduce riesgos asociados a interacciones cross-origin no deseadas.",
            "ref": "OWASP Secure Headers Project: https://owasp.org/www-project-secure-headers/"
        },
        "Cross-Origin-Resource-Policy": {
            "value": "same-origin",
            "comment": "Permite restringir qué orígenes pueden cargar determinados recursos. Debe validarse según integraciones legítimas.",
            "ref": "OWASP Secure Headers Project: https://owasp.org/www-project-secure-headers/"
        },
        "Permissions-Policy": {
            "value": "accelerometer=(), autoplay=(), camera=(), cross-origin-isolated=(), display-capture=(), encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), keyboard-map=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), publickey-credentials-get=(), screen-wake-lock=(), sync-xhr=(self), usb=(), web-share=(), xr-spatial-tracking=(), clipboard-read=(), clipboard-write=(), gamepad=(), hid=(), idle-detection=(), interest-cohort=(), serial=(), unload=()",
            "comment": "La política debe ajustarse a las funcionalidades efectivamente requeridas por la aplicación; no conviene copiarla ciegamente en todos los contextos.",
            "ref": "OWASP Secure Headers Project: https://owasp.org/www-project-secure-headers/"
        },
        "Referrer-Policy": {
            "value": "strict-origin-when-cross-origin",
            "comment": "Suele ser una configuración equilibrada entre privacidad y compatibilidad. 'no-referrer' puede ser más restrictiva, pero no siempre es necesaria.",
            "ref": "MDN Referrer Policy Guide: https://developer.mozilla.org/en-US/docs/Web/Security/Practical_implementation_guides/Referrer_policy"
        },
        "X-Content-Type-Options": {
            "value": "nosniff",
            "comment": "Evita que el navegador interprete el tipo MIME de forma distinta a la declarada, mitigando ciertos escenarios de ejecución no deseada.",
            "ref": "OWASP HTTP Headers Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"
        },
        "X-Permitted-Cross-Domain-Policies": {
            "value": "none",
            "comment": "Restringe políticas cross-domain heredadas utilizadas por tecnologías antiguas como Adobe Flash o Acrobat.",
            "ref": "OWASP Secure Headers Project: https://owasp.org/www-project-secure-headers/"
        }
    }

    missing_headers = []

    print(f"{Fore.CYAN}\n Información Adicional: Sugerencias [Buenas prácticas - Faltantes]{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'-' * 53}{Style.RESET_ALL}")

    for header, meta in recommended_headers.items():
        if header.lower() not in {k.lower() for k in headers.keys()}:
            missing_headers.append((header, meta))

    if missing_headers:
        print(f"\n[!] Cabeceras recomendadas que podrían configurarse:")
        for header, meta in missing_headers:
            print(f"[!] Cabecera: {Fore.YELLOW}{header}{Style.RESET_ALL}")
            print(f"    {Fore.GREEN}Valor sugerido:{Style.RESET_ALL} {meta['value']}")
            print(f"    {Fore.CYAN}Comentario:{Style.RESET_ALL} {meta['comment']}")
            print(f"    {Fore.MAGENTA}Referencia:{Style.RESET_ALL} {meta['ref']}")
    else:
        print("No se detectaron cabeceras recomendadas faltantes.")

# ============================================================
# PLAN DE REMEDIACIÓN (v1.3.0) - Pasos accionables por hallazgo
# Estrategia de implementación general alineada (de apoyo) con
# SOC 2 (CC6.6, CC7.1, CC8.1) y PCI DSS v4.0 (Req 4.2.1, 6.2.3,
# 6.2.4, 6.4.2): se actúa a nivel servidor web / proxy inverso /
# CDN, complementando el código de la aplicación cuando aplica.
# ============================================================

_CSP_OBJETIVO = (
    "Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-XYZ'; "
    "object-src 'none'; base-uri 'self'; frame-ancestors 'none'; upgrade-insecure-requests; "
    "form-action 'self';"
)

_CODE_EXPRESS_NONCE = (
    "/* Node.js / Express: nonce criptografico por solicitud */\n"
    "const crypto = require('crypto');\n"
    "app.use((req, res, next) => {\n"
    "  const nonce = crypto.randomBytes(16).toString('base64');\n"
    "  res.setHeader('Content-Security-Policy',\n"
    "    \"default-src 'self'; script-src 'self' 'nonce-\" + nonce + \"'; \"\n"
    "    + \"object-src 'none'; base-uri 'self'; frame-ancestors 'none'; upgrade-insecure-requests\");\n"
    "  res.locals.cspNonce = nonce;   // usar en plantillas: <script nonce=...>\n"
    "  next();\n"
    "});"
)

_CODE_NGINX_HSTS = (
    "# nginx.conf (server block HTTPS)\n"
    "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;"
)

_CODE_APACHE_HSTS = (
    "# httpd.conf / VirtualHost HTTPS (mod_headers activo)\n"
    "Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\""
)

_CODE_NGINX_TOKENS = "server_tokens off;   # nginx.conf global"

_CODE_NGINX_CSP = (
    "# nginx (add_header no se anida: definir por server/location; el nonce NO lo\n"
    "# genera nginx, viene de la app/backend):\n"
    "# Fase 1 (auditoria):\n"
    'add_header Content-Security-Policy-Report-Only "default-src \'self\'; script-src \'self\' \'unsafe-inline\' \'unsafe-eval\'; report-uri https://tu-servidor/csp-reports" always;\n'
    "# Fase 2 (enforce tras cero violaciones):\n"
    'add_header Content-Security-Policy "default-src \'self\'; script-src \'self\' \'nonce-<generado-por-app>\'; object-src \'none\'; base-uri \'self\'; frame-ancestors \'none\'; upgrade-insecure-requests" always;'
)

_CODE_APACHE_CSP = (
    "# Apache: cabecera por VirtualHost (mod_headers activo)\n"
    "# Fase 1 (auditoria):\n"
    'Header always set Content-Security-Policy-Report-Only "default-src \'self\'; script-src \'self\' \'unsafe-inline\' \'unsafe-eval\'; report-uri https://tu-servidor/csp-reports"\n'
    "# Fase 2 (enforce):\n"
    'Header always set Content-Security-Policy "default-src \'self\'; script-src \'self\' \'nonce-<generado-por-app>\'"\n'
    "# Nota: el nonce debe generarlo la app (Apache no lo computa)."
)

_CODE_CLOUDFLARE_HSTS = (
    "# Cloudflare WAF - 2 opciones:\n"
    "#   a) Dashboard: SSL/TLS -> Edge Certificates -> HSTS (max-age, includeSubDomains,\n"
    "#      preload, no-sniff) -> aplicar por zona.\n"
    "#   b) Rules -> Transform Rules -> Modify Response Header -> Set header:\n"
    "#      Name: Strict-Transport-Security\n"
    "#      Value: max-age=31536000; includeSubDomains; preload"
)

_CODE_CLOUDFLARE_TR_CSP = (
    "# Cloudflare WAF (sin nonce): Rules -> Transform Rules /\n"
    "# Modify Response Header -> Set header:\n"
    "#   Name:  Content-Security-Policy\n"
    "#   Value: default-src 'self'; script-src 'self' 'https://cdn.app'; \\\n"
    "#          object-src 'none'; base-uri 'self'; frame-ancestors 'self'; \\\n"
    "#          upgrade-insecure-requests\n"
    "# IMPORTANTE: las Transform Rules no computan nonces por request;"
)

_CODE_CLOUDFLARE_WORKER = (
    "/* Cloudflare Worker: nonce dinamico por request (el WAF/T.R. no soporta nonce) */\n"
    "async function handleRequest(fresh) {\n"
    "  const respuesta = new Response(fresh.body, fresh);\n"
    "  const bytes = crypto.getRandomValues(new Uint8Array(16));\n"
    "  const nonce = btoa(String.fromCharCode(...bytes));\n"
    "  const csp = \"default-src 'self'; script-src 'self' 'nonce-\" + nonce + \"'; \"\n"
    "    + \"object-src 'none'; base-uri 'self'; frame-ancestors 'none'; upgrade-insecure-requests\";\n"
    "  respuesta.headers.set(\"Content-Security-Policy\", csp);\n"
    "  /* El HTML debe usar <script nonce=\"...\"> con ese MISMO nonce (reescribir body\n"
    "     requiere HTMLRewriter o que la app renderice el nonce en sus plantillas) */\n"
    "  return respuesta;\n"
    "}\n"
    "addEventListener('fetch', (event) => event.respondWith(handleRequest(event.request)));"
)

_CODE_AKAMAI_PM = (
    "# Akamai (WAF/CDN): las cabeceras se gestionan en Property Manager, no en el WAF:\n"
    "#   Property Manager -> Add rule -> 'Modify Response Header' behavior:\n"
    "#     - Set: Strict-Transport-Security = max-age=31536000; includeSubDomains; preload\n"
    "#     - Del: x-powered-by, x-generator\n"
    "#   HSTS: PM trae también un behavior 'HSTS' dedicado en versiones recientes."
)

_CODE_AKAMAI_EW = (
    "/* Akamai EdgeWorkers: nonce/cabeceras dinamicas */\n"
    "/* Nota: generar el nonce con aleatoriedad segura; si la version de EdgeWorkers\n"
    "   no expone crypto confuellete, delegar el nonce a la app y solo setear aqui. */\n"
    "export function onClientResponse(request, response) {\n"
    "  response.setHeader('Content-Security-Policy',\n"
    "    [\"default-src 'self'; script-src 'self' 'nonce-<generado-por-app>'; \"\n"
    "      + \"object-src 'none'; base-uri 'self'; frame-ancestors 'none'\"]);\n"
    "  response.setHeader('Strict-Transport-Security',\n"
    "    ['max-age=31536000; includeSubDomains; preload']);\n"
    ")"
)

_CODE_AKAMAI_LIMPIEZA = (
    "/* Akamai EdgeWorkers: limpieza de cabeceras */\n"
    "export function onClientResponse(request, response) {\n"
    "  response.removeHeader('x-powered-by');\n"
    "  response.removeHeader('x-generator');\n"
    "}"
)

_CODE_APACHE_TOKENS = "ServerTokens Prod\nServerSignature Off"
_CODE_NODE_TOKENS = "app.disable('x-powered-by');"
_CODE_PHP_TOKENS = "expose_php = Off   # php.ini"
_CODE_ASPNET_TOKENS = "<httpRuntime enableVersionHeader=\"false\" />"

_CODE_CLOUDFRONT_CLEAN = (
    "/* CloudFront Function (viewer response): limpiar cabeceras de origen */\n"
    "/* Nota: CloudFront agrega 'Server'/'Via'/'X-Amz-Cf-*' SALIENDO, despues de\n"
    "   la Function; no son removibles al 100% en el edge. Para ocultarlos del\n"
    "   todo, considerar un proxy/CDN delante (ej. Cloudflare) que los reescriba. */\n"
    "function handler(event) {\n"
    "  var r = event.response;\n"
    "  delete r.headers['x-powered-by'];\n"
    "  delete r.headers['x-generator'];\n"
    "  return r;\n"
    "}"
)

_CODE_WP_GENERATOR = (
    "// WordPress: eliminar metaetiqueta generator del head\n"
    "remove_action('wp_head', 'wp_generator');"
)

_CODE_NGINX_CMS = (
    "# nginx: bloquear ficheros sensibles de instalacion/documentacion\n"
    "location ~* /(readme\\.html|license\\.txt|install\\.php|wp-config\\.php\\.bak) { deny all; return 404; }"
)

_CODE_APACHE_CMS = (
    "# Apache: bloquear ficheros sensibles\n"
    "<FilesMatch \"^(readme\\.html|license\\.txt|install\\.php)$\">\n"
    "  Require all denied\n"
    "</FilesMatch>"
)


def _imprimir_codigo(codigo, sangria="        "):
    for linea_cod in codigo.strip("\n").strip().splitlines():
        print(f"{sangria}{linea_cod}")


def detectar_temas_remediacion(headers):
    """Detecta qué temas de hardening de remediation aplican según cabeceras.

    Devuelve dict con claves opcionales:
      - 'csp_endurecer': [(directiva, tema), ...] según tokens inseguros
      - 'hsts_estrechar': [descripción de cada problema]
      - 'stack_ocultar': ['Cabecera: valor', ...]
      - 'cms_metadatos': True si hay señales de CMS/PHP/metadatos
    """
    temas = {}
    normalized = {k.lower(): v for k, v in headers.items()}
    csp = normalized.get("content-security-policy")
    hsts = normalized.get("strict-transport-security")
    server = normalized.get("server", "")
    powered = normalized.get("x-powered-by", "")

    # A) Endurecimiento de CSP
    if csp:
        directivas, _ = parsear_csp(csp)
        deteccion = []
        for nombre, toks in directivas.items():
            bajos = [t.lower() for t in toks]
            if "'unsafe-inline'" in bajos or "'unsafe-eval'" in bajos:
                deteccion.append((nombre, "flags inseguros 'unsafe-inline'/'unsafe-eval'"))
            if any(t == "*" for t in toks):
                deteccion.append((nombre, "wildcard global '*'"))
            if "data:" in bajos:
                deteccion.append((nombre, "fuente 'data:'"))
        if deteccion:
            temas["csp_endurecer"] = deteccion

    # B) HSTS robusto
    problemas_hsts = []
    if not hsts:
        problemas_hsts.append("cabecera Strict-Transport-Security ausente")
    else:
        m = re.search(r"max-age=(\d+)", hsts)
        max_edad = int(m.group(1)) if m else 0
        if max_edad < 31536000:
            problemas_hsts.append(f"max-age={max_edad} menor a 1 anio (31536000)")
        if 'includeSubDomains'.lower() not in hsts.lower():
            problemas_hsts.append("sin 'includeSubDomains'")
        if 'preload'.lower() not in hsts.lower():
            problemas_hsts.append("sin 'preload' (sin precarga registrada)")
    if problemas_hsts:
        temas["hsts_estrechar"] = problemas_hsts

    # C) Exposición del stack
    expuestas = []
    for cand in ("Server", "X-Powered-By", "X-AspNet-Version", "Via", "X-Amz-Cf-Pop", "X-Amz-Cf-Id"):
        if cand.lower() in normalized:
            expuestas.append(f"{cand}: {str(normalized[cand.lower()])[:70]}")
    if expuestas:
        temas["stack_ocultar"] = expuestas

    # D) CMS / metadatos (señales que surgen solo de cabeceras)
    senales_cms = any(s in normalized for s in ("x-generator", "x-drupal-cache", "x-joomla-version", "x-runtime", "x-version"))
    if senales_cms or "php" in powered.lower() or "php" in server.lower():
        temas["cms_metadatos"] = True

    return temas


def plan_remediacion(headers):
    """Plan de remediación accionable (v1.3.0): genera, según lo observado en las
    cabeceras, fases y pasos concretos por tecnología (servidor web / framework /
    CDN) con mapeo de apoyo a SOC 2 y PCI DSS v4.0. Imprime el plan y devuelve los
    temas detectados."""
    temas = detectar_temas_remediacion(headers)
    if not temas:
        return temas

    # ---- Helpers de formato "Ficha de Incidencia / Mejora" (UI/UX de terminal) ----
    def ficha_encabezado(num, titulo):
        barra = "=" * 68
        print(f"\n{Fore.CYAN}{Style.BRIGHT}{barra}")
        print(f"  [Ficha {num}] {titulo}")
        print(f"{barra}{Style.RESET_ALL}")

    def ficha_meta(clave, valor, color_valor=Fore.YELLOW):
        print(f"  {Fore.CYAN}- {clave:<15}:{Style.RESET_ALL} {color_valor}{valor}{Style.RESET_ALL}")

    def ficha_normativa(texto):
        print(f"  {Fore.CYAN}- {'Normativa':<15}:{Style.RESET_ALL} {Fore.MAGENTA}{texto}{Style.RESET_ALL}")

    def ficha_sep():
        print(f"{Fore.CYAN}  " + "-" * 68 + f"{Style.RESET_ALL}")

    def ficha_cierre():
        print(f"{Fore.CYAN}{Style.BRIGHT}  " + "=" * 68 + f"{Style.RESET_ALL}")

    def ficha_paso(num, titulo):
        print(f"\n  {Fore.CYAN}{Style.BRIGHT}[PASO {num}] {titulo}{Style.RESET_ALL}")

    def ficha_riesgo(texto):
        print(f"  {Fore.YELLOW}[!] {texto}{Style.RESET_ALL}")

    def ficha_mitiga(texto):
        print(f"  {Fore.GREEN}[OK] {texto}{Style.RESET_ALL}")

    def ficha_tec(nombre):
        print(f"      {Fore.CYAN}--- {nombre} ---{Style.RESET_ALL}")

    barra = "=" * 68
    print(f"\n{Fore.CYAN}{Style.BRIGHT}{barra}")
    print("  Plan de remediación accionable (fichas por tema)")
    print(f"{barra}{Style.RESET_ALL}")
    print(f"  {Fore.YELLOW}[!]{Style.RESET_ALL} riesgo/advertencia    {Fore.GREEN}[OK]{Style.RESET_ALL} mitigación sugerida    {Fore.CYAN}[PASO n]{Style.RESET_ALL} acción técnica")
    print(f"  Implementación a nivel servidor web / proxy inverso / CDN (más código de")
    print(f"  aplicación si aplica), en ventana de cambio con rollback (SOC 2 CC8.1).")

    ficha_num = {"count": 0}

    def siguiente_ficha():
        ficha_num["count"] = ficha_num["count"] + 1
        return ficha_num["count"]

    # ------------------------- A) CSP -------------------------
    if "csp_endurecer" in temas:
        deteccion = list(dict.fromkeys(temas["csp_endurecer"]))
        directivas_afectadas = sorted({d for d, _ in deteccion})
        resumen_flags = []
        for _, tema_txt in deteccion:
            if tema_txt not in resumen_flags:
                resumen_flags.append(tema_txt)

        ficha_encabezado(siguiente_ficha(), "Content-Security-Policy (CSP) - Endurecimiento")
        ficha_meta("Estado actual", f"directivas débiles en {', '.join(directivas_afectadas)}")
        ficha_normativa("SOC 2 (CC6.6, CC7.1) | PCI DSS v4.0 (Req 6.2.4, 6.4.2)")
        ficha_sep()
        for item in resumen_flags:
            ficha_riesgo(item)

        ficha_paso(1, "Auditoría previa (Modo Report-Only)")
        print("      Publicar la política vigente como cabecera solo-reporte, apuntando a un")
        print("      recolector de reportes propio, y monitorear falsos positivos 1-2 semanas:")
        _imprimir_codigo(
            "Content-Security-Policy-Report-Only: <politica actual>; report-uri /csp-reports; report-to csp-endpoint",
            sangria="      -> ")
        ficha_riesgo("Aplicar enforce sin esta fase puede romper la aplicación en producción.")

        ficha_paso(2, "Mitigación de Scripts Inseguros (por tecnología)")
        print("      Migrar scripts embebidos a ficheros .js externos; si el inline es")
        print("      estrictamente necesario, usar nonce criptográfico dinámico por solicitud:")
        ficha_tec("Node.js / Express (nonce dinámico)")
        _imprimir_codigo(_CODE_EXPRESS_NONCE)
        ficha_tec("Nginx (header estático por fase; nonce viene de la app)")
        _imprimir_codigo(_CODE_NGINX_CSP)
        ficha_tec("Apache (mod_headers por VirtualHost; nonce viene de la app)")
        _imprimir_codigo(_CODE_APACHE_CSP)
        ficha_tec("Cloudflare WAF (sin nonce: Transform Rules; con nonce: Worker)")
        _imprimir_codigo(_CODE_CLOUDFLARE_TR_CSP)
        _imprimir_codigo(_CODE_CLOUDFLARE_WORKER)
        ficha_tec("Akamai WAF/CDN (Property Manager para estático + EdgeWorkers)")
        _imprimir_codigo(_CODE_AKAMAI_PM)
        _imprimir_codigo(_CODE_AKAMAI_EW)
        ficha_mitiga("Contenido inline estático: usar hash SHA-256 ('sha256-...') en lugar de nonce.")

        ficha_paso(3, "Restricción de comodines y 'data:'")
        con_wildcard = sorted({d for d, t in deteccion if '*' in t})
        con_data = sorted({d for d, t in deteccion if 'data:' in t})
        if con_wildcard:
            print(f"      -> Reemplazar '*' por dominios concretos en: {Fore.CYAN}{', '.join(con_wildcard)}{Style.RESET_ALL}")
        if con_data:
            print(f"      -> Eliminar 'data:' de: {Fore.CYAN}{', '.join(con_data)}{Style.RESET_ALL}")
        ficha_mitiga("Preferir 'self' y allowlists explícitas de hosts de confianza.")

        ficha_paso(4, "Política objetivo (enforce tras cero violaciones)")
        _imprimir_codigo(_CSP_OBJETIVO, sangria="      ")
        ficha_cierre()

    # ------------------------- B) HSTS -------------------------
    if "hsts_estrechar" in temas:
        problemas = temas["hsts_estrechar"]
        ficha_encabezado(siguiente_ficha(), "HSTS (Strict-Transport-Security) - Robustez")
        ficha_meta("Estado actual", f"{len(problemas)} problema(s) de robustez detectados")
        ficha_normativa("SOC 2 (CC6.6) | PCI DSS v4.0 (Req 4.2.1)")
        ficha_sep()
        for pr in problemas:
            ficha_riesgo(pr)

        ficha_paso(1, "Configuración por tecnología (aplicar a TODAS las respuestas HTTPS)")
        ficha_tec("Nginx (server block HTTPS)")
        _imprimir_codigo(_CODE_NGINX_HSTS)
        ficha_tec("Apache (mod_headers, VirtualHost HTTPS)")
        _imprimir_codigo(_CODE_APACHE_HSTS)
        ficha_tec("Cloudflare WAF")
        _imprimir_codigo(_CODE_CLOUDFLARE_HSTS)
        ficha_tec("Akamai WAF/CDN")
        _imprimir_codigo(_CODE_AKAMAI_PM)

        ficha_paso(2, "Validaciones ANTES de activar includeSubDomains/preload")
        ficha_riesgo("includeSubDomains: solo se desactiva a corto plazo; confirmar que TODOS los subdominios sirven HTTPS (sino se rompen clientes HTTP-only).")
        ficha_riesgo("preload: registrar en hstspreload.org; la salida de la lista de precarga es lenta y manual.")
        ficha_mitiga("max-age=31536000 (1 anio) obligatorio para optar a la lista de precarga.")
        ficha_cierre()

    # ------------------------- C) Stack -------------------------
    if "stack_ocultar" in temas:
        expuestas = temas["stack_ocultar"]
        ficha_encabezado(siguiente_ficha(), "Ocultar versión del servidor y tecnologías (fingerprinting)")
        ficha_meta("Estado actual", f"{len(expuestas)} cabecera(s) exponen stack/CDN")
        ficha_normativa("SOC 2 (CC6.6) | PCI DSS v4.0 (Req 6.4.2)")
        ficha_sep()
        for exp in expuestas:
            ficha_riesgo(exp)

        ficha_paso(1, "Servidor web: deshabilitar versiones en cabeceras")
        ficha_tec("Nginx")
        _imprimir_codigo(_CODE_NGINX_TOKENS)
        ficha_tec("Apache")
        _imprimir_codigo(_CODE_APACHE_TOKENS)

        ficha_paso(2, "Framework / lenguaje: deshabilitar cabeceras por defecto")
        ficha_tec("Node.js / Express")
        _imprimir_codigo(_CODE_NODE_TOKENS)
        ficha_tec("PHP")
        _imprimir_codigo(_CODE_PHP_TOKENS)
        ficha_tec("ASP.NET")
        _imprimir_codigo(_CODE_ASPNET_TOKENS)

        ficha_paso(3, "CDN / proxy inverso: limpieza de cabeceras en el Edge")
        ficha_tec("Cloudflare")
        print("      Usar Transform Rules (Response Header) para remover/reescribir cabeceras.")
        ficha_tec("Akamai (Property Manager / EdgeWorkers)")
        _imprimir_codigo(_CODE_AKAMAI_PM)
        _imprimir_codigo(_CODE_AKAMAI_LIMPIEZA)
        ficha_tec("CloudFront")
        _imprimir_codigo(_CODE_CLOUDFRONT_CLEAN)
        ficha_riesgo("Via/X-Amz-Cf-*: CloudFront las agrega al salir del edge; el 100% de remoción requiere un proxy/CDN delante que las reescriba.")
        ficha_cierre()

    # ------------------------- D) CMS -------------------------
    if "cms_metadatos" in temas:
        ficha_encabezado(siguiente_ficha(), "CMS y metadatos (generador / archivos de instalación)")
        ficha_meta("Estado actual", "señales de CMS/PHP en cabeceras; revisar meta generator y ficheros públicos")
        ficha_normativa("SOC 2 (CC7.1, CC8.1) | PCI DSS v4.0 (Req 6.2.3)")
        ficha_sep()

        ficha_paso(1, "Eliminar la metaetiqueta del generador")
        ficha_tec("WordPress (functions.php)")
        _imprimir_codigo(_CODE_WP_GENERATOR)
        print("      Drupal/Joomla: equivalente en la plantilla del tema o vía plugin de seguridad.")

        ficha_paso(2, "Bloquear acceso público a archivos de instalación/documentación")
        ficha_tec("Nginx")
        _imprimir_codigo(_CODE_NGINX_CMS)
        ficha_tec("Apache")
        _imprimir_codigo(_CODE_APACHE_CMS)

        ficha_paso(3, "Gestión de parches y actualización continua")
        ficha_mitiga("Inventario de plugins/temas/nucleo del CMS; ciclo de actualización automatizado o periodico (evita N-days).")
        ficha_mitiga("Escaneo recurrente de versiones expuestas: re-ejecutar esta herramienta en cada ciclo.")
        ficha_cierre()

    print(f"\n{Fore.CYAN}{'*'} Fin del plan: {ficha_num['count']} ficha(s) generada(s) según los hallazgos emitidos en este reporte.{Style.RESET_ALL}")
    return temas


def print_tiempo():
    try:
        available_locales = locale.locale_aliases()
    except AttributeError:
        available_locales = list(locale.windows_locale.values())
    
    if 'es_ES.UTF-8' not in available_locales and 'es_ES' not in available_locales:
        locale.setlocale(locale.LC_TIME, '')
    else:
        try:
            locale.setlocale(locale.LC_TIME, 'es_ES.UTF-8')
        except locale.Error:
            locale.setlocale(locale.LC_TIME, 'es_ES')
    
    now = datetime.now(timezone.utc)
    # Offset GMT-3 (rescatado del script original; el offset quedó neutro al 0 en la iteración anterior)
    gmt_offset = timedelta(hours=-3)
    gmt_time = now + gmt_offset
    formatted_date = now.strftime("%A, %d de %B de %Y %H:%M:%S UTC")
    formatted_date += f" ({gmt_time.strftime('%H:%M')} GMT-3)"
    print(f"\nFecha y hora: {formatted_date}")

def save_to_json(data, filename='output.json'):
    with open(filename, 'w') as json_file:
        json.dump(data, json_file, ensure_ascii=False, indent=4)
    print(f"{Fore.GREEN}[+] Headers guardados como {filename}{Style.RESET_ALL}")

def procesar_solicitud(url, headers, proxies, method, body=None, cert=None):
    session = requests.Session()
    session.headers.update(headers)
    
    if proxies:
        session.proxies = proxies

    try:
        response = session.request(
            method=method,
            url=url,
            json=body if isinstance(body, dict) else None,
            data=body if not isinstance(body, dict) else None,
            timeout=TIMEOUT,
            verify=cert if cert else False
        )
        return response
    except requests.exceptions.Timeout:
        print(f"{Fore.RED}[!] Tiempo de espera excedido ({TIMEOUT} segundos).{Style.RESET_ALL}")
        sys.exit(1)
    except requests.exceptions.ConnectionError:
        print(f"{Fore.RED}[!] No se pudo conectar al servidor.{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}[!] Error inesperado: {e}{Style.RESET_ALL}")
        sys.exit(1)

HERRAMIENTA = "Cabeceras_Seguridad"
CATEGORIA = "web"
VERSION_TOOL = __version__

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

def escribir_reporte_log(carpeta_salida, comando, version=VERSION_TOOL, herramienta=HERRAMIENTA, categoria=CATEGORIA):
    import datetime
    os.makedirs(carpeta_salida, exist_ok=True)
    ahora = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    host = socket.gethostname()
    inicio = getattr(escribir_reporte_log, "_inicio", None)
    if inicio:
        seg = (datetime.datetime.now() - inicio).total_seconds()
        duracion = f"{int(seg)}s"
    else:
        duracion = "-"
    linea = f"{ahora} | {categoria}_{herramienta} | {version} | {comando} | {host} | {duracion}\n"
    ruta = os.path.join(carpeta_salida, "reporte.log")
    with open(ruta, "a", encoding="utf-8") as f:
        f.write(linea)
    return ruta

def escribir_manifest(carpeta_salida, comando, artefactos, version=VERSION_TOOL, herramienta=HERRAMIENTA, categoria=CATEGORIA):
    import datetime
    os.makedirs(carpeta_salida, exist_ok=True)
    manifest = {"tool": f"{categoria}/{herramienta}", "categoria": categoria, "version": version, "salida": carpeta_salida, "comando": comando, "log": "reporte.log", "artefactos": artefactos}
    ruta = os.path.join(carpeta_salida, "manifest.json")
    with open(ruta, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)
    return ruta

def main():
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter, description='Herramienta para análisis de cabeceras HTTP de seguridad')
    parser.add_argument("-l", "--lang", default="es", help="Idioma de salida (es por defecto)")
    parser.add_argument('url', type=str, nargs='?', help='URL de destino')
    parser.add_argument('-b', '--body', type=str, help='Cuerpo de la solicitud en formato JSON (cadena o archivo)')
    parser.add_argument('-v', '--verb', type=str, choices=['GET', 'POST', 'PUT', 'HEAD', 'DELETE', 'PATCH', 'OPTIONS'], default='GET', help='Verbo HTTP')
    parser.add_argument('-o', '--output', type=str, default='output.json', help='Nombre del archivo de salida JSON')
    parser.add_argument('-H', '--header', type=str, nargs='+', help='Encabezados (se pueden especificar múltiples)')
    parser.add_argument('-p', '--proxy', type=str, help='Dirección del proxy (ej: usuario:pass@host:puerto)')
    parser.add_argument('--cert', type=str, help='Ruta al certificado SSL personalizado (.pem)')
    parser.add_argument('-s', '--silent', action='store_true', help='Modo silencioso (solo salida JSON)')
    parser.add_argument('-i', '--info', action='store_true', help='Mostrar información de los encabezados')
    parser.add_argument('-ua', '--user-agent', type=str, default=DEFAULT_USER_AGENT, help='Establecer un User-Agent personalizado')
    parser.add_argument('-j', '--json-file', type=str, help='Ruta al archivo JSON con datos estáticos para analizar')
    parser.add_argument('--version', action='version', version=f"{HERRAMIENTA} {VERSION_TOOL}")
    parser.add_argument('--output-dir', default=None, help='Carpeta de salida del cliente (reporte.log + manifest.json)')
    parser.add_argument('--cliente', default=None, help='Nombre del cliente')
    
    args = parser.parse_args()

    if args.cliente:
        args.output_dir = os.path.join("output", args.cliente)
    if args.output_dir is None:
        args.output_dir = "output"
    escribir_reporte_log._inicio = datetime.now()
    comando = " ".join(sys.argv)

    if not args.silent:
        print_banner()

    # Lógica para leer desde archivo JSON o hacer solicitud web
    if args.json_file:
        try:
            with open(args.json_file, 'r') as f:
                output_data = json.load(f)
            print(f"{Fore.CYAN}[+] Leyendo datos de {args.json_file}{Style.RESET_ALL}")
            
            # Formatear la información para print_status, ya que no hay un objeto response
            headers = output_data.get('headers', {})
            status_code = output_data.get('status_code', '')
            response_data = {
                'url': output_data.get('url', ''),
                'status_code': status_code,
                'location': headers.get('Location', ''),
                'status_description': requests.status_codes._codes.get(status_code, [''])[0] if status_code else '',
                'http_version': 'N/A'
            }
            
        except FileNotFoundError:
            print(f"{Fore.RED}[!] Error: Archivo no encontrado: {args.json_file}{Style.RESET_ALL}")
            sys.exit(1)
        except json.JSONDecodeError:
            print(f"{Fore.RED}[!] Error: Formato JSON inválido en el archivo: {args.json_file}{Style.RESET_ALL}")
            sys.exit(1)
        
    else:
        if not args.url:
            args.url = input("Introduce la URL: ")

        if not args.url.startswith(("http://", "https://")):
            args.url = "https://" + args.url

        try:
            normalized_url = normalize_url(args.url)
        except Exception as e:
            print(f"{Fore.RED}[!] Error en URL: {e}{Style.RESET_ALL}")
            sys.exit(1)

        print(f"{Fore.CYAN}[+] URL objetivo: {normalized_url}{Style.RESET_ALL}")

        # [Rescate v1.4.3] Verificación de redirección HTTP -> HTTPS (solo modo URL)
        redir = verificar_redireccion_http_https(normalized_url)
        if not redir["verificado"]:
            print(f"{Fore.CYAN}[*] Redirección HTTP->HTTPS: {redir['detalle']}{Style.RESET_ALL}")
        elif redir["redirige"]:
            print(f"{Fore.GREEN}[+] Redirección HTTP->HTTPS verificada: {redir['detalle']}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[!] Redirección HTTP->HTTPS NO verificada: {redir['detalle']}{Style.RESET_ALL}")


        headers = {
            'User-Agent': args.user_agent
        }
        if args.header:
            headers.update(parse_headers(args.header))

        proxies = {}
        if args.proxy:
            proxy_parts = args.proxy.split('@')
            if len(proxy_parts) == 2:
                auth, host = proxy_parts
                user_pass = auth.split(':')
                if len(user_pass) == 2:
                    user, password = user_pass
                    proxy_url = f"http://{host}"
                    proxies = {"http": proxy_url, "https": proxy_url}
                    print(f"{Fore.CYAN}[+] Usando proxy con autenticación: {host}{Style.RESET_ALL}")
            else:
                proxies = {
                    "http": f"http://{args.proxy}",
                    "https": f"http://{args.proxy}"
                }
                print(f"{Fore.CYAN}[+] Usando proxy: {args.proxy}{Style.RESET_ALL}")

        body = load_body(args.body) if args.body else None
        response = procesar_solicitud(normalized_url, headers, proxies, args.verb, body, args.cert)

        # Creación del diccionario de salida con la URL
        output_data = {
            "url": normalized_url,
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "ip": get_ip(normalized_url),
            "timestamp": datetime.now().isoformat()
        }
        save_to_json(output_data, args.output)

        # Usar un diccionario para pasar los datos a print_status
        response_data = {
            'url': normalized_url,
            'status_code': response.status_code,
            'status_description': response.reason,
            'http_version': f"HTTP/{response.raw.version // 10}.{response.raw.version % 10}",
            'location': response.headers.get("Location")
        }
        
    # Lógica de impresión para ambos casos (JSON o solicitud en vivo)
    if not args.silent:
        print_status(response_data)
        if args.info:
            print_header(output_data['headers'])
        # Estas funciones se mueven al final de suggest_recommended_headers para una salida más limpia
        # print("\n Información Adicional: Sugerencias [Buenas prácticas]\n ") 
        
        
        
        print_special_headers(output_data['headers'])
        resumen_inventario_cabeceras(output_data['headers'])

        # [3] Evaluación de seguridad estándar (bloque por bloque)
        csp_val, xfo_val = print_security_headers(output_data['headers'])

        # [4] Análisis profundo (CSP directiva por directiva) y control de caché
        if csp_val:
            try:
                analizar_csp_profundo(csp_val, xfo_val)
            except Exception as e:  # El análisis profundo nunca debe frenar el resto del reporte
                logger.error(f"Error en análisis profundo de CSP: {e}")
        suggest_cache_headers(output_data['headers'])

        # [5] Endurecimiento, sugerencias y buenas prácticas
        suggest_recommended_headers(output_data['headers'])
        suggest_headers_to_remove(output_data['headers'])

        # [5b] Plan de remediación accionable (con alineación SOC 2 / PCI DSS)
        try:
            plan_remediacion(output_data['headers'])
        except Exception as e:  # El plan nunca debe frenar el resto del reporte
            logger.error(f"Error en plan de remediación: {e}")

        # [6] Cierre
        print_tiempo()

    artefactos = [args.output] if not args.json_file else []
    escribir_reporte_log(args.output_dir, comando)
    escribir_manifest(args.output_dir, comando, artefactos)

if __name__ == "__main__":
    main()
