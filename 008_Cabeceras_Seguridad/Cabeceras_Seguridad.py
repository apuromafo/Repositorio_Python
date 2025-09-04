#-------------------------------------------------------------------------------------------------
#    Cabeceras de seguridad - Analizador de encabezados HTTP.
#
# Descripción:
#     Este script se conecta a una URL o lee un archivo JSON para analizar los encabezados de
#     respuesta HTTP en busca de configuraciones relacionadas con la seguridad.
#     Ofrece sugerencias para mejorar la seguridad, identificar encabezados faltantes
#     y señalar información que podría exponer la infraestructura.
#
# Forma de uso:
#     - Analizar una URL en vivo:
#         python Cabeceras_Seguridad.py <URL> [opciones]
#         Ejemplo: python Cabeceras_Seguridad.py https://ejemplo.com -i
#
#     - Analizar un archivo JSON (generado con 'convert_headers.py'):
#         python Cabeceras_Seguridad.py -j <archivo.json> [opciones]
#         Ejemplo: python Cabeceras_Seguridad.py -j demo.json -i
#
#     - Opciones comunes:
#         -i, --info       Mostrar todos los encabezados presentes.
#         -v, --verb       Especificar el verbo HTTP (ej: POST).
#         -H, --header     Añadir encabezados personalizados.
# -------------------------------------------------------------------------------------------------
# ==============================================================================
# --- HISTORIAL DE VERSIONES ---
# ==============================================================================
# v0.1.0 (2025-09-04) - [LANZAMIENTO]
#     ✅ Añadido: Bloque de 'Forma de uso' para una referencia rápida.
#     ✅ Mejorado: Lógica de análisis de JSON para la 'Descripción' del estado HTTP.
#     ✅ Corregido: Errores menores en el código y la presentación.
# ------------------------------------------------------------------------------
# v0.0.7 (2025-07-15) - [INICIO]
#     ✅ Prototipo funcional inicial.
#     ✅ Análisis de cabeceras de seguridad comunes.
#     ✅ Soporte para solicitudes web y archivos JSON.
#     ❌ Pendiente: Historial de versiones detallado y comentarios.
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

# Inicializar colorama
init(autoreset=True)

# Desactivar warnings de SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Constantes
TIMEOUT = 10  # segundos
DEFAULT_USER_AGENT = 'CabecerasSegurasScript/0.0.7'

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
    banner = """
 ::::::::    :::      :::::::::  :::::::::: ::::::::  :::::::::: :::::::::     :::      ::::::::  
:+:   :+:   :+: :+:   :+:   :+: :+:        :+:   :+: :+:         :+:   :+:    :+: :+:   :+:   :+: 
+:+        +:+   +:+  +:+   +:+ +:+        +:+       +:+         +:+   +:+   +:+   +:+  +:+       
+#+        +#++:++#++:+#++:++#+  +#++:++#  +#+       +#++:++#     +#++:++#:  +#++:++#++:+#++:++#++
+#+        +#+     +#+ +#+   +#+ +#+        +#+       +#+         +#+   +#+  +#+     +#+       +#+
#+#   #+# #+#     #+# #+#   #+# #+#        #+#   #+# #+#         #+#   #+#  #+#     #+# #+#   #+#
 ########  ###     ### #########  ########## ########  ########## ###   ###  ###     ###  ########  
                                                                                              v0.1  
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

def suggest_headers_to_remove(headers):
    suggest_remove = [
        "$wsep", "Host-Header", "K-Proxy-Request", "Liferay-Portal", "OracleCommerceCloud-Version",
        "Pega-Host", "Powered-By", "Product", "Server", "SourceMap", "X-AspNet-Version",
        "X-AspNetMvc-Version", "X-Atmosphere-error", "X-Atmosphere-first-request",
        "X-Atmosphere-tracking-id", "X-B3-ParentSpanId", "X-B3-Sampled", "X-B3-SpanId",
        "X-B3-TraceId", "X-BEServer", "X-Backside-Transport", "X-CF-Powered-By", "X-CMS",
        "X-CalculatedBETarget", "X-Cocoon-Version", "X-Content-Encoded-By", "X-DiagInfo",
        "X-Envoy-Attempt-Count", "X-Envoy-External-Address", "X-Envoy-Internal",
        "X-Envoy-Original-Dst-Host", "X-Envoy-Upstream-Service-Time", "X-FEServer",
        "X-Framework", "X-Generated-By", "X-Generator", "X-Jitsi-Release","X-Magento-Tags",
        "X-Joomla-Version", "X-Kubernetes-PF-FlowSchema-UI", "X-Kubernetes-PF-PriorityLevel-UID",
        "X-LiteSpeed-Cache", "X-LiteSpeed-Purge", "X-LiteSpeed-Tag", "X-LiteSpeed-Vary",
        "X-Litespeed-Cache-Control", "X-Mod-Pagespeed", "X-Nextjs-Cache",
        "X-Nextjs-Matched-Path", "X-Nextjs-Page", "X-Nextjs-Redirect", "X-OWA-Version",
        "X-Old-Content-Length", "X-OneAgent-JS-Injection", "X-Page-Speed", "X-Php-Version",
        "X-Powered-By", "X-Powered-By-Plesk", "X-Powered-CMS", "X-Redirect-By",
        "X-Server-Powered-By", "X-SourceFiles", "X-SourceMap", "X-Turbo-Charged-By",
        "X-Umbraco-Version", "X-Varnish-Backend", "X-Varnish-Server", "X-dtAgentId",
        "X-dtHealthCheck", "X-dtInjectedServlet", "X-ruxit-JS-Agent"
    ]
    present_suggestions = {
        header: headers[header]
        for header in suggest_remove
        if header in headers
    }
    if present_suggestions:
        print(f"\n[!] Cabeceras que podrían eliminarse:")
        for header, value in present_suggestions.items():
            print(f"[!] Cabecera: {Fore.RED}{header}{Style.RESET_ALL} = {value}")

def print_security_headers(headers):
    security_headers = [
        "Content-Security-Policy", "X-XSS-Protection", "X-Frame-Options",
        "Referrer-Policy", "Strict-Transport-Security", "X-Content-Type-Options",
        "Permissions-Policy"
    ]
    present_headers = [h for h in security_headers if h in headers or h.lower() in headers]
    missing_headers = [h for h in security_headers if h not in headers and h.lower() not in headers]

    print(f"\nCabeceras de seguridad presentes:")
    if present_headers:
        for header in present_headers:
            print(f"[*] Cabecera {Fore.GREEN}{header}{Style.RESET_ALL} está presente!")
    else:
        print("No se encontraron cabeceras de seguridad presentes.")

    print(f"\n[!] Cabeceras de seguridad faltantes:")
    if missing_headers:
        for header in missing_headers:
            print(f"[!] Falta la cabecera de seguridad: {Fore.YELLOW}{header}{Style.RESET_ALL}")
    else:
        print("Todas las cabeceras de seguridad están presentes.")

    print(f"\nTotal de cabeceras de seguridad presentes: {Fore.GREEN}{len(present_headers)}{Style.RESET_ALL}")
    print(f"Total de cabeceras de seguridad faltantes: {Fore.RED}{len(missing_headers)}{Style.RESET_ALL}")

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

def suggest_recommended_headers(headers):
    recommended_headers = {
        "Cache-Control": "no-store, max-age=0",
        "Clear-Site-Data": "\"cache\",\"cookies\",\"storage\"",
        "Content-Security-Policy": "default-src 'self'; form-action 'self'; object-src 'none'; frame-ancestors 'none'; upgrade-insecure-requests; block-all-mixed-content",
        "Cross-Origin-Embedder-Policy": "require-corp",
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Resource-Policy": "same-origin",
        "Permissions-Policy": "accelerometer=(), autoplay=(), camera=(), cross-origin-isolated=(), display-capture=(), encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), keyboard-map=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), publickey-credentials-get=(), screen-wake-lock=(), sync-xhr=(self), usb=(), web-share=(), xr-spatial-tracking=(), clipboard-read=(), clipboard-write=(), gamepad=(), hid=(), idle-detection=(), interest-cohort=(), serial=(), unload=()",
        "Referrer-Policy": "no-referrer",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "deny",
        "X-Permitted-Cross-Domain-Policies": "none"
    }
    missing_headers = []
    
    for header, value in recommended_headers.items():
        if header not in headers:
            missing_headers.append({"name": header, "value": value})

    if missing_headers:
        print(f"\n[!] Cabeceras recomendadas que podrían configurarse:")
        for header in missing_headers:
            print(f"[!] Cabecera: {Fore.YELLOW}{header['name']}: {header['value']}{Style.RESET_ALL}")

def print_tiempo():
    try:
        available_locales = locale.locale_aliases()
    except AttributeError:
        available_locales = list(locale.windows_locale.values())
    
    if 'es_ES.UTF-8' not in available_locales:
        locale.setlocale(locale.LC_TIME, '')
    else:
        locale.setlocale(locale.LC_TIME, 'es_ES.UTF-8')
    
    now = datetime.now(timezone.utc)
    gmt_offset = timedelta(hours=-4)
    gmt_time = now + gmt_offset
    formatted_date = now.strftime("%A, %d de %B de %Y %H:%M:%S UTC")
    print(f"\nFecha y hora: {formatted_date} ({gmt_time.strftime('%H:%M GMT-4')})")

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

def main():
    parser = argparse.ArgumentParser(description='Herramienta para análisis de cabeceras HTTP de seguridad')
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
    
    args = parser.parse_args()

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
            response_data = {
                'url': output_data.get('url', ''),
                'status_code': output_data.get('status_code', ''),
                'location': headers.get('Location', ''),
                'status_description': requests.status_codes._codes.get(output_data.get('status_code', ''), [''])[0],
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
        
        print_special_headers(output_data['headers'])
        print_security_headers(output_data['headers'])
        print("\n Información Adicional: Sugerencias [Buenas prácticas]\n ")
        suggest_headers_to_remove(output_data['headers'])
        suggest_recommended_headers(output_data['headers'])
        print_tiempo()

if __name__ == "__main__":
    main()