#!/usr/bin/env python

description = 'Cabeceras de seguridad inspirado en OWASP secure Headers [https://owasp.org/www-project-secure-headers/ ]'
author = 'Apuromafo'
version = '0.0.3'
date = '28.11.2024'

import argparse
import requests
import json
from datetime import datetime, timedelta, timezone  # Importaciones correctas
from tabulate import tabulate
from colorama import Fore, Style #banner
import random #banner
import math #banner
import socket
from urllib.parse import urlparse, urlunparse
import ipaddress
import locale
import urllib3

# Definición de colores
colores = {
    "rojo": (255, 0, 0),
    "naranja": (255, 165, 0),
    "amarillo": (255, 255, 0),
    "verde": (0, 255, 0),
    "azul": (0, 0, 255),
    "morado": (128, 0, 128),
}

# Función para interpolar valores de color según la posición
def interpolar_color(color_inicio, color_fin, posicion):
    r_inicio, g_inicio, b_inicio = color_inicio
    r_fin, g_fin, b_fin = color_fin

    r_nuevo = int(r_inicio + (posicion * (r_fin - r_inicio)))
    g_nuevo = int(g_inicio + (posicion * (g_fin - g_inicio)))
    b_nuevo = int(b_inicio + (posicion * (b_fin - b_inicio)))

    return (r_nuevo, g_nuevo, b_nuevo)

# Función para generar código ANSI de escape a partir de valores RGB
def rgb_a_codigo_ansi(rgb):
    r, g, b = rgb
    return f"\033[38;2;{r};{g};{b}m"

# Generar un degradado de colores
def generar_degradado_colores(color_inicio, color_fin, pasos):
    degradado = []
    for i in range(pasos + 1):
        posicion = i / pasos
        color = interpolar_color(color_inicio, color_fin, posicion)
        codigo_ansi = rgb_a_codigo_ansi(color)
        degradado.append(codigo_ansi)

    return degradado

# Función para imprimir el banner
def print_banner():
    # Fuente: https://patorjk.com/software/taag/#p=display&f=Alligator2&t=Cabeceras
    banner = """
 ::::::::      :::     :::::::::  :::::::::: ::::::::  :::::::::: :::::::::      :::      ::::::::  
:+:    :+:   :+: :+:   :+:    :+: :+:       :+:    :+: :+:        :+:    :+:   :+: :+:   :+:    :+: 
+:+         +:+   +:+  +:+    +:+ +:+       +:+        +:+        +:+    +:+  +:+   +:+  +:+        
+#+        +#++:++#++: +#++:++#+  +#++:++#  +#+        +#++:++#   +#++:++#:  +#++:++#++: +#++:++#++ 
+#+        +#+     +#+ +#+    +#+ +#+       +#+        +#+        +#+    +#+ +#+     +#+        +#+ 
#+#    #+# #+#     #+# #+#    #+# #+#       #+#    #+# #+#        #+#    #+# #+#     #+# #+#    #+# 
 ########  ###     ### #########  ########## ########  ########## ###    ### ###     ###  ########  
                                                                              v0.1 
    """
    # Generar colores degradados para el texto
    color_inicio = colores[random.choice(list(colores.keys()))]
    color_fin = colores[random.choice(list(colores.keys()))]
    degradado = generar_degradado_colores(color_inicio, color_fin, len(banner.splitlines()))

    # Imprimir el texto con el degradado de color
    for i, line in enumerate(banner.splitlines()):
        print(degradado[i % len(degradado)] + line + "\033[0m")

def save_to_json(data, filename='output.json'):
    with open(filename, 'w') as json_file:
        json.dump(data, json_file, ensure_ascii=False, indent=4)
    print(f"Headers guardados como {filename}")
    
def print_status(response):
    status_code = response.status_code
    status_description = response.reason
    http_version = f"HTTP/{response.raw.version // 10}.{response.raw.version % 10}"
    location = response.headers.get("Location")
    
    data = []
    if http_version:
        data.append(["HTTP", http_version])
    if status_code:
        data.append(["Código de estado", status_code])
    if location:
        data.append(["Location", location])
    if status_description:
        data.append(["Descripción", status_description])

    if data:
        table = tabulate(data, tablefmt="grid", floatfmt=".0f", stralign="left", numalign="right")
        print(table)

def print_header(headers):
    header_names = [f"[{str(i + 1).zfill(2)}]{key}" for i, key in enumerate(headers.keys())]
    header_list = ', '.join(header_names)
    total_headers = len(headers)
    
    print(f"Total de Headers {total_headers}:\n")# {header_list}")
    print(f"[Informativo] Headers actuales \n")
    for i, (key, value) in enumerate(headers.items(), start=1):
        print(f"[{str(i).zfill(2)}] {key}: {value}")
    print(f"\n\n") 
      
    
def suggest_headers_to_remove(headers):
    # Lista de cabeceras que se deben considerar para eliminación
    suggest_remove = [
   "$wsep",
    "Host-Header",
    "K-Proxy-Request",
    "Liferay-Portal",
    "OracleCommerceCloud-Version",
    "Pega-Host",
    "Powered-By",
    "Product",
    "Server",
    "SourceMap",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Atmosphere-error",
    "X-Atmosphere-first-request",
    "X-Atmosphere-tracking-id",
    "X-B3-ParentSpanId",
    "X-B3-Sampled",
    "X-B3-SpanId",
    "X-B3-TraceId",
    "X-BEServer",
    "X-Backside-Transport",
    "X-CF-Powered-By",
    "X-CMS",
    "X-CalculatedBETarget",
    "X-Cocoon-Version",
    "X-Content-Encoded-By",
    "X-DiagInfo",
    "X-Envoy-Attempt-Count",
    "X-Envoy-External-Address",
    "X-Envoy-Internal",
    "X-Envoy-Original-Dst-Host",
    "X-Envoy-Upstream-Service-Time",
    "X-FEServer",
    "X-Framework",
    "X-Generated-By",
    "X-Generator",
    "X-Jitsi-Release",
    "X-Joomla-Version",
    "X-Kubernetes-PF-FlowSchema-UI",
    "X-Kubernetes-PF-PriorityLevel-UID",
    "X-LiteSpeed-Cache",
    "X-LiteSpeed-Purge",
    "X-LiteSpeed-Tag",
    "X-LiteSpeed-Vary",
    "X-Litespeed-Cache-Control",
    "X-Mod-Pagespeed",
    "X-Nextjs-Cache",
    "X-Nextjs-Matched-Path",
    "X-Nextjs-Page",
    "X-Nextjs-Redirect",
    "X-OWA-Version",
    "X-Old-Content-Length",
    "X-OneAgent-JS-Injection",
    "X-Page-Speed",
    "X-Php-Version",
    "X-Powered-By",
    "X-Powered-By-Plesk",
    "X-Powered-CMS",
    "X-Redirect-By",
    "X-Server-Powered-By",
    "X-SourceFiles",
    "X-SourceMap",
    "X-Turbo-Charged-By",
    "X-Umbraco-Version",
    "X-Varnish-Backend",
    "X-Varnish-Server",
    "X-dtAgentId",
    "X-dtHealthCheck",
    "X-dtInjectedServlet",
    "X-ruxit-JS-Agent"
    ]
    
    # Verificar si alguna de las cabeceras sugeridas está presente
    present_suggestions = {
        header: headers[header]
        for header in suggest_remove
        if header in headers
    }

    if present_suggestions:
        print("\n[!] Cabeceras que podrían eliminarse:")
        for header, value in present_suggestions.items():
            print(f"[!] Cabecera: {Fore.RED}{header}{Style.RESET_ALL} = {value}")
    else:
        print("\n")#\nTodas las cabeceras sugeridas para eliminación están ausentes.")

def print_special_headers(headers):
    special_headers = [
        "Access-Control-Allow-Origin",
        "Access-Control-Allow-Methods",
        "Access-Control-Allow-Headers",
        "Content-Security-Policy-Report-Only",
    ]

    present_headers = [header for header in special_headers if header in headers]
    if present_headers:
        print("Cabeceras especiales presentes:")
        for header in present_headers:
            print(f"[*] Cabecera {Fore.GREEN}{header}{Style.RESET_ALL} está presente!")
        print()
    else:
        print("No se encontraron cabeceras especiales.")

def print_security_headers(headers):
    security_headers = [
        "Content-Security-Policy", 
        "X-XSS-Protection", 
        "X-Frame-Options", 
        "Referrer-Policy", 
        "Strict-Transport-Security", 
        "X-Content-Type-Options", 
        "Permissions-Policy"
    ]
    
    present_headers = [header for header in security_headers if header in headers or header.lower() in headers]
    missing_headers = [header for header in security_headers if header not in headers and header.lower() not in headers]

    # Imprimir cabeceras presentes
    if present_headers:
        print("\nCabeceras de seguridad presentes:")
        for header in present_headers:
            print(f"[*] Cabecera {Fore.GREEN}{header}{Style.RESET_ALL} está presente!")
    else:
        print("No se encontraron cabeceras de seguridad presentes.")

    # Imprimir cabeceras faltantes
    if missing_headers:
        print("\n[!] Cabeceras de seguridad faltantes:")
        for header in missing_headers:
            print(f"[!] Falta la cabecera de seguridad: {Fore.YELLOW}{header}{Style.RESET_ALL}")
    else:
        print("Todas las cabeceras de seguridad están presentes.")

    print(f"\nTotal de cabeceras de seguridad presentes: {Fore.GREEN}{len(present_headers)}{Style.RESET_ALL}")
    print(f"Total de cabeceras de seguridad faltantes: {Fore.RED}{len(missing_headers)}{Style.RESET_ALL}")

def suggest_recommended_headers(headers):
    recommended_headers = [
        {
            "name": "Cache-Control",
            "value": "no-store, max-age=0"
        },
        {
            "name": "Clear-Site-Data",
            "value": "\"cache\",\"cookies\",\"storage\""
        },
        {
            "name": "Content-Security-Policy",
            "value": "default-src 'self'; form-action 'self'; object-src 'none'; frame-ancestors 'none'; upgrade-insecure-requests; block-all-mixed-content"
        },
        {
            "name": "Cross-Origin-Embedder-Policy",
            "value": "require-corp"
        },
        {
            "name": "Cross-Origin-Opener-Policy",
            "value": "same-origin"
        },
        {
            "name": "Cross-Origin-Resource-Policy",
            "value": "same-origin"
        },
        {
            "name": "Permissions-Policy",
            "value": "accelerometer=(), autoplay=(), camera=(), cross-origin-isolated=(), display-capture=(), encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), keyboard-map=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), publickey-credentials-get=(), screen-wake-lock=(), sync-xhr=(self), usb=(), web-share=(), xr-spatial-tracking=(), clipboard-read=(), clipboard-write=(), gamepad=(), hid=(), idle-detection=(), interest-cohort=(), serial=(), unload=()"
        },
        {
            "name": "Referrer-Policy",
            "value": "no-referrer"
        },
        {
            "name": "Strict-Transport-Security",
            "value": "max-age=31536000; includeSubDomains"
        },
        {
            "name": "X-Content-Type-Options",
            "value": "nosniff"
        },
        {
            "name": "X-Frame-Options",
            "value": "deny"
        },
        {
            "name": "X-Permitted-Cross-Domain-Policies",
            "value": "none"
        }
    ]

    missing_headers = []
    
    for header in recommended_headers:
        if header["name"] not in headers:
            missing_headers.append(header)

    if missing_headers:
        print("\n[!] Cabeceras recomendadas que podrían configurarse:")
        for header in missing_headers:
            print(f"[!] Cabecera: {Fore.YELLOW}{header['name']}: {header['value']}{Style.RESET_ALL}")
    else:
        #print("\nTodas las cabeceras recomendadas están presentes.")
        print("\n")
        
def check_http_to_https_redirection(url):
    response = requests.get(url, allow_redirects=False)
    if response.status_code in (301, 302):
        redirect_url = response.headers.get('Location')
        if redirect_url and redirect_url.startswith('https://'):
            print(f"El sitio {url} redirige de HTTP a HTTPS.")
        else:
            print(f"El sitio {url} no redirige de HTTP a HTTPS.")
    else:
        print(f"El sitio {url} no realiza una redirección.")

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
def load_body(body_arg):
    try:
        with open(body_arg, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, IsADirectoryError):
        try:
            return json.loads(body_arg)
        except json.JSONDecodeError:
            print(f"Error: Invalid JSON format: {body_arg}")
            return None
def parse_headers(header_strings):
    headers = {}
    for raw_header in header_strings:
        try:
            key, value = raw_header.split(':', 1)
            headers[key.strip()] = value.strip()
        except ValueError:
            print(f"Error: Invalid header format: {raw_header}")
    return headers            
            
def get_ip_type(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return "IPv4" if ip_obj.version == 4 else "IPv6"
    except ValueError:
        return "Invalid IP"


def normalize_url(url):
    parsed_url = urlparse(url)
    
    # Si no hay esquema, asumir http por defecto
    if not parsed_url.scheme:
        parsed_url = parsed_url._replace(scheme='http')
    
    # Si no hay puerto, añadir el puerto por defecto según el esquema
    if parsed_url.port is None:
        if parsed_url.scheme == 'http':
            port = 80
        elif parsed_url.scheme == 'https':
            port = 443
        else:
            raise ValueError("Esquema no soportado. Usa 'http' o 'https'.")
        
        # Reconstruir la URL con el puerto por defecto
        netloc = f"{parsed_url.hostname}:{port}"
        normalized_url = urlunparse(parsed_url._replace(netloc=netloc))
    else:
        normalized_url = url
    
    return normalized_url

    
def print_tiempo():
    # Intentar obtener los alias de locales
    try:
        available_locales = locale.locale_aliases()
    except AttributeError:
        # Si ocurre el error, intentar con locale.windows_locale (para Windows)
        available_locales = list(locale.windows_locale.values())

    if 'es_ES.UTF-8' not in available_locales:
        #print("Warning: 'es_ES.UTF-8' locale not found. Using default locale.")
        locale.setlocale(locale.LC_TIME, '')
    else:
        locale.setlocale(locale.LC_TIME, 'es_ES.UTF-8')


    now = datetime.now(timezone.utc)
    gmt_offset = timedelta(hours=-3)
    gmt_time = now + gmt_offset
    formatted_date = now.strftime("%A, %d de %B de %Y %H:%M:%S UTC") + f" ({gmt_time.strftime('%H:%M GMT-3')})"
    print("Fecha y hora:", formatted_date)

def procesar_get(url, headers, proxies):
    response = requests.get(url, headers=headers, proxies=proxies, verify=False)
    return response

def procesar_head(url, headers, proxies):
    response = requests.head(url, headers=headers, proxies=proxies, verify=False)
    return response

def procesar_put(url, headers, body, proxies):
    if body:
        if isinstance(body, dict):
            headers['Content-Type'] = 'application/json'
            response = requests.put(url, headers=headers, json=body, proxies=proxies, verify=False)
        else:
            headers['Content-Type'] = 'text/plain'  # Puede ser XML u otro formato
            response = requests.put(url, headers=headers, data=body, proxies=proxies, verify=False)
    else:
        response = requests.put(url, headers=headers, proxies=proxies, verify=False)
    return response

def procesar_post(url, headers, body, proxies):
    if body:
        if isinstance(body, dict):
            headers['Content-Type'] = 'application/json'
            response = requests.post(url, headers=headers, json=body, proxies=proxies, verify=False)
        else:
            headers['Content-Type'] = 'text/plain'  # Puede ser XML u otro formato
            response = requests.post(url, headers=headers, data=body, proxies=proxies, verify=False)
    else:
        response = requests.post(url, headers=headers, proxies=proxies, verify=False)
    return response
    
def procesar_patch(url, headers, body, proxies):
    if body:
        if isinstance(body, dict):
            headers['Content-Type'] = 'application/json'
            response = requests.patch(url, headers=headers, json=body, proxies=proxies, verify=False)
        else:
            headers['Content-Type'] = 'text/plain'  # Puede ser XML u otro formato
            response = requests.patch(url, headers=headers, data=body, proxies=proxies, verify=False)
    else:
        response = requests.patch(url, headers=headers, proxies=proxies, verify=False)
    return response    
    
def procesar_options(url, headers, proxies):
    response = requests.options(url, headers=headers, proxies=proxies, verify=False)
    return response

def procesar_delete(url, headers, proxies):
    response = requests.delete(url, headers=headers, proxies=proxies, verify=False)
    return response
    
def main():
    # Disable warnings from urllib3
    urllib3.disable_warnings()
    print_banner()

    parser = argparse.ArgumentParser(description='Enviar solicitud HTTP con un verbo especificado')
    parser.add_argument('-b', '--body', type=str, help='Cuerpo de la solicitud en formato JSON (cadena o archivo)')
    parser.add_argument('url', type=str, nargs='?', help='URL de destino')  # Hacer que la URL sea opcional
    parser.add_argument('-v', '--verb', type=str, choices=['GET', 'POST', 'PUT', 'HEAD'], default='GET', help='Verbo HTTP')  # Por defecto GET
    parser.add_argument('-o', '--output', type=str, default='output.json', help='Nombre del archivo de salida JSON')
    parser.add_argument('-H', '--header', type=str, nargs='+', help='Encabezados (se pueden especificar múltiples)')
    parser.add_argument('-p', '--proxy', type=str, help='Dirección del proxy en formato host:puerto')
    parser.add_argument('-i', '--info', action='store_true', help='Mostrar información de los encabezados')  # Uso de flag

    args = parser.parse_args()

    url = args.url

    try:
        normalized_url = normalize_url(url)
        print(f"Dirección: {normalized_url}")
        # Aquí puedes continuar con la lógica de la solicitud HTTP usando normalized_url
    except Exception as e:
        print(f"Error URL: {str(e)}")
    
    verb = args.verb.upper()
    output_file = args.output
    headers = {}
    body = None  # Inicializar body como None
    info = args.info  # Asegúrate de que info esté definido aquí

    # Hacer que la URL sea interactiva si no se proporciona
    if url is None:
        url = input("Introduce la URL: ")

    # Asegurarse de que la URL comience con http:// o https://
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    # Procesar encabezados en bruto
    if args.header:
        headers = parse_headers(args.header)

    # Cargar cuerpo desde un archivo o cadena
    if args.body:
        body = load_body(args.body)

    # Configurar el encabezado Content-Type para solicitudes POST con cuerpo
    if verb == "POST" and body:
        headers['Content-Type'] = 'application/json'

    # Manejar proxy
    proxies = {}
    if args.proxy:
        proxies = {
            "http": f"http://{args.proxy}",
            "https": f"http://{args.proxy}",
        }
        print(f"Usando proxy: {proxies}")

    # Validación y procesamiento usando funciones específicas
    try:
        
        if verb == "GET":
            response = procesar_get(url, headers, proxies)
        elif verb == "HEAD":
            response = procesar_head(url, headers, proxies)
        elif verb == "PUT":
            response = procesar_put(url, headers, body, proxies)
        elif verb == "POST":
            response = procesar_post(url, headers, body, proxies)
        elif verb == "DELETE":
            response = procesar_delete(url, headers, proxies)
        elif verb == "OPTIONS":            
            response = procesar_options(url, headers, proxies)
        elif verb == "PATCH":    
            response = procesar_patch(url, headers, body, proxies)
            
        # Procesar la respuesta de las funciones
        response_headers = response.headers
        output_data = {
            "url": url,
            "status_code": response.status_code,
            "headers": dict(response_headers),
            "ip": get_ip(url),
            "timestamp": datetime.now().isoformat()
        }
        save_to_json(output_data, output_file)

        # Mostrar el código de estado
        check_http_to_https_redirection(url)
        print(f"Código de estado: {response.status_code}")  # Imprimir el código de estado
        

        # Mostrar cabeceras si se solicita
        if info:  # Verificar si el flag info es True
            print_header(response_headers)  # Mostrar cabeceras

        # Funcionalidades adicionales (solo si no se solicitó info)
        print_special_headers(response_headers)
        print_security_headers(response_headers)
        print_tiempo()
        print(f"\n Información Adicional: Sugerencias [Buenas prácticas]\n ")
        suggest_headers_to_remove(response_headers)
        suggest_recommended_headers(response_headers)

    except Exception as e:
        print("Error en el procesamiento específico:", str(e))

if __name__ == "__main__":
    main()