import argparse
import requests
import json
from datetime import datetime, timedelta, timezone
from tabulate import tabulate
from colorama import Fore, Style
import locale
import socket
from urllib.parse import urlparse
import ipaddress

def print_banner():
    banner = """
    ==============================
            Cabeceras 
    ==============================
    """
    print(Fore.CYAN + banner + Style.RESET_ALL)

def save_to_json(data, filename='output.json'):
    with open(filename, 'w') as json_file:
        json.dump(data, json_file, ensure_ascii=False, indent=4)
    print(f"Salida guardada en {filename}")

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
    
    print(f"Total de Headers {total_headers}:\n {header_list}")
    print(f"Headers actuales [Informativo]\n")
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
    present_suggestions = [header for header in suggest_remove if header in headers]
    
    if present_suggestions:
        print("\n[!] Cabeceras que podrían eliminarse:")
        for header in present_suggestions:
            print(f"[!] Cabecera: {Fore.RED}{header}{Style.RESET_ALL}")
    else:
        print("\nTodas las cabeceras sugeridas para eliminación están ausentes.")    

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

def get_ip_type(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return "IPv4" if ip_obj.version == 4 else "IPv6"
    except ValueError:
        return "Invalid IP"

def print_tiempo():
    locale.setlocale(locale.LC_TIME, 'es_ES.UTF-8')
    now = datetime.now(timezone.utc)
    gmt_offset = timedelta(hours=-3)
    gmt_time = now + gmt_offset
    formatted_date = now.strftime("%A, %d de %B de %Y %H:%M:%S UTC") + f" ({gmt_time.strftime('%H:%M GMT-3')})"
    print("Fecha y hora:", formatted_date)

def main():
    print_banner()
    parser = argparse.ArgumentParser(description='Enviar solicitud HTTP con un verbo especificado')
    parser.add_argument('url', type=str, nargs='?', help='URL de destino')
    parser.add_argument('info', type=str, nargs='?', choices=['i'], default=None, help='i = Header info')
    parser.add_argument('verb', type=str, nargs='?', choices=['GET', 'POST', 'PUT', 'HEAD'], default='GET', help='Verbo HTTP')
    parser.add_argument('-o', '--output', type=str, default='output.json', help='Nombre del archivo de salida JSON')
    parser.add_argument('-H', '--header', type=str, help='Header en formato raw para autenticación')

    args = parser.parse_args()
    url = args.url
    verb = args.verb.upper()
    info = args.info
    output_file = args.output
    raw_header = args.header

    if url is None:
        url = input("Introduce la URL: ")

    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    headers = {}
    
    # Si se proporciona un header raw, lo agrega a los headers
    if raw_header:
        try:
            key, value = raw_header.split(':', 1)
            headers[key.strip()] = value.strip()
            print(f"Header importado: {key.strip()}: {value.strip()}")
        except ValueError:
            print("Error: El formato del header debe ser 'Nombre: Valor'.")

    try:
        check_http_to_https_redirection(url)
        response = requests.request(verb, url, headers=headers)
        response_headers = response.headers

        if info is not None:
            print_header(response_headers)
        else:
            print_status(response)

        print_special_headers(response_headers)
        print_security_headers(response_headers)
        print_tiempo()
        print(f"\n Información Adicional: Sugerencias [Buenas prácticas]\n ")
        suggest_headers_to_remove(response_headers)  # Llamada a la nueva función
        suggest_recommended_headers(response_headers)# Llamada a la nueva función
        
        # Guardar cabeceras y otros datos en JSON
        output_data = {
            "url": url,
            "status_code": response.status_code,
            "headers": dict(response_headers),
            "ip": get_ip(url),
            "timestamp": datetime.now().isoformat()
        }
        save_to_json(output_data, output_file)

    except Exception as e:
        print("Error al establecer la conexión:", str(e))


if __name__ == "__main__":
    main()