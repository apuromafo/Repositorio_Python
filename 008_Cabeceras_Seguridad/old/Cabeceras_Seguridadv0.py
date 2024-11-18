#Invoke-WebRequest -Uri https://www.google.com | Select-Object -Expand Headers
#curl -i https://sitio.com
#python Cabeceras_Seguridad.py sitio.com i
#python Cabeceras_Seguridad.py sitio.com i GET
#Securityheaders.com con el check tildado de hideresults

import argparse
import requests
import json
from datetime import datetime, timedelta, timezone
from tabulate import tabulate
from colorama import Fore, Style #agregando color
import locale #para forzar que esté en español el día
import socket #para tener la ip
from urllib.parse import urlparse #para validar ip o dato valido
import ipaddress



def print_status(response):
    # Obtener el código de estado y la descripción
    status_code = response.status_code
    status_description = response.reason

    # Obtener la versión del protocolo HTTP
    http_version = f"HTTP/{response.raw.version // 10}.{response.raw.version % 10}"

    # Obtener la ubicación si está presente
    location = response.headers.get("Location")
    # Crear una lista con los datos de la respuesta
    data = []
    if http_version:
        data.append(["HTTP", http_version])
    if status_code:
        data.append(["Código de estado", status_code])
    if location:
        data.append(["Location", location])
    if status_description:
        data.append(["Descripción", status_description])

    # Verificar si hay suficientes filas para mostrar la tabla
    if data:
        table = tabulate(data, tablefmt="grid", floatfmt=".0f", stralign="left", numalign="right")
        print(table)
    else:
        print("No se encontraron datos para mostrar.")
        
        

def print_header(headers):
    print("Header:")
    disclouse_fields = ['server', 'x-powered-by','x-magento-tags','x-oneagent-js-injection','x-ruxit-js-agent','server-timing']  # Lista de campos disclouse
  # Comentarios
# La cabecera `server` indica el servidor web que se utilizó para generar la respuesta. 
#Esta información puede ser utilizada por atacantes para identificar vulnerabilidades o para personalizar ataques.
# La cabecera `x-powered-by` indica la tecnología utilizada para generar la respuesta. 
#Esta información puede ser utilizada por atacantes para identificar vulnerabilidades o para personalizar ataques.
# La cabecera `x-magento-tags` se utiliza para indicar los tags de caché asociados con una respuesta. 
#Los tags de caché son identificadores únicos que se pueden utilizar para identificar el contenido que ha cambiado. En el caso de Magento, la cabecera `x-magento-tags` puede contener información sobre los productos, categorías y bloques que se muestran en una página. Esta información puede ser utilizada por atacantes para identificar vulnerabilidades o para personalizar ataques.
#`x-oneagent-js-injection` y `x-ruxit-js-agent` indican que el sitio web utiliza el software OneAgent o Ruxit para inyectar JavaScript en las páginas. 
#Este software se utiliza para recopilar datos de rendimiento y otros datos sobre el comportamiento de los usuarios.
# La cabecera `server-timing` indica que el sitio web utiliza el middleware Server Timing para medir el rendimiento de las solicitudes HTTP.
# Este middleware puede recopilar datos sobre el tiempo que se tarda en procesar una solicitud, el tiempo que se tarda en transferir los datos y el tiempo que se tarda en renderizar la página.

    for key, value in headers.items():
        if key.lower() == 'access-control-allow-origin' and value == '*':
            print(f"{Fore.RED}{key}:{Style.RESET_ALL} {value}")
        elif key.lower() in disclouse_fields:
            print(f"{Fore.RED}{key}:{Style.RESET_ALL} {value}")
        else:
            print(f"{key}: {value}")

def print_special_headers(headers):
    special_headers = [
        "Access-Control-Allow-Origin",
        "Access-Control-Allow-Methods",
        "Access-Control-Allow-Headers",
        "Content-Security-Policy-Report-Only",
    ]

    special_present_headers = [header for header in special_headers if header in headers]
    if special_present_headers:
        print("Cabeceras especiales presentes:")
        for header in special_present_headers:
            value = headers[header]
            print(f"[*] Cabecera {Fore.GREEN}{header}{Style.RESET_ALL} está presente! (Valor: {value})")
        print()
    else:
        print()#"No se encontraron cabeceras especiales."

def print_security_headers(headers):
    print("Cabeceras de seguridad:")
    security_headers = ["Content-Security-Policy", "X-XSS-Protection", "X-Frame-Options", "Referrer-Policy", "Strict-Transport-Security", "X-Content-Type-Options", "Permissions-Policy"]
    lowercase_headers = [header.lower() for header in security_headers]
    present_count = 0
    for header, lowercase_header in zip(security_headers, lowercase_headers):
        if header in headers or lowercase_header in headers:
            value = headers.get(header) or headers.get(lowercase_header)
            print(f"[*] Cabecera {Fore.GREEN}{header}{Style.RESET_ALL} está presente! (Valor: {value})")
            present_count += 1
    
    missing_headers = [header for header in security_headers if header not in headers and header.lower() not in headers]
    missing_count = len(missing_headers)
    print("\n[!] Cabeceras de seguridad faltantes:")
    for header in missing_headers:
        print(f"[!] Falta la cabecera de seguridad: {Fore.YELLOW}{header}{Style.RESET_ALL}")
    
    print(f"\nTotal de cabeceras de seguridad presentes: {Fore.GREEN}{present_count}{Style.RESET_ALL}")
    print(f"Total de cabeceras de seguridad faltantes: {Fore.RED}{missing_count}{Style.RESET_ALL}")
    
    
def check_http_to_https_redirection(url):
    response = requests.get(url, allow_redirects=False)

    if response.status_code == 301 or response.status_code == 302:
        redirect_url = response.headers.get('Location')
        if redirect_url and redirect_url.startswith('https://'):
            print(f"El sitio {url} redirige de HTTP a HTTPS.")
        else:
            print(f"El sitio {url} no redirige de HTTP a HTTPS.")
    else:
        print()#f"El sitio {url} no realiza una redirección.")
 
def get_ip(url):
    """Obtiene la dirección IP de un sitio web a partir de una URL completa.

    Args:
        url: La URL completa del sitio web.

    Returns:
        Una cadena que contiene la dirección IP y su tipo entre paréntesis,
        o None si no se pudo obtener la dirección IP.
    """

    if not url or not url.startswith(("http://", "https://")):
        return None

    parsed_url = urlparse(url)
    if not parsed_url.netloc:
        return None

    try:
        domain = parsed_url.netloc.split(':')[0]
        addr_info = socket.getaddrinfo(domain, None)
        ip = addr_info[0][4][0]
        ip_type = get_ip_type(ip)
        return f"{ip} ({ip_type})"
    except (socket.gaierror, IndexError):
        return None

def get_ip_type(ip):
    """Determina si una dirección IP es IPv4 o IPv6.

    Args:
        ip: La dirección IP a verificar.

    Returns:
        "IPv4" si es una dirección IPv4, "IPv6" si es una dirección IPv6,
        o "Invalid IP" si no es una dirección IP válida.
    """

    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.version == 4:
            return "IPv4"
        elif ip_obj.version == 6:
            return "IPv6"
        else:
            return "Invalid IP"
    except ValueError:
        return "Invalid IP"
  
def print_tiempo():
    # Establecer la configuración regional en español
    locale.setlocale(locale.LC_TIME, 'es_ES.UTF-8')

    # Obtener la fecha y hora actual en UTC
    now = datetime.now(timezone.utc)

    # Calcular la fecha y hora en GMT-3
    gmt_offset = timedelta(hours=-3)
    gmt_time = now + gmt_offset

    # Formatear la fecha y hora según el formato deseado
    formatted_date = now.strftime("%A, %d de %B de %Y %H:%M:%S UTC")# // %H:%M GMT%z")
    #formatted_date += f" ({gmt_time.strftime('%H:%M GMT-3')})"

    formatted_date = formatted_date.replace(formatted_date.split(',')[0], formatted_date.split(',')[0].capitalize())
    formatted_date = formatted_date.replace(formatted_date.split(' de ')[1].lower(), formatted_date.split(' de ')[1].capitalize())

    # Agregar hora en GMT-3
    formatted_date += f" ({gmt_time.strftime('%H:%M GMT-3')})"
 
    print("Fecha y hora:", formatted_date)
    
    
def main():

    # Crear el objeto ArgumentParser
    parser = argparse.ArgumentParser(description='Enviar solicitud HTTP con un verbo especificado')

    # Agregar argumentos
    parser.add_argument('url', type=str, nargs='?', help='URL de destino')
    parser.add_argument('info',type=str, nargs='?', choices=['i'], default=None, help='i = Header info')
    parser.add_argument('verb', type=str, nargs='?', choices=['GET', 'get', 'POST', 'post', 'PUT', 'put', 'HEAD', 'head'], default=None, help='Verbo HTTP (GET, POST, PUT, HEAD)')
    

    # Analizar los argumentos de línea de comandos
    args = parser.parse_args()

    # Obtener los valores de los argumentos
    url = args.url
    verb = args.verb
    info =args.info

# Comprobar si se proporcionó una URL
    if url is None:
        url = input("Introduce la URL: ")
# Comprobar si se proporcionó un verbo
    if verb is None:
        verb = "GET"
##
##    print("¿Desea utilizar GET (1), POST (2), PUT (3) o HEAD (4)?")
##    respuesta = input()
##
##    if respuesta == "1":
##        verb = "GET"
##    elif respuesta == "2":
##        verb = "POST"
##    elif respuesta == "3":
##        verb = "PUT"
##    elif respuesta == "4":
##       verb = "HEAD"

# Convertir el verbo a mayúsculas si no es None
    if verb is not None:
        verb = verb.upper()

# Imprimir el verbo seleccionado
    #print("Verbo seleccionado:", verb)

    # Agregar el esquema "https://" si no está presente en la URL
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    # Verificar redirección HTTP a HTTPS
    try:
        check_http_to_https_redirection(url)
        # Enviar la solicitud HTTP
        response = requests.request(verb, url)
        headers = response.headers
    # Imprimir la versión del protocolo HTTP
    #protocol_version = f"HTTP/{response.raw.version // 10}.{response.raw.version % 10}"
    # Imprimir el código de estado y descripción, si hay location, además que la indique.
    #print_status(response)
    #print() # Imprimir una línea en blanco
    # Imprimir el header
        if info is not None:
            print_header(headers)
        else:
            print()
#    print() # Imprimir una línea en blanco
        
        print_special_headers(headers)
 #   print()
        print_security_headers(headers)
  #  print()
    except Exception as e:
        #print(e)
        print("Dirección ingresada refleja un error (No se puede establecer una conexión) ")
        
    ip = get_ip(url)
    if ip is not None:
        print(f"La dirección IP del servidor {url} es: {ip}")
    else:
        print(f"No se pudo obtener la dirección IP del servidor {url}")
    
    
    print_tiempo()
    
if __name__ == "__main__":
    main()