#!/usr/bin/env python

description = 'mini herramienta con uso de socket para validar puertos abiertos '
author = 'Apuromafo'
version = '0.0.1'
date = '28.11.2024'

import socket
import logging
import argparse
from concurrent.futures import ThreadPoolExecutor

# Configuración de logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Diccionario de puertos y servicios comunes
SERVICIOS_COMUNES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "MS RPC",
    139: "NetBIOS",
    443: "HTTPS",
    445: "Microsoft-DS",
    3389: "RDP",
    8080: "HTTP alternativo",
    # Puedes agregar más puertos y servicios según sea necesario
}

def grab_banner(sock, puerto):
    """Intenta obtener el banner de un servicio en un socket dado."""
    try:
        sock.settimeout(1)
        
        # Enviar un comando dependiendo del puerto
        if puerto == 80 or puerto == 443:  # HTTP/HTTPS
            sock.sendall(b'HEAD / HTTP/1.1\r\nHost: example.com\r\n\r\n')
        elif puerto == 21:  # FTP
            sock.sendall(b'USER anonymous\r\n')
        elif puerto == 22:  # SSH
            sock.sendall(b'\r\n')  # Simplemente intenta abrir la conexión
        else:
            return "Protocolo no soportado para banner grabbing."

        # Intentar recibir el banner
        banner = sock.recv(1024).decode(errors='replace').strip()
        return banner if banner else "No se pudo obtener el banner."
    except socket.timeout:
        return "Timeout al obtener el banner."
    except UnicodeDecodeError:
        return "Error de codificación al obtener el banner."
    except Exception as e:
        logging.error(f'Error al obtener banner: {e}')
        return "Error desconocido al obtener el banner."

def scan_port(objetivo, puerto):
    """Escanea un único puerto y devuelve el puerto si está abierto."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        if s.connect_ex((objetivo, puerto)) == 0:
            logging.info(f'Puerto {puerto} está abierto.')
            banner = grab_banner(s, puerto)
            servicio = SERVICIOS_COMUNES.get(puerto, "Desconocido")
            return puerto, banner, servicio
    return None

def scaner(objetivo, puertos):
    """Escanea una lista de puertos en un objetivo dado."""
    puertos_abiertos = []
    try:
        with ThreadPoolExecutor(max_workers=100) as executor:
            resultados = list(executor.map(lambda p: scan_port(objetivo, p), puertos))
            puertos_abiertos = [result for result in resultados if result is not None]
    except Exception as e:
        logging.error(f'Error durante el escaneo de puertos: {e}')
        logging.info('Deteniendo el escaneo y registrando resultados hasta este punto.')
        raise  # Relanzar la excepción para que se capture en main
    return puertos_abiertos

def parse_ports(port_args):
    """Parses a list of ports from command line arguments, allowing ranges."""
    ports = []
    for arg in port_args:
        if '-' in arg:  # Si es un rango
            start, end = map(int, arg.split('-'))
            ports.extend(range(start, end + 1))  # Incluye ambos extremos
        else:
            ports.append(int(arg))  # Añade el puerto individual
    return ports

def main():
    # Configuración de argumentos de línea de comandos
    parser = argparse.ArgumentParser(description='Escáner de puertos simple con banner grabbing.')
    parser.add_argument('objetivo', help='IP o dominio a escanear.')
    parser.add_argument('--puertos', nargs='*', default=['1-65535'],
                        help='Lista de puertos a escanear (puede incluir rangos como 20-80).')
    args = parser.parse_args()

    # Parsear los puertos usando la función definida
    puertos = parse_ports(args.puertos)

    logging.info(f'Iniciando el escaneo en {args.objetivo}...')
    try:
        puertos_abiertos = scaner(args.objetivo, puertos)

        if puertos_abiertos:
            for puerto, banner, servicio in puertos_abiertos:
                print(f'Puerto {puerto} está abierto. Banner: {banner}, Servicio: {servicio}')
        else:
            print('No se encontraron puertos abiertos.')

    except Exception as e:
        logging.error(f'Se ha producido un error durante el escaneo: {e}')
        logging.info('El escaneo se ha detenido. Verifica el log para más detalles.')

if __name__ == '__main__':
    main()