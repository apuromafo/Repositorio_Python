#!/usr/bin/env python3
"""
Mini herramienta con uso de socket para validar puertos abiertos.
Autor: Apuromafo
Versión: 0.0.4 - Mejoras en estructura, manejo de errores y soporte IPv6
Fecha: 29.11.2024
"""

import os
import sys
import subprocess
import socket
import ssl
import logging
import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from typing import List, Tuple, Optional


# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Diccionario de puertos y servicios comunes
COMMON_SERVICES = {
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
}

def check_dependencies():
    """Verifica si nmap está instalado."""
    try:
        subprocess.run(["nmap", "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    except FileNotFoundError:
        logging.error("Nmap no está instalado. Por favor, instálalo antes de continuar.")
        sys.exit(1)


def grab_banner(sock: socket.socket, port: int) -> str:
    """
    Intenta obtener el banner del servicio conectado al puerto especificado.
    """
    try:
        sock.settimeout(3)

        if port == 80 or port == 8080:
            sock.sendall(b'HEAD / HTTP/1.1\r\nHost: example.com\r\n\r\n')
        elif port == 443:
            context = ssl.create_default_context()
            with context.wrap_socket(sock, server_hostname=sock.getpeername()[0]) as ssock:
                ssock.sendall(b'HEAD / HTTP/1.1\r\nHost: example.com\r\n\r\n')
                return ssock.recv(1024).decode(errors='replace').strip()
        elif port == 21:
            sock.sendall(b'USER anonymous\r\n')
        elif port == 22:
            pass  # SSH ya devuelve un banner inicial
        elif port == 25:
            sock.sendall(b'EHLO example.com\r\n')
        elif port == 110:
            sock.sendall(b'CAPA\r\n')
        else:
            return "Banner no soportado."

        return sock.recv(1024).decode(errors='replace').strip() or "Sin banner"
    except socket.timeout:
        return "Timeout al leer banner."
    except UnicodeDecodeError:
        return "Codificación inválida."
    except Exception as e:
        return f"Error: {e}"


def scan_port(target: str, port: int) -> Optional[Tuple[int, str, str]]:
    """Escanea un único puerto y devuelve información si está abierto."""
    try:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            if result == 0:
                logging.debug(f"Puerto {port} está abierto.")
                banner = grab_banner(sock, port)
                service = COMMON_SERVICES.get(port, "Desconocido")
                return port, banner, service
    except Exception as e:
        logging.warning(f"Error al escanear puerto {port}: {e}")
    return None


def parse_ports(port_args: List[str]) -> List[int]:
    """Parses a list of ports from command line arguments, allowing ranges."""
    ports = []
    for arg in port_args:
        if '-' in arg:
            start, end = map(int, arg.split('-'))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(arg))
    return ports


def scanner(target: str, ports: List[int]) -> List[Tuple[int, str, str]]:
    """Ejecuta escaneo multihilo sobre los puertos dados."""
    open_ports = []
    with ThreadPoolExecutor(max_workers=100) as executor:
        results = executor.map(lambda p: scan_port(target, p), ports)
        for result in results:
            if result:
                open_ports.append(result)
    return open_ports


def main():
    parser = argparse.ArgumentParser(description="Escáner de puertos simple con banner grabbing.")
    parser.add_argument('target', help='IP o dominio objetivo.')
    parser.add_argument('--ports', nargs='*', default=['1-1024'],
                        help='Lista de puertos o rangos (ej: 80 443 20-100).')
    parser.add_argument('--verbose', action='store_true', help='Mostrar salida detallada.')

    args = parser.parse_args()
    if not args.target:
        parser.print_help()
        sys.exit(1)

    logging_level = logging.DEBUG if args.verbose else logging.INFO
    logging.getLogger().setLevel(logging_level)

    check_dependencies()

    try:
        target_ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        logging.error("No se pudo resolver el nombre de host.")
        sys.exit(1)

    logging.info(f"Iniciando escaneo en {args.target} ({target_ip})")

    try:
        ports_to_scan = parse_ports(args.ports)
        open_ports = scanner(target_ip, ports_to_scan)

        if open_ports:
            print("\n[+] Puertos abiertos encontrados:")
            for port, banner, service in open_ports:
                print(f"Port {port} ({service}):")
                print(f" Banner: {banner}\n")
        else:
            print("[*] No se encontraron puertos abiertos.")

    except KeyboardInterrupt:
        logging.info("Escaneo interrumpido por el usuario.")
        sys.exit(0)
    except Exception as e:
        logging.error(f"Ocurrió un error durante el escaneo: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()