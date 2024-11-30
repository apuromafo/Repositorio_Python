#!/usr/bin/env python

import requests
import socket
import os
import sys
from urllib.parse import urljoin
from bs4 import BeautifulSoup
import time

description = 'Herramienta para descarga, inspirado en wget pero solo para ciertas extensiones'
author = 'Apuromafo'
version = '0.0.3'
date = '28.11.2024'

# Lista de extensiones permitidas
ALLOWED_EXTENSIONS = ['.pdf', '.jpg', '.jpeg', '.png', '.gif', '.zip', '.docx']

def download_file(source_url, dest_file):
    try:
        response = requests.get(source_url, stream=True)
        response.raise_for_status()  # Lanza un error para códigos de respuesta 4xx y 5xx
        with open(dest_file, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        return True
    except Exception as e:
        print(f"Error al descargar {source_url}: {e}")
        return False

def get_ip():
    try:
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except Exception as e:
        print(f"Error al obtener IP: {e}")
        return "No IP found"

def download_from_website(url, download_to):
    try:
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        links = soup.find_all('a')

        for link in links:
            href = link.get('href')
            if href:
                full_url = urljoin(url, href)
                if any(href.lower().endswith(ext) for ext in ALLOWED_EXTENSIONS):
                    dest_file = os.path.join(download_to, os.path.basename(href))

                    # Comprobar si el archivo ya existe
                    if os.path.exists(dest_file):
                        overwrite = input(f"El archivo {dest_file} ya existe. ¿Deseas sobrescribirlo? (s/n): ")
                        if overwrite.lower() != 's':
                            print(f"Saltando archivo: {dest_file}")
                            continue

                    download_file(full_url, dest_file)
                else:
                    print(f"Saltando archivo no permitido: {full_url}")

    except Exception as e:
        print(f"Error accediendo a {url}: {e}")

def main():
    if len(sys.argv) < 4 or sys.argv[2] != '-o':
        print("Uso: python downloader.py <source_url> -o <dest_folder>")
        print("Ejemplo: python downloader.py http://ejemplo.com/ -o ./descargas")
        return

    source_url = sys.argv[1]
    dest_folder = sys.argv[3]

    # Validar si la carpeta de destino existe
    if not os.path.exists(dest_folder):
        create_folder = input(f"La carpeta {dest_folder} no existe. ¿Deseas crearla? (s/n): ")
        if create_folder.lower() == 's':
            os.makedirs(dest_folder)
        else:
            return

    start_time = time.time()  # Iniciar temporizador
    download_from_website(source_url, dest_folder)
    elapsed_time = time.time() - start_time  # Calcular tiempo transcurrido

    print(f"Descargas completadas en: {dest_folder}")
    print(f"Tu IP: {get_ip()}")
    print(f"Tiempo de ejecución: {elapsed_time:.2f} segundos")

if __name__ == "__main__":
    main()