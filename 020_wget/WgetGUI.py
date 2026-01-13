#!/usr/bin/env python

import requests
import socket
import os
import tkinter as tk
from tkinter import messagebox, filedialog
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
                        overwrite = messagebox.askyesno("Archivo existente", f"El archivo {dest_file} ya existe. ¿Deseas sobrescribirlo?")
                        if not overwrite:
                            print(f"Saltando archivo: {dest_file}")
                            continue

                    download_file(full_url, dest_file)
                else:
                    print(f"Saltando archivo no permitido: {full_url}")

    except Exception as e:
        print(f"Error accediendo a {url}: {e}")

def on_download():
    source_url = entry_url.get()
    dest_folder = entry_dest.get()

    if not source_url or not dest_folder:
        messagebox.showerror("Error", "Por favor, ingresa la URL y la carpeta de destino.")
        return

    # Validar si la carpeta de destino existe
    if not os.path.exists(dest_folder):
        create_folder = messagebox.askyesno("Carpeta no encontrada", f"La carpeta {dest_folder} no existe. ¿Deseas crearla?")
        if create_folder:
            os.makedirs(dest_folder)
        else:
            return

    start_time = time.time()  # Iniciar temporizador
    download_from_website(source_url, dest_folder)
    elapsed_time = time.time() - start_time  # Calcular tiempo transcurrido

    messagebox.showinfo("Info", f"Descargas completadas en: {dest_folder}\nTu IP: {get_ip()}\nTiempo de ejecución: {elapsed_time:.2f} segundos")

def browse_folder():
    folder_selected = filedialog.askdirectory()
    entry_dest.delete(0, tk.END)
    entry_dest.insert(0, folder_selected)

# Configuración de la ventana principal
root = tk.Tk()
root.title("Downloader")

# Establecer tamaño de ventana
root.geometry("500x300")  # Ancho x Alto
root.resizable(False, False)  # Deshabilitar redimensionamiento

label_url = tk.Label(root, text="Source URL:")
label_url.pack(pady=10)

entry_url = tk.Entry(root, width=60)
entry_url.pack(pady=5)

label_dest = tk.Label(root, text="Destination Folder:")
label_dest.pack(pady=10)

entry_dest = tk.Entry(root, width=60)
entry_dest.pack(pady=5)

button_browse = tk.Button(root, text="Browse", command=browse_folder)
button_browse.pack(pady=5)

button_download = tk.Button(root, text="Download", command=on_download)
button_download.pack(pady=20)

root.mainloop()