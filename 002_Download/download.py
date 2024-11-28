#!/usr/bin/env python

description = 'Herramienta para descarga, prueba de conversion de Delphi a python3+gui'
author = 'Apuromafo'
version = '0.0.3'
date = '28.11.2024'


import tkinter as tk
from tkinter import messagebox
import requests
import socket
import os
import webbrowser

def download_file(source_url, dest_file):
    try:
        response = requests.get(source_url)
        response.raise_for_status()  # Lanza un error para códigos de respuesta 4xx y 5xx
        with open(dest_file, 'wb') as f:
            f.write(response.content)
        return True
    except Exception as e:
        print(e)
        return False

def get_ip():
    try:
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except Exception as e:
        print(e)
        return "No IP found"

def on_download():
    source_url = entry_url.get()
    dest_file = entry_dest.get() or 'pagina2.html'
    
    if download_file(source_url, dest_file):
        entry_ip.delete(0, tk.END)
        entry_ip.insert(0, get_ip())
        messagebox.showinfo("Info", "Download ok!")
        
        if radio_var.get() == 0:  # Opción 1: Abrir el archivo
            webbrowser.open(os.path.abspath(dest_file))
    else:
        messagebox.showerror("Error", f"Error maybe need http:// {source_url}")

# Configuración de la ventana principal
root = tk.Tk()
root.title("Downloader")

label_url = tk.Label(root, text="Source URL:")
label_url.pack()

entry_url = tk.Entry(root, width=50)
entry_url.pack()

label_dest = tk.Label(root, text="Destination File:")
label_dest.pack()

entry_dest = tk.Entry(root, width=50)
entry_dest.pack()

button_download = tk.Button(root, text="Download", command=on_download)
button_download.pack()

label_ip = tk.Label(root, text="Your IP:")
label_ip.pack()

entry_ip = tk.Entry(root, width=50)
entry_ip.pack()

radio_var = tk.IntVar()
radio_open = tk.Radiobutton(root, text="Open file after download", variable=radio_var, value=0)
radio_open.pack()

radio_dont_open = tk.Radiobutton(root, text="Don't open file", variable=radio_var, value=1)
radio_dont_open.pack()

root.mainloop()