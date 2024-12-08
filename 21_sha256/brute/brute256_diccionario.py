#!/usr/bin/env python

description = 'pequeño crack hash de  sha-256 tipo diccionario'
author = 'Apuromafo'
version = '0.0.2'
date = '08.12.2024'

import hashlib
import argparse
import time
import sys
import random

def print_banner():
    clear = "\x1b[0m"  # color reset

    # Mapa de colores
    colors = {
        "magenta": "\x1b[35m",
        "red": "\x1b[31m",
        "green": "\x1b[32m",
        "yellow": "\x1b[33m",
        "blue": "\x1b[34m",
        "cyan": "\x1b[36m",
        "white": "\x1b[37m"
    }

    banner = r"""
        888              .d8888b. 888888888  .d8888b.    888                    888
        888             d88P  Y88b888       d88P  Y88b   888                    888
        888                    888888       888          888                    888
.d8888b 88888b.  8888b.      .d88P8888888b. 888d888b.    88888b. 888d888888  888888888 .d88b.
88K     888 "88b    "88b .od888P"      "Y88b888P "Y88b   888 "88b888P"  888  888888   d8P  Y8b
"Y8888b.888  888.d888888d88P"            888888    888   888  888888    888  888888   88888888
     X88888  888888  888888"      Y88b  d88PY88b  d88P   888 d88P888    Y88b 888Y88b. Y8b.
 88888P'888  888"Y888888888888888  "Y8888P"  "Y8888P"    88888P" 888     "Y88888 "Y888 "Y8888
  
                     v0.2 
"""

    # Elegir colores aleatorios de las claves del diccionario
    color_keys = list(colors.keys())
    
    for line in banner.split("\n"):
        color = random.choice(color_keys)  # Elegir un color aleatorio
        sys.stdout.write(f"{colors[color]}{line}{clear}\n")  # Imprimir con color del mapa
        time.sleep(0.03)  # Pausa para efecto de tipo máquina de escribir


    
def fuerza_bruta_diccionario(hash_objetivo, archivo_diccionario):
    """Realiza un ataque usando un diccionario para encontrar la cadena que genera un hash SHA-256 específico.

    Args:
        hash_objetivo: El hash a encontrar.
        archivo_diccionario: Ruta al archivo que contiene las palabras.

    Returns:
        La cadena encontrada si existe, o None si no se encuentra.
    """
    
    inicio = time.time()  # Registramos el tiempo inicial

    # Cargar el diccionario
    with open(archivo_diccionario, 'r', encoding='utf-8') as f:
        for linea in f:
            cadena = linea.strip()  # Eliminamos espacios en blanco
            hash_calculado = hashlib.sha256(cadena.encode('utf-8')).hexdigest()
            if hash_calculado.lower() == hash_objetivo.lower():
                fin = time.time()  # Registramos el tiempo final
                tiempo_total = fin - inicio
                print(f"La cadena encontrada es: {cadena}")
                print(f"Tiempo de ejecución: {tiempo_total:.2f} segundos")
                return cadena
    return None
    
def main():
    parser = argparse.ArgumentParser(description='Realiza un ataque usando un diccionario sobre hashes SHA-256')
    parser.add_argument('hash', help='El hash SHA-256 a buscar')
    parser.add_argument('diccionario', help='Ruta al archivo de diccionario')
    args = parser.parse_args()

    resultado = fuerza_bruta_diccionario(args.hash, args.diccionario)

    if resultado is None:
        print("No se encontró ninguna cadena que coincida con el hash.")    

if __name__ == "__main__":
    print_banner()
    main()

