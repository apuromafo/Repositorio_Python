#!/usr/bin/env python
description = 'Pequeño generador de SHA-256 en minúscula y mayúscula'
author = 'Apuromafo'
version = '0.0.2'
date = '12.02.2025'
#ejemplo de uso pyhton script.py -t "Hola Mundo" -f resultados.txt  

import hashlib
import argparse
import sys
import random
import time  # sleep

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
         __         ___   ___________
   _____/ /_  ____ |__ \ / ____/ ___/
  / ___/ __ \/ __ `/_/ //___ \/ __ \
 (__  ) / / / /_/ / __/____/ / /_/ /
/____/_/ /_/\__,_/____/_____/\____/
  
                     v0.1 
"""
    # Elegir colores aleatorios de las claves del diccionario
    color_keys = list(colors.keys())
    
    for line in banner.split("\n"):
        color = random.choice(color_keys)  # Elegir un color aleatorio
        sys.stdout.write(f"{colors[color]}{line}{clear}\n")  # Imprimir con color del mapa
        time.sleep(0.03)  # Pausa para efecto de tipo máquina de escribir

def calcular_sha256(texto):
    """Calcula el hash SHA-256 de un texto dado.
    Args:
        texto: El texto a convertir en hash.
    Returns:
        Una cadena de texto que representa el hash SHA-256.
    """
    # Codificamos el texto a bytes (necesario para el cálculo del hash)
    texto_bytes = texto.encode('utf-8')
    # Creamos un objeto SHA-256 y actualizamos con los bytes
    sha256 = hashlib.sha256()
    sha256.update(texto_bytes)
    # Obtenemos el hash en formato hexadecimal
    hash_hex = sha256.hexdigest()
    return hash_hex

def guardar_resultados(nombre_archivo, texto, hash_min, hash_may):
    """Guarda los resultados en un archivo."""
    with open(nombre_archivo, 'w') as archivo:
        archivo.write(f"Texto: {texto}\n")
        archivo.write(f"Hash SHA-256 (minúsculas): {hash_min}\n")
        archivo.write(f"Hash SHA-256 (mayúsculas): {hash_may}\n")
    print(f"\nResultados guardados en '{nombre_archivo}'.")

def menu_interactivo():
    """Muestra un menú interactivo para el usuario."""
    while True:
        print("\n--- Menú ---")
        print("1. Calcular hash SHA-256")
        print("2. Salir")
        opcion = input("Seleccione una opción: ")

        if opcion == "1":
            texto = input("Ingrese el texto para calcular su hash: ")
            hash_min = calcular_sha256(texto)
            hash_may = hash_min.upper()
            print(f"\nTexto: {texto}")
            print(f"Hash SHA-256 (minúsculas): {hash_min}")
            print(f"Hash SHA-256 (mayúsculas): {hash_may}")

            guardar = input("\n¿Desea guardar los resultados? (s/n): ").lower()
            if guardar == "s":
                nombre_archivo = input("Ingrese el nombre del archivo para guardar los resultados: ")
                guardar_resultados(nombre_archivo, texto, hash_min, hash_may)

        elif opcion == "2":
            print("Saliendo del programa...")
            break
        else:
            print("Opción inválida. Intente nuevamente.")

def main():
    parser = argparse.ArgumentParser(description='Calcula el hash SHA-256 de un texto.')
    parser.add_argument('-t', '--texto', help='El texto a convertir en hash.', default=None)
    parser.add_argument('-f', '--file', help='Guardar resultados en un archivo.', default=None)
    args = parser.parse_args()

    if args.texto:
        hash_min = calcular_sha256(args.texto)
        hash_may = hash_min.upper()
        print(f"\nTexto: {args.texto}")
        print(f"Hash SHA-256 (minúsculas): {hash_min}")
        print(f"Hash SHA-256 (mayúsculas): {hash_may}")

        if args.file:
            guardar_resultados(args.file, args.texto, hash_min, hash_may)
    else:
        menu_interactivo()

if __name__ == "__main__":
    print_banner()
    main()