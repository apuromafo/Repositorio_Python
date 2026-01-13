#!/usr/bin/env python
description = 'Pequeño crack hash de SHA-256 numérico 0000 a  9999'
author = 'Apuromafo'
version = '0.0.1'
date = '08.12.2024'
#ejemplo de uso  python .\brute256_num.py -hsh "03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4" -f resultados.txt
#La cadena encontrada es: 1234

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
             _                   ____      ____    ____         _                          _
   ____     FJ___      ___ _    / _  `.   F ___L  F ___]       FJ___     _ ___   _    _   FJ_      ____
  F ___J   J  __ `.   F __` L  J_/-7 .'  J |___| J `--_]      J  __ J   J '__ ",J |  | L J  _|    F __ J
 | '----_  | |--| |  | |--| |  `-:'.'.'  |____ \ | ,--. L     | |--| |  | |__|-J| |  | | | |-'   | _____J
 )-____  L F L  J J  F L__J J  .' ;_J__ .--___) \F L__J |     F L__J J  F L  `-'F L__J J F |__-. F L___--.
J\______/FJ__L  J__LJ\____,__LJ________LJ\______J\______/L   J__,____/LJ__L    J\____,__L\_____/J\______/F
 J______F |__L  J__| J____,__F|________| J______FJ______F    J__,____F |__L     J____,__FJ_____F J______F    
                     v0.1 
"""
    # Elegir colores aleatorios de las claves del diccionario
    color_keys = list(colors.keys())
    
    for line in banner.split("\n"):
        color = random.choice(color_keys)  # Elegir un color aleatorio
        sys.stdout.write(f"{colors[color]}{line}{clear}\n")  # Imprimir con color del mapa
        time.sleep(0.03)  # Pausa para efecto de tipo máquina de escribir

def fuerza_bruta_sha256(hash_objetivo):
    """Realiza un ataque de fuerza bruta para encontrar la cadena que genera un hash SHA-256 específico.
    Args:
        hash_objetivo: El hash a encontrar.
    Returns:
        La cadena encontrada si existe, o None si no se encuentra.
    """
    inicio = time.time()  # Registramos el tiempo inicial
    for i in range(10000):  # Ampliamos el rango a 4 dígitos (0000-9999)
        cadena = str(i).zfill(4)
        hash_calculado = hashlib.sha256(cadena.encode('utf-8')).hexdigest()
        if hash_calculado.lower() == hash_objetivo.lower():
            fin = time.time()  # Registramos el tiempo final
            tiempo_total = fin - inicio
            return cadena, tiempo_total  # Retornamos la cadena y el tiempo total
    return None, None  # Si no se encuentra, retornamos None

def guardar_resultados(nombre_archivo, hash_objetivo, cadena_encontrada, tiempo_total):
    """Guarda los resultados en un archivo."""
    with open(nombre_archivo, 'w') as archivo:
        archivo.write(f"Hash objetivo: {hash_objetivo}\n")
        archivo.write(f"Cadena encontrada: {cadena_encontrada}\n")
        archivo.write(f"Tiempo de ejecución: {tiempo_total:.2f} segundos\n")
    print(f"\nResultados guardados en '{nombre_archivo}'.")

def menu_interactivo():
    """Muestra un menú interactivo para el usuario."""
    while True:
        print("\n--- Menú ---")
        print("1. Crackear hash SHA-256")
        print("2. Salir")
        opcion = input("Seleccione una opción: ")

        if opcion == "1":
            hash_objetivo = input("Ingrese el hash SHA-256 a crackear: ")
            cadena_encontrada, tiempo_total = fuerza_bruta_sha256(hash_objetivo)

            if cadena_encontrada:
                print(f"\nCadena encontrada: {cadena_encontrada}")
                print(f"Tiempo de ejecución: {tiempo_total:.2f} segundos")

                guardar = input("\n¿Desea guardar los resultados? (s/n): ").lower()
                if guardar == "s":
                    nombre_archivo = input("Ingrese el nombre del archivo para guardar los resultados: ")
                    guardar_resultados(nombre_archivo, hash_objetivo, cadena_encontrada, tiempo_total)
            else:
                print("\nNo se encontró ninguna cadena que coincida con el hash.")
        
        elif opcion == "2":
            print("Saliendo del programa...")
            break
        else:
            print("Opción inválida. Intente nuevamente.")

def main():
    parser = argparse.ArgumentParser(description='Realiza un ataque de fuerza bruta sobre hashes SHA-256 de 4 dígitos')
    parser.add_argument('-hsh', '--hash', help='El hash SHA-256 a buscar', default=None)
    parser.add_argument('-f', '--file', help='Guardar resultados en un archivo', default=None)
    args = parser.parse_args()

    if args.hash:
        cadena_encontrada, tiempo_total = fuerza_bruta_sha256(args.hash)

        if cadena_encontrada:
            print(f"\nCadena encontrada: {cadena_encontrada}")
            print(f"Tiempo de ejecución: {tiempo_total:.2f} segundos")

            if args.file:
                guardar_resultados(args.file, args.hash, cadena_encontrada, tiempo_total)
        else:
            print("\nNo se encontró ninguna cadena que coincida con el hash.")
    else:
        menu_interactivo()

if __name__ == "__main__":
    print_banner()
    main()