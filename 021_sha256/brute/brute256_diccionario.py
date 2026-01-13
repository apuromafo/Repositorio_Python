#!/usr/bin/env python
descripcion = 'Pequeño crack hash de SHA-256 tipo diccionario'
autor = 'Apuromafo'
version = '0.0.2'
fecha = '08.12.2024'
#forma de uso python script.py -hsh "b221d9dbb083a7f33428d7c2a3c3198ae925614d70210e28716ccaa7cd4ddb79" -dic diccionario.txt -f resultados.txt
#!/usr/bin/env python
descripcion = 'Pequeño crack hash de SHA-256 tipo diccionario'
autor = 'Apuromafo'
version = '0.0.2'
fecha = '08.12.2024'

import hashlib
import argparse
import time
import sys
import random

def imprimir_banner():
    clear = "\x1b[0m"  # Resetear color
    # Mapa de colores
    colores = {
        "magenta": "\x1b[35m",
        "rojo": "\x1b[31m",
        "verde": "\x1b[32m",
        "amarillo": "\x1b[33m",
        "azul": "\x1b[34m",
        "cyan": "\x1b[36m",
        "blanco": "\x1b[37m"
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
    claves_colores = list(colores.keys())
    
    for linea in banner.split("\n"):
        color = random.choice(claves_colores)  # Elegir un color aleatorio
        sys.stdout.write(f"{colores[color]}{linea}{clear}\n")  # Imprimir con color del mapa
        time.sleep(0.03)  # Pausa para efecto de máquina de escribir

def ataque_diccionario(hash_objetivo, archivo_diccionario):
    """Realiza un ataque usando un diccionario para encontrar la cadena que genera un hash SHA-256 específico.
    Args:
        hash_objetivo: El hash a encontrar.
        archivo_diccionario: Ruta al archivo que contiene las palabras.
    Returns:
        La palabra encontrada si existe, o None si no se encuentra.
    """
    inicio = time.time()  # Registrar el tiempo inicial
    try:
        with open(archivo_diccionario, 'r', encoding='utf-8') as archivo:
            for linea in archivo:
                palabra = linea.strip()  # Eliminar espacios en blanco
                hash_calculado = hashlib.sha256(palabra.encode('utf-8')).hexdigest()
                if hash_calculado.lower() == hash_objetivo.lower():
                    fin = time.time()  # Registrar el tiempo final
                    tiempo_total = fin - inicio
                    return palabra, tiempo_total  # Retornar la palabra y el tiempo total
    except FileNotFoundError:
        print(f"\nError: El archivo '{archivo_diccionario}' no fue encontrado.")
    except Exception as e:
        print(f"\nError inesperado: {e}")
    return None, None

def guardar_resultados(nombre_archivo, hash_objetivo, palabra_encontrada, tiempo_total):
    """Guarda los resultados en un archivo."""
    try:
        with open(nombre_archivo, 'w', encoding='utf-8') as archivo:
            archivo.write(f"Hash objetivo: {hash_objetivo}\n")
            archivo.write(f"Palabra encontrada: {palabra_encontrada}\n")
            archivo.write(f"Tiempo de ejecución: {tiempo_total:.2f} segundos\n")
        print(f"\nResultados guardados en '{nombre_archivo}'.")
    except Exception as e:
        print(f"\nError al guardar los resultados: {e}")

def menu_interactivo():
    """Muestra un menú interactivo para el usuario."""
    while True:
        print("\n--- Menú ---")
        print("1. Crackear hash SHA-256 usando diccionario")
        print("2. Salir")
        opcion = input("Seleccione una opción: ")

        if opcion == "1":
            hash_objetivo = input("Ingrese el hash SHA-256 a crackear: ")
            archivo_diccionario = input("Ingrese la ruta del archivo de diccionario: ")
            palabra_encontrada, tiempo_total = ataque_diccionario(hash_objetivo, archivo_diccionario)

            if palabra_encontrada:
                print(f"\nPalabra encontrada: {palabra_encontrada}")
                print(f"Tiempo de ejecución: {tiempo_total:.2f} segundos")

                guardar = input("\n¿Desea guardar los resultados? (s/n): ").lower()
                if guardar == "s":
                    nombre_archivo = input("Ingrese el nombre del archivo para guardar los resultados: ")
                    guardar_resultados(nombre_archivo, hash_objetivo, palabra_encontrada, tiempo_total)
            else:
                print("\nNo se encontró ninguna palabra que coincida con el hash.")
        
        elif opcion == "2":
            print("Saliendo del programa...")
            break
        else:
            print("Opción inválida. Intente nuevamente.")

def main():
    parser = argparse.ArgumentParser(description='Realiza un ataque usando un diccionario sobre hashes SHA-256')
    parser.add_argument('-hsh', '--hash', help='El hash SHA-256 a buscar', default=None)
    parser.add_argument('-dic', '--diccionario', help='Ruta al archivo de diccionario', default=None)
    parser.add_argument('-f', '--file', help='Guardar resultados en un archivo', default=None)
    args = parser.parse_args()

    if args.hash and args.diccionario:
        palabra_encontrada, tiempo_total = ataque_diccionario(args.hash, args.diccionario)

        if palabra_encontrada:
            print(f"\nPalabra encontrada: {palabra_encontrada}")
            print(f"Tiempo de ejecución: {tiempo_total:.2f} segundos")

            if args.file:
                guardar_resultados(args.file, args.hash, palabra_encontrada, tiempo_total)
        else:
            print("\nNo se encontró ninguna palabra que coincida con el hash.")
    else:
        menu_interactivo()

if __name__ == "__main__":
    imprimir_banner()
    main()