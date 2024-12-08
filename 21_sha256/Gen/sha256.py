#!/usr/bin/env python

description = 'pequeño generador de sha-256 en minúscula y mayúscula'
author = 'Apuromafo'
version = '0.0.1'
date = '08.12.2024'

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
  
def main():
  parser = argparse.ArgumentParser(description='Calcula el hash SHA-256 de un texto.')
  parser.add_argument('texto', help='El texto a convertir en hash.')
  args = parser.parse_args()

  hash_resultante = calcular_sha256(args.texto)
  print(f"String: {args.texto} \nHash Sha-256:")
  print(hash_resultante)
  print(hash_resultante.upper())

if __name__ == "__main__":
    print_banner()
    main()
 