#!/usr/bin/env python

description = 'pequeña herramienta de rotación ROT-n, haciendo uso de rot47'
author = 'Apuromafo'
version = '0.0.1'
date = '08.12.2024'

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
######   ##### ######  ### #######
##   ## ##   ##  ##   #### ##   ##
##   ## ##   ##  ##  ## ##     ##
######  ##   ##  ## ##  ##    ##
#####   ##   ##  ## #######  ##
##  ##  ##   ##  ##     ##   ##
##   ##  #####   ##     ##   ##
  
                     v0.0.1  
"""

    # Elegir colores aleatorios de las claves del diccionario
    color_keys = list(colors.keys())
    
    for line in banner.split("\n"):
        color = random.choice(color_keys)  # Elegir un color aleatorio
        sys.stdout.write(f"{colors[color]}{line}{clear}\n")  # Imprimir con color del mapa
        time.sleep(0.03)  # Pausa para efecto de tipo máquina de escribir


def rot47_char(char, n):
    """Rotates a single character by n positions using ROT-47."""
    if 33 <= ord(char) <= 126:  # Solo caracteres imprimibles
        return chr((ord(char) - 33 + n) % 94 + 33)
    return char  # No modificar caracteres fuera del rango

def rot47(s, n):
    """Encode string s with a custom ROT-n based on ROT-47."""
    return ''.join(rot47_char(char, n) for char in s)

def brute_force_rot47(encoded_string, max_rotations):
    """Apply ROT-n encoding from 1 to max_rotations and return all results."""
    results = []
    
    for i in range(1, max_rotations + 1):  # Rotaciones de 1 a max_rotations
        rotated_string = rot47(encoded_string, i)  # Aplicar ROT-n usando ROT-47
        results.append((i, rotated_string))
    
    return results

def main():
    parser = argparse.ArgumentParser(description="Aplica ROT-n usando ROT-47 a una cadena.")
    parser.add_argument('-s', '--string', required=True, help='Cadena a codificar')
    parser.add_argument('-n', '--rotations', type=int, default=100, help='Número máximo de rotaciones (default: 100)')
    
    args = parser.parse_args()
    
    results = brute_force_rot47(args.string, args.rotations)

    print("ROT-n Results:")
    for attempt in results:
        print(f"Amount = {attempt[0]:>3}: {attempt[1]}")

if __name__ == "__main__":
    print_banner()
    main()