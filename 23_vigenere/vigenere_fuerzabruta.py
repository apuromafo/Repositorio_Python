#!/usr/bin/env python

description = 'Herramienta para hacer uso de VIGENERE'
author = 'Apuromafo'
version = '0.0.3'
date = '16.12.2024'

def print_banner():
    banner = r""" 
##   ##
 ## ##     ##  # ####  # #### #    ##  # ####  # ####  # ####
 ## ##    ### ##   ##  #   ## # #  ##  #   ##  #   ##  #   ##
 ## ##     ## ##       #      # ##  #  #       #  ##   #
 ## ##    ### #       ## ##   #  ## # ## ##   ####    ## ##
  ###     ### #   ### ##      ##  # # ##      ## ##   ##
   #       ## ###  #  ##  ### ##  ### ##  ### ##  ### ##  ###
           ##  #####  ## ###  ##   ## ## ###  ##   ## ## ###
"""
    print(banner)

import argparse
import re
import sys

# Definimos el conjunto de caracteres permitidos, incluyendo caracteres especiales
abc = 'abcdefghijklmnopqrstuvwxyz'

def ajustar_clave(cadena, clave):
    clave_repetida = (clave * (len(cadena) // len(clave) + 1))[:len(cadena)]
    return clave_repetida

def vigenere(cadena, clave, descifrar=False):
    resultado = ''
    clave_repetida = ajustar_clave(cadena, clave).lower()
    clave_index = 0  # Índice para la clave

    for letra in cadena:
        if letra.lower() in abc:
            letra_index = abc.index(letra.lower())
            clave_letra = clave_repetida[clave_index]
            clave_index += 1  # Solo incrementamos si se usa una letra de la clave

            if descifrar:
                nuevo_index = (letra_index - abc.index(clave_letra)) % len(abc)
            else:
                nuevo_index = (letra_index + abc.index(clave_letra)) % len(abc)

            nueva_letra = abc[nuevo_index]
            # Mantener la mayúscula si corresponde
            resultado += nueva_letra.upper() if letra.isupper() else nueva_letra
        else:
            resultado += letra  # Mantiene caracteres no alfabéticos

    return resultado

def fuerza_bruta(ciphertext, dictionary_file):
    try:
        with open(dictionary_file, 'r', encoding='utf-8') as file:
            for line in file:
                key = line.strip()  # Eliminar espacios en blanco y saltos de línea
                if not all(c in abc for c in key.lower()):  # Verificar que la clave solo contenga caracteres válidos
                    print(f'Clave ignorada (no válida): {key}')
                    continue
                decrypted_text = vigenere(ciphertext, key, descifrar=True)
                print(f'Probando clave: {key} -> Texto decodificado: {decrypted_text}')
                # Aquí puedes agregar lógica para validar si el resultado tiene sentido
                # Por ejemplo, verificar si contiene palabras comunes o patrones esperados
    except FileNotFoundError:
        print(f"Error: El archivo '{dictionary_file}' no se encontró.")
    except Exception as e:
        print(f"Ocurrió un error: {e }")

def main():
    print_banner()
    parser = argparse.ArgumentParser(description='Cifrar o descifrar texto usando una clave.')
    parser.add_argument('-s', '--string', required=True, help='Texto cifrado a descifrar')
    parser.add_argument('-f', '--fuerza-bruta', action='store_true', help='Usar fuerza bruta con un diccionario')
    parser.add_argument('-dic', '--diccionario', required='-f' in sys.argv, help='Ruta al archivo de diccionario')

    args = parser.parse_args()

    # Validación de entrada
    if not args.string:
        print("Error: El texto no puede estar vacío.")
        return

    if args.fuerza_bruta:
        fuerza_bruta(args.string, args.diccionario)
    else:
        print("Error: Debe usar la opción de fuerza bruta.")

if __name__ == '__main__':
    main()