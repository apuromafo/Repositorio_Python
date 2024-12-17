#!/usr/bin/env python

description = 'Herramienta para hacer uso de VIGENERE'
author = 'Apuromafo'
version = '0.0.2'
date = '16.12.2024'
#otras_herramientas detect
001_D = 'https://www.dcode.fr/cipher-identifier'
#otras_herramientas decode
001_d = 'https://www.boxentriq.com/code-breaking/vigenere-cipher'
002_d = 'https://cyberchef.io/"
003_d = 'https://cryptii.com/pipes/vigenere-cipher"


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

# Definimos el conjunto de caracteres permitidos, incluyendo caracteres especiales
abc = 'abcdefghijklmnopqrstuvwxyz'
caracteres_validos = re.compile(r'^[a-zA-Z0-9\s!@#$%^&*()_+=:/]*$')

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

def main():
    print_banner()
    parser = argparse.ArgumentParser(description='Cifrar o descifrar texto usando una clave.')
    parser.add_argument('-s', '--string', required=True, help='Texto a cifrar o descifrar')
    parser.add_argument('-k', '--key', required=True, help='Clave para cifrar o descifrar')
    parser.add_argument('-d', '--decrypt', action='store_true', help='Descifrar el texto en lugar de cifrar')

    args = parser.parse_args()

    # Validación de entrada
    if not args.string or not args.key:
        print("Error: El texto y la clave no pueden estar vacíos.")
        return

    #if not caracteres_validos.match(args.string) or not caracteres_validos.match(args.key):
    #    print("Error: El texto y la clave solo pueden contener caracteres alfanuméricos y algunos caracteres especiales.")
    #    return

    try:
        resultado = vigenere(args.string, args.key, args.decrypt)
        
        # Mostrar el resultado en el formato deseado
        print(f'Texto ingresado: {args.string}\n')
        print(f'Clave ingresada: {args.key}\n')
        if args.decrypt:
            print(f'Texto decodificado: {resultado}\n')
        else:
            print(f'Texto cifrado: {resultado}\n')
    except Exception as e:
        print(f"Ocurrió un error: {e}")

if __name__ == '__main__':
    main()