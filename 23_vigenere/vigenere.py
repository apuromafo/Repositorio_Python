#!/usr/bin/env python

description = 'Herramienta para hacer uso de VIGENERE'
author = 'Apuromafo'
version = '0.0.4'
date = '17.12.2024'
#otras_herramientas Detect
#001D = 'https://www.dcode.fr/cipher-identifier'
#otras_herramientas decode
#001d = 'https://www.boxentriq.com/code-breaking/vigenere-cipher'
#002d = 'https://cyberchef.io/"
#003d = 'https://cryptii.com/pipes/vigenere-cipher"


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
        print(f"Ocurrió un error: {e}")

def main():
    print_banner()
    parser = argparse.ArgumentParser(description='Cifrar o descifrar texto usando una clave o realizar fuerza bruta.')
    parser.add_argument('-s', '--string', required=True, help='Texto a cifrar o descifrar')
    parser.add_argument('-k', '--key', help='Clave para cifrar o descifrar')
    parser.add_argument('-d', '--decrypt', action='store_true', help='Descifrar el texto en lugar de cifrar')
    parser.add_argument('-f', '--fuerza-bruta', action='store_true', help='Usar fuerza bruta con un diccionario')
    parser.add_argument('-dic', '--diccionario', help='Ruta al archivo de diccionario', required='-f' in sys.argv)

    args = parser.parse_args()

    # Validación de entrada
    if args.fuerza_bruta and not args.diccionario:
        print("Error: Debe proporcionar un archivo de diccionario para la fuerza bruta.")
        return

    if args.fuerza_bruta:
        fuerza_bruta(args.string, args.diccionario)
    else:
        if not args.key:
            print ("Error: La clave es requerida para cifrar o descifrar.")
            return

        resultado = vigenere(args.string, args.key, args.decrypt)

        # Mostrar el resultado en el formato deseado
        print(f'Texto ingresado: {args.string}\n')
        print(f'Clave ingresada: {args.key}\n')
        if args.decrypt:
            print(f'Texto decodificado: {resultado}\n')
        else:
            print(f'Texto cifrado: {resultado}\n')

if __name__ == '__main__':
    main()