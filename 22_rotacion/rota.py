#!/usr/bin/env python

description = 'pequeña herramienta de rotación ROT-n, solo letras'
author = 'Apuromafo'
version = '0.0.2'
date = '08.12.2024'
import string
import argparse

def rot(s, n=13):
    """Encode string s with ROT-n, shifting all letters n positions.
    Values of n over 26 or negative values are handled appropriately.
    Defaults to ROT-13 if n is not supplied.
    """
    n = n % 26  # Normalizar n
    upper = string.ascii_uppercase
    lower = string.ascii_lowercase
    upper_start = ord(upper[0])
    lower_start = ord(lower[0])
    out = ''
    
    for letter in s:
        if letter in upper:
            out += chr(upper_start + (ord(letter) - upper_start + n) % 26)
        elif letter in lower:
            out += chr(lower_start + (ord(letter) - lower_start + n) % 26)
        else:
            out += letter  # No modificar caracteres que no son letras
    return out

def brute_force_rot(encoded_string, max_rotations=100):
    """Apply ROT-n encoding from 1 to max_rotations and return all results."""
    results = []
    
    for i in range(1, max_rotations + 1):  # Rotaciones de 1 a max_rotations
        rotated_string = rot(encoded_string, i)  # Aplicar ROT-n directamente
        results.append((i, rotated_string))
    
    return results

def main():
    parser = argparse.ArgumentParser(description="Aplica ROT-n a una cadena.")
    parser.add_argument('-s', '--string', required=True, help='Cadena a codificar')
    parser.add_argument('-n', '--rotations', type=int, default=100, help='Número máximo de rotaciones (default: 100)')
    
    args = parser.parse_args()
    
    results = brute_force_rot(args.string, args.rotations)

    print("ROT-n Results:")
    for attempt in results:
        print(f"Amount = {attempt[0]:>3}: {attempt[1]}")

if __name__ == "__main__":
    main()