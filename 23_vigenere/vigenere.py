import argparse

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

def main():
    parser = argparse.ArgumentParser(description='Cifrar o descifrar texto usando una clave.')
    parser.add_argument('-s', '--string', required=True, help='Texto a cifrar o descifrar')
    parser.add_argument('-k', '--key', required=True, help='Clave para cifrar o descifrar')
    parser.add_argument('-d', '--decrypt', action='store_true', help='Descifrar el texto en lugar de cifrar')

    args = parser.parse_args()

    resultado = vigenere(args.string, args.key, args.decrypt)
    if args.decrypt:
        print(f'Texto descifrado: {resultado}')
    else:
        print(f'Texto cifrado: {resultado}')

if __name__ == '__main__':
    main()