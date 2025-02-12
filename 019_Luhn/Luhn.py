#!/usr/bin/env python
description = 'Fórmula de Luhn, usada en códigos IMEI, además se añaden mejoras adicionales'
author = 'Apuromafo'
version = '0.0.4'
date = '28.11.2024'

import sys
import random
import time  # sleep

def print_banner():
    clear = "\x1b[0m"  # color reset
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
 _      __ __  __ __  ____ 
| T    |  T  T|  T  T|    \
| |    |  |  ||  l  ||  _  Y
| l___ |  |  ||  _  ||  |  |
|     T|  :  ||  |  ||  |  |
|     |l     ||  |  ||  |  |
l_____j \__,_jl__j__jl__j__j
                     v0.1 
"""
    color_keys = list(colors.keys())
    
    for line in banner.split("\n"):
        color = random.choice(color_keys)
        sys.stdout.write(f"{colors[color]}{line}{clear}\n")
        time.sleep(0.03)

def calcular_luhn(imei):
    """Calcula el dígito de verificación de Luhn para un número IMEI."""
    imei = imei.replace(" ", "")
    if not imei.isdigit() or len(imei) not in (14, 15, 16):
        print("Error: El IMEI debe contener solo números y tener una longitud válida (14, 15 o 16).")
        return None
    
    digitos = [int(d) for d in imei]
    suma = 0

    # Calcular la suma de los dígitos según el algoritmo de Luhn
    for i in range(len(digitos) - 1, -1, -2):
        digito = digitos[i] * 2
        suma += digito if digito < 10 else digito - 9

    for i in range(len(digitos) - 2, -1, -2):
        suma += digitos[i]

    # Calcular el dígito de verificación
    digito_verificacion = (10 - suma % 10) % 10
    return digito_verificacion

def validar_imei(imei):
    """Valida si un IMEI es correcto usando el algoritmo de Luhn."""
    imei = imei.replace(" ", "")
    if not imei.isdigit() or len(imei) != 15:
        print("Error: El IMEI debe contener exactamente 15 dígitos.")
        return False

    digito_verificacion_calculado = calcular_luhn(imei[:-1])
    digito_verificacion_real = int(imei[-1])

    if digito_verificacion_calculado == digito_verificacion_real:
        print("El IMEI es válido.")
        return True
    else:
        print("El IMEI no es válido.")
        return False

def generar_imei_valido():
    """Genera un IMEI válido aleatorio."""
    tac = ''.join([str(random.randint(0, 9)) for _ in range(6)])  # Type Allocation Code
    fac = ''.join([str(random.randint(0, 9)) for _ in range(2)])  # Final Assembly Code
    snr = ''.join([str(random.randint(0, 9)) for _ in range(6)])  # Serial Number
    imei_sin_cd = tac + fac + snr
    cd = calcular_luhn(imei_sin_cd)
    return imei_sin_cd + str(cd)

def obtener_info_tac(tac):
    """Obtiene información básica sobre el TAC (fabricante y modelo).
    Esta función puede ser ampliada con una base de datos real."""
    # Simulación de una base de datos de TACs
    db_tac = {
        "123456": {"marca": "Samsung", "modelo": "Galaxy S20"},
        "654321": {"marca": "Apple", "modelo": "iPhone 12"},
        "987654": {"marca": "Xiaomi", "modelo": "Mi 11"},
    }
    return db_tac.get(tac, {"marca": "Desconocido", "modelo": "Desconocido"})

def main():
    print_banner()
    print("Bienvenido a la herramienta de validación y generación de IMEI.\n")

    while True:
        print("Opciones:")
        print("1. Validar un IMEI")
        print("2. Generar un IMEI válido")
        print("3. Salir")
        opcion = input("Seleccione una opción (1/2/3): ")

        if opcion == "1":
            imei = input("[solo números] Ingrese el número IMEI: ")
            if validar_imei(imei):
                tac = imei[:6]
                info_tac = obtener_info_tac(tac)
                print(f"\nDatos del IMEI:")
                print(f"**TAC (Type Allocation Code)**: {tac}")
                print(f"**Fabricante**: {info_tac['marca']}")
                print(f"**Modelo**: {info_tac['modelo']}")
                print(f"**SNR (Serial Number)**: {imei[8:14]}")
                print(f"**CD (Check Digit)**: {imei[14]}")
                print(f"")
        elif opcion == "2":
            imei_generado = generar_imei_valido()
            print(f"IMEI generado válido: {imei_generado}")
        elif opcion == "3":
            print("Saliendo...")
            break
        else:
            print("Opción no válida. Intente nuevamente.")

if __name__ == "__main__":
    main()