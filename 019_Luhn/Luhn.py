#!/usr/bin/env python

description = 'fórmula de Luhn, usada en códigos IMEI, además se añade mejoras adicionales'
author = 'Apuromafo'
version = '0.0.4'
date = '28.11.2024'
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
 _      __ __  __ __  ____ 
| T    |  T  T|  T  T|    \
| |    |  |  ||  l  ||  _  Y
| l___ |  |  ||  _  ||  |  |
|     T|  :  ||  |  ||  |  |
|     |l     ||  |  ||  |  |
l_____j \__,_jl__j__jl__j__j

                     v0.1 
"""

    # Elegir colores aleatorios de las claves del diccionario
    color_keys = list(colors.keys())
    
    for line in banner.split("\n"):
        color = random.choice(color_keys)  # Elegir un color aleatorio
        sys.stdout.write(f"{colors[color]}{line}{clear}\n")  # Imprimir con color del mapa
        time.sleep(0.03)  # Pausa para efecto de tipo máquina de escribir

def calcular_luhn(imei):
    """Calcula el dígito de verificación de Luhn para un número IMEI.

    Args:
        imei (str): El número IMEI.

    Returns:
        int: El dígito de verificación, o None si hay un error.
    """
    # Limpiar espacios y verificar que solo contenga dígitos
    imei = imei.replace(" ", "")
    if not imei.isdigit() or len(imei) not in (14, 15, 16):
        print("Error: El IMEI debe contener solo números y tener una longitud válida (14, 15 o 16).")
        return None

    # Convertir IMEI a una lista de dígitos
    digitos = [int(d) for d in imei]

    # Inicializar suma para el cálculo de Luhn
    suma = 0

    # Calcular la suma de los dígitos según el algoritmo de Luhn
    for i in range(len(digitos) - 1, -1, -2):
        digito = digitos[i] * 2
        suma += digito if digito < 10 else digito - 9
    
    for i in range(len(digitos) - 2, -1, -2):
        suma += digitos[i]

    # Calcular el dígito de verificación
    digito_verificacion = (10 - suma % 10) % 10
    
    # Extraer datos básicos del IMEI
    tac = imei[:6]
    fac = imei[6:8]
    snr = imei[8:14]
    cd = imei[14] if len(imei) == 15 else imei[15] if len(imei) == 16 else None

    print(f"\nDatos del IMEI:")
    print(f"**TAC (Type Allocation Code)**: {tac}")
    print(f"**FAC (Final Assembly Code)**: {fac}")
    print(f"**SNR (Serial Number)**: {snr}")
    print(f"**CD (Check Digit)**: {cd}")

    return digito_verificacion

def main():
    # Obtener el número IMEI del usuario
    imei = input("[solo números] Ingrese el número IMEI: ")

    # Calcular y mostrar los resultados
    digito_verificacion = calcular_luhn(imei)

    if digito_verificacion is not None:
        print("Dígito de verificación de Luhn:", digito_verificacion)
    else:
        print("No se pudo calcular el dígito de verificación debido a un error en la entrada.")

if __name__ == "__main__":
    print_banner()
    main()