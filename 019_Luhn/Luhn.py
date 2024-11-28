#!/usr/bin/env python

description = 'fórmula de Luhn, usada en códigos IMEI'
author = 'Apuromafo'
version = '0.0.3'
date = '28.11.2024'

def calcular_luhn(imei):
    """Calcula el dígito de verificación de Luhn para un número IMEI.

    Args:
        imei (str): El número IMEI.

    Returns:
        int: El dígito de verificación, o None si hay un error.
    """
    # Limpiar espacios y verificar que solo contenga dígitos
    imei = imei.replace(" ", "")
    if not imei.isdigit():
        print("Error: El IMEI debe contener solo números.")
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
    main()