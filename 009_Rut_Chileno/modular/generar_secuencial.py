#!/usr/bin/python3
# -*- coding: utf-8 -*-
import re
from datetime import datetime

def calcular_digito_verificador(rut):
    if not rut.isdigit():
        raise ValueError("El RUT debe ser un número entero.")
    serie = [2, 3, 4, 5, 6, 7]
    suma = 0
    for i, digito in enumerate(reversed(rut)):
        suma += int(digito) * serie[i % 6]
    resto = suma % 11
    return 'K' if resto == 1 else str((11 - resto) % 11)

def generar_ruts_secuenciales(rut_inicial, cantidad, con_puntos=False, con_guion=False):
    """
    Genera una lista de RUTs secuenciales.
    :param rut_inicial: RUT inicial desde donde comenzar la secuencia.
    :param cantidad: Cantidad de RUTs a generar.
    :param con_puntos: Incluir puntos en el formato.
    :param con_guion: Incluir guion antes del dígito verificador.
    :return: Lista de RUTs generados.
    """
    ruts = []
    # Asegurarse de que el RUT inicial tenga exactamente 8 dígitos
    rut_inicial = int(str(rut_inicial)[:8])  # Truncar a 8 dígitos si es necesario

    for i in range(cantidad):
        rut_str = str(rut_inicial + i).zfill(8)  # Incrementar y asegurar longitud de 8 dígitos
        digito = calcular_digito_verificador(rut_str)
        if con_guion:
            if con_puntos:
                ruts.append(f"{rut_str[:2]}.{rut_str[2:5]}.{rut_str[5:8]}-{digito}")
            else:
                ruts.append(f"{rut_str[:2]}{rut_str[2:5]}{rut_str[5:8]}-{digito}")
        else:
            if con_puntos:
                ruts.append(f"{rut_str[:2]}.{rut_str[2:5]}.{rut_str[5:8]}{digito}")
            else:
                ruts.append(f"{rut_str}{digito}")
    return ruts

def guardar_resultados(archivo, ruts):
    with open(archivo, 'w') as f:
        f.write("RUTs generados:\n")
        for rut in ruts:
            f.write(rut + '\n')
    print(f"Resultados guardados en '{archivo}'.")

def generar_ruts_secuenciales_interactivo():
    print("\n=== GENERAR RUTS SECUENCIALES ===")
    rut_inicial = int(input("Ingrese el RUT inicial para generación secuencial [por defecto: 12345678]: ") or 12345678)
    cantidad = int(input("Ingrese la cantidad de RUTs a generar [por defecto: 50]: ") or 50)
    con_puntos = input("¿Desea generar RUTs con puntos? (s/n) [por defecto: n]: ").strip().lower() == 's'
    con_guion = input("¿Desea generar RUTs con guión? (s/n) [por defecto: n]: ").strip().lower() == 's'

    ruts = generar_ruts_secuenciales(rut_inicial, cantidad, con_puntos, con_guion)
    print("\nRUTs generados:")
    for rut in ruts:
        print(rut)

    respuesta = input("\n¿Desea guardar los resultados en un archivo? (s/n) [por defecto: s]: ").strip().lower() or 's'
    if respuesta == 's':
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        archivo = f"ruts_generados_{timestamp}.txt"
        guardar_resultados(archivo, ruts)