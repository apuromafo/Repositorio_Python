#!/usr/bin/python3
# -*- coding: utf-8 -*-
import re
import os
from datetime import datetime

def calcular_digito_verificador(rut):
    """
    Calcula el dígito verificador de un RUT chileno.
    :param rut: Número del RUT sin dígito verificador (como string).
    :return: Dígito verificador como string ('K' o número).
    """
    if not rut.isdigit():
        raise ValueError("El RUT debe ser un número entero.")
    
    serie = [2, 3, 4, 5, 6, 7]
    suma = 0
    for i, digito in enumerate(reversed(rut)):
        suma += int(digito) * serie[i % 6]
    resto = suma % 11
    return 'K' if resto == 1 else str((11 - resto) % 11)

def validar_rut(rut):
    """
    Valida un RUT chileno.
    :param rut: RUT completo (con puntos, guion y dígito verificador).
    :return: True si es válido, False si no lo es.
    """
    rut = re.sub(r'[^0-9Kk]', '', rut.strip())
    if len(rut) < 2:
        return False
    cuerpo = rut[:-1]
    digito_verificador = rut[-1].upper()
    try:
        dv_calculado = calcular_digito_verificador(cuerpo)
    except ValueError:
        return False
    return dv_calculado == digito_verificador

def guardar_resultados(archivo, resultados):
    """
    Guarda los resultados de validación en un archivo.
    :param archivo: Nombre del archivo de salida.
    :param resultados: Lista de mensajes de validación.
    """
    with open(archivo, 'w') as f:
        f.write("Resultados de validación:\n")
        for resultado in resultados:
            f.write(resultado + '\n')
    print(f"Resultados guardados en '{archivo}'.")

def validar_multiples_ruts(ruts, archivo_salida=None, verbose=False):
    """
    Valida una lista de RUTs y muestra un resumen.
    :param ruts: Lista de RUTs a validar.
    :param archivo_salida: Archivo donde guardar los resultados (opcional).
    :param verbose: Mostrar detalles adicionales.
    """
    validos = 0
    invalidos = 0
    resultados = []
    for rut in ruts:
        rut = rut.strip()
        if validar_rut(rut):
            resultado = f"El RUT {rut} es válido."
            validos += 1
        else:
            resultado = f"El RUT {rut} es inválido."
            invalidos += 1
        print(resultado)
        resultados.append(resultado)
    
    # Mostrar resumen si verbose está activado
    if verbose:
        resumen = "\nResumen de la validación:\n"
        resumen += f"Total válidos: {validos}\n"
        resumen += f"Total inválidos: {invalidos}\n"
        print(resumen)
        resultados.append(resumen)
    
    # Guardar resultados en un archivo de salida si se especifica
    if archivo_salida:
        guardar_resultados(archivo_salida, resultados)

def validar_ruts_interactivo():
    """
    Función interactiva para validar RUTs desde la entrada del usuario.
    """
    print("\n=== VALIDAR RUTS ===")
    entrada = input("Ingrese uno o más RUTs separados por comas o el nombre de un archivo: ").strip()
    ruts = []
    if os.path.isfile(entrada):  # Verificar si la entrada es un archivo
        with open(entrada, 'r') as file:
            ruts = file.readlines()
    else:
        ruts = entrada.split(',')

    # Validar RUTs
    validar_multiples_ruts(ruts, verbose=True)

    # Preguntar si desea guardar los resultados
    respuesta = input("\n¿Desea guardar los resultados en un archivo? (s/n) [por defecto: s]: ").strip().lower() or 's'
    if respuesta == 's':
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        archivo = f"resultados_validacion_{timestamp}.txt"
        guardar_resultados(archivo, [])