#!/usr/bin/python3
# -*- coding: utf-8 -*-
import random
import re
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

def generar_rut_aleatorio(rango_inicial=10, rango_final=20, con_puntos=False, con_guion=False):
    rut_numero = random.randint(rango_inicial * 1000000, (rango_final + 1) * 1000000 - 1)
    rut_str = str(rut_numero).zfill(8)
    digito = calcular_digito_verificador(rut_str)
    if con_guion:
        return f"{rut_str[:2]}.{rut_str[2:5]}.{rut_str[5:8]}-{digito}" if con_puntos else f"{rut_str[:2]}{rut_str[2:5]}{rut_str[5:8]}-{digito}"
    else:
        return f"{rut_str[:2]}.{rut_str[2:5]}.{rut_str[5:8]}{digito}" if con_puntos else f"{rut_str}{digito}"

def guardar_resultados(archivo, ruts):
    with open(archivo, 'w') as f:
        f.write("RUTs generados:\n")
        for rut in ruts:
            f.write(rut + '\n')
    print(f"Resultados guardados en '{archivo}'.")

def generar_ruts_aleatorios_interactivo():
    print("\n=== GENERAR RUTS ALEATORIOS ===")
    rango_inicial = int(input("Ingrese el rango inicial (en millones) [por defecto: 10]: ") or 10)
    rango_final = int(input("Ingrese el rango final (en millones) [por defecto: 20]: ") or 20)
    cantidad = int(input("Ingrese la cantidad de RUTs a generar [por defecto: 50]: ") or 50)
    con_puntos = input("¿Desea generar RUTs con puntos? (s/n) [por defecto: n]: ").strip().lower() == 's'
    con_guion = input("¿Desea generar RUTs con guión? (s/n) [por defecto: n]: ").strip().lower() == 's'

    ruts = [generar_rut_aleatorio(rango_inicial, rango_final, con_puntos, con_guion) for _ in range(cantidad)]
    print("\nRUTs generados:")
    for rut in ruts:
        print(rut)

    respuesta = input("\n¿Desea guardar los resultados en un archivo? (s/n) [por defecto: s]: ").strip().lower() or 's'
    if respuesta == 's':
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        archivo = f"ruts_generados_{timestamp}.txt"
        guardar_resultados(archivo, ruts)
        
        
#!/usr/bin/python3
# -*- coding: utf-8 -*-
import random
import re
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

def generar_rut_aleatorio(rango_inicial=10, rango_final=20, con_puntos=False, con_guion=False):
    rut_numero = random.randint(rango_inicial * 1000000, (rango_final + 1) * 1000000 - 1)
    rut_str = str(rut_numero).zfill(8)
    digito = calcular_digito_verificador(rut_str)
    if con_guion:
        return f"{rut_str[:2]}.{rut_str[2:5]}.{rut_str[5:8]}-{digito}" if con_puntos else f"{rut_str[:2]}{rut_str[2:5]}{rut_str[5:8]}-{digito}"
    else:
        return f"{rut_str[:2]}.{rut_str[2:5]}.{rut_str[5:8]}{digito}" if con_puntos else f"{rut_str}{digito}"

def guardar_resultados(archivo, ruts):
    with open(archivo, 'w') as f:
        f.write("RUTs generados:\n")
        for rut in ruts:
            f.write(rut + '\n')
    print(f"Resultados guardados en '{archivo}'.")

def generar_ruts_aleatorios_interactivo():
    print("\n=== GENERAR RUTS ALEATORIOS ===")
    rango_inicial = int(input("Ingrese el rango inicial (en millones) [por defecto: 10]: ") or 10)
    rango_final = int(input("Ingrese el rango final (en millones) [por defecto: 20]: ") or 20)
    cantidad = int(input("Ingrese la cantidad de RUTs a generar [por defecto: 50]: ") or 50)
    con_puntos = input("¿Desea generar RUTs con puntos? (s/n) [por defecto: n]: ").strip().lower() == 's'
    con_guion = input("¿Desea generar RUTs con guión? (s/n) [por defecto: n]: ").strip().lower() == 's'

    ruts = [generar_rut_aleatorio(rango_inicial, rango_final, con_puntos, con_guion) for _ in range(cantidad)]
    print("\nRUTs generados:")
    for rut in ruts:
        print(rut)

    respuesta = input("\n¿Desea guardar los resultados en un archivo? (s/n) [por defecto: s]: ").strip().lower() or 's'
    if respuesta == 's':
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        archivo = f"ruts_generados_{timestamp}.txt"
        guardar_resultados(archivo, ruts)
 