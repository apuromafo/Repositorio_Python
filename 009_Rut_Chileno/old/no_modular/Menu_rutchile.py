#!/usr/bin/python3
# -*- coding: utf-8 -*-
import os
import re
from datetime import datetime
import random

def mostrar_menu():
    print("\n=== MENÚ PRINCIPAL ===")
    print("1. Generar RUTs Aleatorios")
    print("2. Generar RUTs Secuenciales")
    print("3. Validar RUTs")
    print("4. Salir")
    opcion = input("Seleccione una opción (1-4): ").strip()
    return opcion

def main():
    while True:
        try:
            os.system('cls' if os.name == 'nt' else 'clear')  # Limpiar pantalla
            mostrar_banner()
            opcion = mostrar_menu()

            if opcion == '1':
                generar_ruts_aleatorios_interactivo()
            elif opcion == '2':
                generar_ruts_secuenciales_interactivo()
            elif opcion == '3':
                validar_ruts_interactivo()
            elif opcion == '4':
                print("Saliendo del programa. ¡Hasta luego!")
                break
            else:
                print("Opción no válida. Intente nuevamente.")
        except Exception as e:
            print(f"Ocurrió un error inesperado: {e}")
        
        input("\nPresione Enter para continuar...")

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


def generar_rut_aleatorio(rango_inicial=10, rango_final=20, con_puntos=False, con_guion=False):
    rut_numero = random.randint(rango_inicial * 1000000, (rango_final + 1) * 1000000 - 1)
    rut_str = str(rut_numero).zfill(8)
    digito = calcular_digito_verificador(rut_str)
    if con_guion:
        return f"{rut_str[:2]}.{rut_str[2:5]}.{rut_str[5:8]}-{digito}" if con_puntos else f"{rut_str[:2]}{rut_str[2:5]}{rut_str[5:8]}-{digito}"
    else:
        return f"{rut_str[:2]}.{rut_str[2:5]}.{rut_str[5:8]}{digito}" if con_puntos else f"{rut_str}{digito}"


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

 
#inicio banner
colores = {
    "rojo": (255, 0, 0),
    "naranja": (255, 165, 0),
    "amarillo": (255, 255, 0),
    "verde": (0, 255, 0),
    "azul": (0, 0, 255),
    "morado": (128, 0, 128),
}

def interpolar_color(color_inicio, color_fin, posicion):
    r_inicio, g_inicio, b_inicio = color_inicio
    r_fin, g_fin, b_fin = color_fin
    r_nuevo = int(r_inicio + (posicion * (r_fin - r_inicio)))
    g_nuevo = int(g_inicio + (posicion * (g_fin - g_inicio)))
    b_nuevo = int(b_inicio + (posicion * (b_fin - b_inicio)))
    return (r_nuevo, g_nuevo, b_nuevo)

def rgb_a_codigo_ansi(rgb):
    r, g, b = rgb
    return f"\033[38;2;{r};{g};{b}m"

def generar_degradado_colores(color_inicio, color_fin, pasos):
    degradado = []
    for i in range(pasos + 1):
        posicion = i / pasos
        color = interpolar_color(color_inicio, color_fin, posicion)
        codigo_ansi = rgb_a_codigo_ansi(color)
        degradado.append(codigo_ansi)
    return degradado

def mostrar_banner():
    texto = """
:::::::::  :::    ::: :::::::::::	
:+:    :+: :+:    :+:     :+:	
+:+    +:+ +:+    +:+     +:+	
+#++:++#:  +#+    +:+     +#+	
+#+    +#+ +#+    +#+     +#+	
#+#    #+# #+#    #+#     #+#	
###    ###  ########      ###	
 ::::::::  :::    ::: ::::::::::: :::	:::::::::: ::::    :::  ::::::::  
:+:    :+: :+:    :+:     :+:     :+:	:+:	:+:+:   :+: :+:    :+: 
+:+	+:+    +:+     +:+     +:+	+:+	:+:+:+  +:+ +:+    +:+ 
+#+	+#++:++#++     +#+     +#+	+#++:++#   +#+ +:+ +#+ +#+    +:+ 
+#+	+#+    +#+     +#+     +#+	+#+	+#+  +#+#+# +#+    +#+ 
#+#    #+# #+#    #+#     #+#     #+#	#+#	#+#   #+#+# #+#    #+# 
 ########  ###    ### ########### ########## ########## ###    ####  ########  
    v03 by Apuromafo
"""
    color_inicio = colores[random.choice(list(colores.keys()))]
    color_fin = colores[random.choice(list(colores.keys()))]
    degradado = generar_degradado_colores(color_inicio, color_fin, len(texto))
    for i, c in enumerate(texto):
        print(degradado[i % len(degradado)] + c + "\033[0m", end="")
    print()        
#fin banner
  
if __name__ == '__main__':
    main()