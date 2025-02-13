#!/usr/bin/python
# _*_ coding: utf-8 _*_
import random #banner
import math #banner
import argparse
import os
import re
from datetime import datetime
#todo capturas en readme

# Configuración de valores por defecto
RANGO_INICIAL = 10
RANGO_FINAL = 20
CANTIDAD_DEFAULT = 50
ARCHIVO_DEFAULT = 'ruts_generados.txt'

# Define códigos de color (valores RGB)
colores = {
    "rojo": (255, 0, 0),
    "naranja": (255, 165, 0),
    "amarillo": (255, 255, 0),
    "verde": (0, 255, 0),
    "azul": (0, 0, 255),
    "morado": (128, 0, 128),
}

# Función para interpolar valores de color según la posición
def interpolar_color(color_inicio, color_fin, posicion):
    r_inicio, g_inicio, b_inicio = color_inicio
    r_fin, g_fin, b_fin = color_fin

    r_nuevo = int(r_inicio + (posicion * (r_fin - r_inicio)))
    g_nuevo = int(g_inicio + (posicion * (g_fin - g_inicio)))
    b_nuevo = int(b_inicio + (posicion * (b_fin - b_inicio)))

    return (r_nuevo, g_nuevo, b_nuevo)

# Función para generar código ANSI de escape a partir de valores RGB
def rgb_a_codigo_ansi(rgb):
    r, g, b = rgb
    return f"\033[38;2;{r};{g};{b}m"

# Generar un degradado de colores
def generar_degradado_colores(color_inicio, color_fin, pasos):
    degradado = []
    for i in range(pasos + 1):
        posicion = i / pasos
        color = interpolar_color(color_inicio, color_fin, posicion)
        codigo_ansi = rgb_a_codigo_ansi(color)
        degradado.append(codigo_ansi)

    return degradado

# Texto ASCII art
# Fuente: https://patorjk.com/software/taag/#p=display&f=Alligator2&t=Rut%0AChileno
texto = """
:::::::::  :::    ::: :::::::::::                                              
:+:    :+: :+:    :+:     :+:                                                  
+:+    +:+ +:+    +:+     +:+                                                  
+#++:++#:  +#+    +:+     +#+                                                  
+#+    +#+ +#+    +#+     +#+                                                  
#+#    #+# #+#    #+#     #+#                                                  
###    ###  ########      ###                                                  
 ::::::::  :::    ::: ::::::::::: :::        :::::::::: ::::    :::  ::::::::  
:+:    :+: :+:    :+:     :+:     :+:        :+:        :+:+:   :+: :+:    :+: 
+:+        +:+    +:+     +:+     +:+        +:+        :+:+:+  +:+ +:+    +:+ 
+#+        +#++:++#++     +#+     +#+        +#++:++#   +#+ +:+ +#+ +#+    +:+ 
+#+        +#+    +#+     +#+     +#+        +#+        +#+  +#+#+# +#+    +#+ 
#+#    #+# #+#    #+#     #+#     #+#        #+#        #+#   #+#+# #+#    #+# 
 ########  ###    ### ########### ########## ########## ###    ####  ########  

                        v03 by Apuromafo
"""

# Generar colores degradados para el texto
color_inicio = colores[random.choice(list(colores.keys()))]
color_fin = colores[random.choice(list(colores.keys()))]
degradado = generar_degradado_colores(color_inicio, color_fin, len(texto))

# Imprimir el texto con el degradado de color
for i, c in enumerate(texto):
    print(degradado[i % len(degradado)] + c + "\033[0m", end="")
print()  # Nueva línea tras el banner

# Función para calcular el dígito verificador del RUT
def calcular_digito_verificador(rut):
    suma = sum(int(rut[j]) * (3, 2, 7, 6, 5, 4, 3, 2)[j] for j in range(8))
    digito = (11 - suma % 11) % 11
    return 'K' if digito == 10 else str(digito)

# Función para validar un RUT
def validar_rut(rut):
    # Limpiar el RUT de caracteres no deseados
    rut = re.sub(r'[^0-9Kk]', '', rut)  # Eliminar todo excepto números y 'K'
    if len(rut) != 9 or rut[8].upper() not in "0123456789K":
        return False
    
    rut_sin_digito = rut[:-1]  # Sin dígito verificador
    digito_verificador = rut[-1].upper()
    return calcular_digito_verificador(rut_sin_digito) == digito_verificador

# Función para generar un RUT aleatorio
def generar_rut_aleatorio(rango_millones_inicial, rango_millones_final, con_puntos, con_guion):
    rut_numero = random.randint(rango_millones_inicial * 1000000, (rango_millones_final + 1) * 1000000 - 1)
    rut_str = str(rut_numero).zfill(8)
    digito = calcular_digito_verificador(rut_str)

    if con_guion:
        if con_puntos:
            return f"{rut_str[:2]}.{rut_str[2:5]}.{rut_str[5:8]}-{digito}"
        else:
            return f"{rut_str[:2]}{rut_str[2:5]}{rut_str[5:8]}-{digito}"
    else:
        if con_puntos:
            return f"{rut_str[:2]}.{rut_str[2:5]}.{rut_str[5:8]}{digito}"
        else:
            return f"{rut_str}{digito}"

# Función para generar RUTs secuenciales
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

# Función para guardar resultados en un archivo
def guardar_resultados(archivo, ruts, opciones, mostrar_opciones):
    with open(archivo, 'w') as f:
        if mostrar_opciones:
            f.write("Opciones utilizadas:\n")
            for key, value in opciones.items():
                f.write(f"{key}: {value}\n")
            f.write("\nRUTs generados:\n")
        for rut in ruts:
            f.write(rut + '\n')

def es_rut_valido(rut):
    # Verifica que el RUT tenga un formato válido
    # Permite 1-2 dígitos, opcionalmente puntos, y un dígito verificador al final
    if re.match(r'^\d{1,2}(?:\.\d{3}){2}-[\dkK]$', rut) or \
       re.match(r'^\d{1,8}-[\dkK]$', rut) or \
       re.match(r'^\d{1,2}(?:\.\d{3}){2}[\dkK]$', rut) or \
       re.match(r'^\d{1,8}[\dkK]$', rut):
        return True
    return False


# Función principal
def principal():
    # Análisis de argumentos
    parser = argparse.ArgumentParser(description='Generador de RUTs chilenos.')
    parser.add_argument('-m', '--modo', choices=['a', 's'], 
                        help='Modo de operación: "a" para aleatorio o "s" para secuencial.')
    parser.add_argument('-r', '--rango', type=int, nargs=2, metavar=('INICIAL', 'FINAL'),
                        help='Rango en millones para generación aleatoria (INICIAL FINAL). Por defecto: [10, 20].')
    parser.add_argument('-c', '--cantidad', type=int, default=CANTIDAD_DEFAULT, 
                        help='Cantidad de RUTs a generar (por defecto: 50).')
    parser.add_argument('-p', '--con-puntos', action='store_true',
                        help='Generar RUTs con puntos. Por defecto: sin puntos.')
    parser.add_argument('-g', '--con-guion', action='store_true',
                        help='Generar RUTs con guión. Por defecto: sin guión.')
    parser.add_argument('-o', '--rut-inicial', type=int, 
                        help='RUT inicial para generación secuencial.')
    parser.add_argument('-f', '--archivo', type=str, default=ARCHIVO_DEFAULT,
                        help='Nombre del archivo de salida (por defecto: ruts_generados.txt).')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Mostrar la tabla de opciones en la salida y en el archivo.')
    parser.add_argument('-val', '--validar', type=str, nargs='+',
                        help='Validar uno o más RUTs (Ej: 12345678-K ).')
    parser.add_argument('-vo', '--archivo-salida', type=str, help='Nombre del archivo para guardar los resultados de la validación.')


    args = parser.parse_args()

    # Inicializar contadores
    validos = 0
    invalidos = 0
    resultados = []  # Lista para almacenar los resultados

    # Nombre de archivo de salida por defecto
    if not args.archivo_salida:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M")
        args.archivo_salida = f"resultados_{timestamp}.txt"

    # Validar RUTs si se proporcionan
    if args.validar:
        # Verificar si el argumento es un archivo o una lista de RUTs
        if os.path.isfile(args.validar[0]):
            entrada_tipo = f"archivo: {args.validar[0]}"
            try:
                with open(args.validar[0], 'r') as file:
                    ruts = file.readlines()
                    for rut in ruts:
                        rut = rut.strip()  # Eliminar espacios y saltos de línea
                        if es_rut_valido(rut):
                            if validar_rut(rut):
                                resultado = f"El RUT {rut} es válido."
                                print(resultado)
                                resultados.append(resultado)
                                validos += 1
                            else:
                                resultado = f"El RUT {rut} es inválido."
                                print(resultado)
                                resultados.append(resultado)
                                invalidos += 1
                        else:
                            resultado = f"El RUT {rut} no es un formato válido."
                            print(resultado)
                            resultados.append(resultado)
            except FileNotFoundError:
                print(f"El archivo {args.validar[0]} no fue encontrado.")
            except Exception as e:
                print(f"Ocurrió un error al procesar el archivo: {e}")
        else:
            entrada_tipo = "texto"
            # Si no es un archivo, tratar cada argumento como un RUT
            for rut in args.validar:
                rut = rut.strip()  # Limpiar el RUT
                if es_rut_valido(rut):
                    # Aquí se filtra el RUT antes de validar
                    rut_limpio = re.sub(r'[^0-9Kk]', '', rut)  # Eliminar puntos y guiones
                    if validar_rut(rut_limpio):
                        resultado = f"El RUT {rut} es válido."
                        print(resultado)
                        resultados.append(resultado)
                        validos += 1
                    else:
                        resultado = f"El RUT {rut} es inválido."
                        print(resultado)
                        resultados.append(resultado)
                        invalidos += 1
                else:
                    resultado = f"El RUT {rut} no es un formato válido."
                    print(resultado)
                    resultados.append(resultado)
        # Mostrar resumen si se usa verbose
        if args.verbose:
            resumen = "\nResumen de la validación:\n"
            resumen += f"Total válidos: {validos}\n"
            resumen += f"Total inválidos: {invalidos}\n"
            resumen += f"Tipo de entrada: {entrada_tipo}\n"
            print(resumen)
            resultados.append(resumen)

        # Guardar resultados en un archivo de salida
        with open(args.archivo_salida, 'w') as output_file:
            output_file.write("\n".join(resultados))
        print(f"Resultados guardados en {args.archivo_salida}")

        return

    # Si no se proporcionan argumentos, entrar en modo interactivo
    if args.modo is None:
        print("\nBienvenido al generador de RUTs chilenos.")
        modo = input("¿Deseas generar RUTs aleatorios (a) o secuenciales (s)? [por defecto: a]: ").strip().lower()

        while modo not in ['a', 's']:
            print("Por favor, ingresa 'a' para aleatorios o 's' para secuenciales.")
            modo = input("¿Deseas generar RUTs aleatorios (a) o secuenciales (s)? [por defecto: a]: ").strip().lower()

        if modo == 'a':
            rango_inicial = int(input(f"Ingrese el rango inicial (en millones) [por defecto: {RANGO_INICIAL}]: ") or RANGO_INICIAL)
            rango_final = int(input(f"Ingrese el rango final (en millones) [por defecto: {RANGO_FINAL}]: ") or RANGO_FINAL)
            cantidad = int(input(f"Ingrese la cantidad de RUTs a generar [por defecto: {CANTIDAD_DEFAULT}]: ") or CANTIDAD_DEFAULT)
            con_puntos = input("¿Desea generar RUTs con puntos? (s/n) [por defecto: n]: ").strip().lower() == 's'
            con_guion = input("¿Desea generar RUTs con guión? (s/n) [por defecto: n]: ").strip().lower() == 's'
            mostrar_opciones = input("¿Desea mostrar la tabla de opciones? (s/n) [por defecto: n]: ").strip().lower() == 's'
            archivo = input(f"Ingrese el nombre del archivo de salida [por defecto: {ARCHIVO_DEFAULT}]: ") or ARCHIVO_DEFAULT
            
            # Generar RUTs
            ruts = []
            print("\nRUTs generados (Aleatorios):")
            for _ in range(cantidad):
                rut = generar_rut_aleatorio(rango_inicial, rango_final, con_puntos, con_guion)
                ruts.append(rut)
                print(rut)

            # Guardar resultados en el archivo
            guardar_resultados(archivo, ruts, {
                'modo': 'aleatorio',
                'rango': f"Desde {rango_inicial} hasta  {rango_final} ",
                'cantidad': cantidad,
                'con_puntos': con_puntos,
                'con_guion': con_guion,
                'archivo': archivo,
            }, mostrar_opciones)

            # Mostrar opciones si verbose está activado
            if mostrar_opciones:
                opciones = [
                    "Tabla de opciones utilizadas:",
                    "Modo: Aleatorio",
                    f"Rango: {rango_inicial} a {rango_final} millones",
                    f"Cantidad: {cantidad}",
                    f"Con puntos: {'Sí' if con_puntos else 'No'}",
                    f"Con guión: {'Sí' if con_guion else 'No'}",
                    f"Archivo de salida: {archivo}"
                ]
                print("\n".join(opciones))
 
        else:
            rut_inicial = int(input("Ingrese el RUT inicial para generación secuencial [por defecto: 12345678]: ") or 12345678)
            cantidad = int(input(f"Ingrese la cantidad de RUTs a generar [por defecto: {CANTIDAD_DEFAULT}]: ") or CANTIDAD_DEFAULT)
            con_puntos = input("¿Desea generar RUTs con puntos? (s/n) [por defecto: n]: ").strip().lower() == 's'
            con_guion = input("¿Desea generar RUTs con guión? (s/n) [por defecto: n]: ").strip().lower() == 's'
            mostrar_opciones = input("¿Desea mostrar la tabla de opciones? (s/n) [por defecto: n]: ").strip().lower() == 's'
            archivo = input(f"Ingrese el nombre del archivo de salida [por defecto: {ARCHIVO_DEFAULT}]: ") or ARCHIVO_DEFAULT
            rango_inicial = rut_inicial 
            rango_final = rut_inicial + cantidad
            # Generar RUTs
            ruts = generar_rut_secuencial(rut_inicial, cantidad, con_puntos, con_guion)
            print("\nRUTs generados (Secuenciales):")
            for rut in ruts:
                print(rut)

            # Guardar resultados en el archivo
            guardar_resultados(archivo, ruts, {
                'modo': 'secuencial',
                'rut_inicial': rut_inicial,
                'cantidad': cantidad,
                'con_puntos': con_puntos,
                'con_guion': con_guion,
                'archivo': archivo,
            }, mostrar_opciones)

            # Mostrar opciones si verbose está activado
            if mostrar_opciones:
                opciones = [
                    "Tabla de opciones utilizadas:",
                    "Modo: Secuencial",
                    f"Rango: Desde {rango_inicial} hasta  {rango_final} ",
                    f"Cantidad: {cantidad}",
                    f"Con puntos: {'Sí' if con_puntos else 'No'}",
                    f"Con guión: {'Sí' if con_guion else 'No'}",
                    f"Archivo de salida: {archivo}"
                ]
                print("\n".join(opciones))

    else:
        # Ejecutar según los argumentos de línea de comandos
        ruts = []
        if args.modo == 'a':
            if args.rango is None or len(args.rango) != 2:
                rango_inicial, rango_final = RANGO_INICIAL, RANGO_FINAL  # Valores por defecto
            else:
                rango_inicial, rango_final = args.rango
            
            for _ in range(args.cantidad):
                rut = generar_rut_aleatorio(rango_inicial, rango_final, args.con_puntos, args.con_guion)
                ruts.append(rut)
                print(rut)

            # Guardar resultados en el archivo
            guardar_resultados(args.archivo, ruts, {
                'modo': 'aleatorio',
                'rango': f"{rango_inicial} a {rango_final}",
                'cantidad': args.cantidad,
                'con_puntos': args.con_puntos,
                'con_guion': args.con_guion,
                'archivo': args.archivo,
            }, args.verbose)

        elif args.modo == 's':
            if args.rut_inicial is None:
                print("Error: Debes especificar un RUT inicial para el modo secuencial.")
                return
        
        # Definir rango inicial y final para el modo secuencial
            rango_inicial = args.rut_inicial // 1000000  # Asumiendo que el RUT inicial es en millones
            rango_final = rango_inicial  # Si solo generas desde el RUT inicial

            ruts = generar_rut_secuencial(args.rut_inicial, args.cantidad, args.con_puntos, args.con_guion)
            for rut in ruts:
                print(rut)
                # Guardar resultados en el archivo
                guardar_resultados(args.archivo, ruts, {
                    'modo': 'secuencial',
                    'rut_inicial': args.rut_inicial,
                    'cantidad': args.cantidad,
                    'con_puntos': args.con_puntos,
                    'con_guion': args.con_guion,
                    'archivo': args.archivo,
                }, args.verbose)

if __name__ == '__main__':
    principal()