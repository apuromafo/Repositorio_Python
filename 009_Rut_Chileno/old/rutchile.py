#!/usr/bin/python
# _*_ coding: utf-8 _*_
import random
import argparse
import os

# Configuración de valores por defecto
RANGO_INICIAL = 10
RANGO_FINAL = 20
CANTIDAD_DEFAULT = 50
ARCHIVO_DEFAULT = 'ruts_generados.txt'

# Define color codes (RGB values)
colors = {
    "red": (255, 0, 0),
    "orange": (255, 165, 0),
    "yellow": (255, 255, 0),
    "green": (0, 255, 0),
    "blue": (0, 0, 255),
    "purple": (128, 0, 128),
}

# Function to interpolate color values based on position
def interpolate_color(start_color, end_color, position):
    r_start, g_start, b_start = start_color
    r_end, g_end, b_end = end_color

    r_new = int(r_start + (position * (r_end - r_start)))
    g_new = int(g_start + (position * (g_end - g_start)))
    b_new = int(g_start + (position * (b_end - b_start)))

    return (r_new, g_new, b_new)

# Function to generate ANSI escape code from RGB values
def rgb_to_ansi_code(rgb):
    r, g, b = rgb
    return f"\033[38;2;{r};{g};{b}m"

# Generate a gradient of colors
def generate_color_gradient(start_color, end_color, steps):
    gradient = []
    for i in range(steps + 1):
        position = i / steps
        color = interpolate_color(start_color, end_color, position)
        ansi_code = rgb_to_ansi_code(color)
        gradient.append(ansi_code)

    return gradient

# ASCII art text
text = """
RRRR  U   U TTTTTT                  
R   R U   U   TT                    
RRRR  U   U   TT                    
R R   U   U   TT                    
R  RR  UUU    TT                    
                                    
                                    
 CCC H  H III L    EEEE N   N  OOO  
C    H  H  I  L    E    NN  N O   O 
C    HHHH  I  L    EEE  N N N O   O 
C    H  H  I  L    E    N  NN O   O 
 CCC H  H III LLLL EEEE N   N  OOO  

                        by Apuromafo
"""

# Generate gradient colors for the text
start_color = colors[random.choice(list(colors.keys()))]
end_color = colors[random.choice(list(colors.keys()))]
gradient = generate_color_gradient(start_color, end_color, len(text))

# Print the text with the color gradient
for i, c in enumerate(text):
    print(gradient[i % len(gradient)] + c + "\033[0m", end="")

# Function to calculate the verification digit for RUT
def calcular_digito_verificador(rut):
    suma = sum(int(rut[j]) * (3, 2, 7, 6, 5, 4, 3, 2)[j] for j in range(8))
    digito = (11 - suma % 11) % 11
    return 'K' if digito == 10 else str(digito)

# Function to generate a random RUT
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

# Function to generate sequential RUTs
def generar_rut_secuencial(rut_ini, cantidad, con_puntos, con_guion):
    ruts = []
    for i in range(cantidad):
        rut_str = str(rut_ini + i).zfill(8)
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

# Function to save results to a file
def guardar_resultados(archivo, ruts, opciones, mostrar_opciones):
    with open(archivo, 'w') as f:
        if mostrar_opciones:
            f.write("Opciones utilizadas:\n")
            for key, value in opciones.items():
                f.write(f"{key}: {value}\n")
            f.write("\n")
            f.write("RUTs generados:\n")
        for rut in ruts:
            f.write(rut + '\n')

# Main function
def main():
    # Argument parsing
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

    args = parser.parse_args()

    # If no arguments are provided, enter interactive mode
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
            mostrar_opciones = input("¿Desea mostrar la tabla de opciones? (s/n) [por defecto: n]: ").strip().lower() == 's' # Opciones para mostrar la tabla
            archivo = input(f"Ingrese el nombre del archivo de salida [por defecto: {ARCHIVO_DEFAULT}]: ") or ARCHIVO_DEFAULT
            
            # Generate RUTs
            ruts = []
            print("\nRUTs generados (Aleatorios):")
            for _ in range(cantidad):
                rut = generar_rut_aleatorio(rango_inicial, rango_final, con_puntos, con_guion)
                ruts.append(rut)
                print(rut)

            # Save results to file
            guardar_resultados(archivo, ruts, {
                'modo': 'aleatorio',
                'rango': f"{rango_inicial} a {rango_final} millones",
                'cantidad': cantidad,
                'con_puntos': con_puntos,
                'con_guion': con_guion,
                'archivo': archivo,
            }, args.verbose)

            # Show options if verbose is set
            if args.verbose:
                print("\nTabla de opciones utilizadas:")
                print(f"Modo: {'Aleatorio'}")
                print(f"Rango: {rango_inicial} a {rango_final} millones")
                print(f"Cantidad: {cantidad}")
                print(f"Con puntos: {'Sí' if con_puntos else 'No'}")
                print(f"Con guión: {'Sí' if con_guion else 'No'}")
                print(f"Archivo de salida: {archivo}")

        else:
            rut_inicial = int(input(f"Ingrese el RUT inicial para generación secuencial [por defecto: 12345678]: ") or 12345678)
            cantidad = int(input(f"Ingrese la cantidad de RUTs a generar [por defecto: {CANTIDAD_DEFAULT}]: ") or CANTIDAD_DEFAULT)
            con_puntos = input("¿Desea generar RUTs con puntos? (s/n) [por defecto: n]: ").strip().lower() == 's'
            con_guion = input("¿Desea generar RUTs con guión? (s/n) [por defecto: n]: ").strip().lower() == 's'
            mostrar_opciones = input("¿Desea mostrar la tabla de opciones? (s/n) [por defecto: n]: ").strip().lower() == 's' # Opciones para mostrar la tabla
            archivo = input(f"Ingrese el nombre del archivo de salida [por defecto: {ARCHIVO_DEFAULT}]: ") or ARCHIVO_DEFAULT

            # Generate RUTs
            ruts = generar_rut_secuencial(rut_inicial, cantidad, con_puntos, con_guion)
            print("\nRUTs generados (Secuenciales):")
            for rut in ruts:
                print(rut)

            # Save results to file
            guardar_resultados(archivo, ruts, {
                'modo': 'secuencial',
                'rut_inicial': rut_inicial,
                'cantidad': cantidad,
                'con_puntos': con_puntos,
                'con_guion': con_guion,
                'archivo': archivo,
            }, args.verbose)

            # Show options if verbose is set
            if args.verbose:
                print("\nTabla de opciones utilizadas:")
                print(f"Modo: {'Secuencial'}")
                print(f"RUT inicial: {rut_inicial}")
                print(f"Cantidad: {cantidad}")
                print(f"Con puntos: {'Sí' if con_puntos else 'No'}")
                print(f"Con guión: {'Sí' if con_guion else 'No'}")
                print(f"Archivo de salida: {archivo}")

    else:
        # Execute based on command line arguments
        ruts = []
        if args.modo == 'a':
            if args.rango is None or len(args.rango) != 2:
                rango_inicial, rango_final = RANGO_INICIAL, RANGO_FINAL  # Default values
            else:
                rango_inicial, rango_final = args.rango
            
            for _ in range(args.cantidad):
                rut = generar_rut_aleatorio(rango_inicial, rango_final, args.con_puntos, args.con_guion)
                ruts.append(rut)
                print(rut)

            # Save results to file
            guardar_resultados(args.archivo, ruts, {
                'modo': 'aleatorio',
                'rango': f"{rango_inicial} {rango_final}",
                'cantidad': args.cantidad,
                'con_puntos': args.con_puntos,
                'con_guion': args.con_guion,
                'archivo': args.archivo,
            }, args.verbose)  # Pass verbose option

        elif args.modo == 's':
            if args.rut_inicial is None:
                print("Error: Debes especificar un RUT inicial para el modo secuencial.")
                return
            ruts = generar_rut_secuencial(args.rut_inicial, args.cantidad, args.con_puntos, args.con_guion)
            for rut in ruts:
                print(rut)

            # Save results to file
            guardar_resultados(args.archivo, ruts, {
                'modo': 'secuencial',
                'rut_inicial': args.rut_inicial,
                'cantidad': args.cantidad,
                'con_puntos': args.con_puntos,
                'con_guion': args.con_guion,
                'archivo': args.archivo,
            }, args.verbose)  # Pass verbose option

if __name__ == '__main__':
    main()