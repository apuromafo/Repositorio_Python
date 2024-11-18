#!/usr/bin/python
# _*_ coding: utf8 _*_

#todo generar ruts random
#todo generar validador de rut válidos
#todo optimizar algoritmo

#banner  añadir colores en banner  OK
import math
import random

# Define color codes (corrected: use actual RGB values)
colors = {
    "red": (255, 0, 0),  # Use RGB tuples for colors
    "orange": (255, 165, 0),
    "yellow": (255, 255, 0),
    "green": (0, 255, 0),
    "blue": (0, 0, 255),
    "purple": (128, 0, 128),
}

# Function to interpolate color values based on position
def interpolate_color(start_color, end_color, position):
    r_start, g_start, b_start = start_color  # Access RGB values from dictionary
    r_end, g_end, b_end = end_color  # Access RGB values from dictionary

    r_new = int(r_start + (position * (r_end - r_start)))
    g_new = int(g_start + (position * (g_end - g_start)))
    b_new = int(b_start + (position * (b_end - b_start)))

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

# Print a text with color gradient

#fuente: https://patorjk.com/software/taag/#p=display&f=Alphabet&t=RUT%20%0ACHILENO
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
start_color = colors[random.choice(list(colors.keys()))]  # Choose a random color from the dictionary
end_color = colors[random.choice(list(colors.keys()))] 
#end_color = colors["blue"]
gradient = generate_color_gradient(start_color, end_color, len(text))

for i, c in enumerate(text):
    print(gradient[i % len(gradient)] + c + "\033[0m", end="")
                                  
# strings en uso
Str1 = "Falta instalar algunas librerías"
Str2 = "RUTs"
str_descripcion=" RUT CHILENO V0.2 by Apuromafo "
# errores rut distinto a 8 dígitos

try:
    import argparse
    from prettytable import PrettyTable
except ImportError as error:
    print(Str1)
    print(error)
    print(str_descripcion)
x = PrettyTable()
x.field_names = ["Argumento", "Descripción del Diccionario", "Rut Ejemplo","Ejemplo uso"]
x.align["Descripción del Diccionario"] = "l" #alinea a la izquierda
x.align["Rut Ejemplo"] = "l" #alinea a la izquierda
x.add_row(["-f", Str2+" con puntos, guión y dígito verificador" ,"12.345.678-9",
          "python rutchile.py -f -o full.txt"])
x.add_row(["-d", Str2+" solo con dígito verificador" ,"12345678-9",
          "python rutchile.py -d -o digit.txt"])
x.add_row(["-l", Str2+" sin puntos ni guión con dígito verificador" ,"123456789",
          "python rutchile.py -l -o list.txt"])
x.add_row(["-m", Str2+" sin dígito verificador" ,"12345678",
          "python rutchile.py -m -o miss.txt"])

print(str_descripcion)

parser = argparse.ArgumentParser(description=str_descripcion)

parser.add_argument('-f', '--full', action='store_true',
                    help="Generar RUTs con puntos, guión y dígito verificador Ej: 12.345.678-9")
parser.add_argument('-d', '--digit', action='store_true',
                    help="Generar RUTs solo con dígito verificador  Ej: 12345678-9")
parser.add_argument('-l', '--list', action='store_true',
                    help="Generar RUTs sin puntos ni guión con dígito verificador Ej: 123456789")
parser.add_argument('-m', '--miss', action='store_true',
                    help="Generar solo RUTs sin dígito verificador Ej: 12345678")
parser.add_argument("-o", "--output_file", type=str,
                    default="diccionario.txt", help="Nombre del archivo de salida")
parser.add_argument('-i', '--info', action='store_true', help=print(x))
# Parsear los argumentos de la línea de comando
parser = parser.parse_args()
output_file_name = parser.output_file

#        Solicita al usuario que ingrese un valor de la longitud especificada y lo valida.


def pedir_valor(mensaje, longitud):
    while True:
        valor = input(mensaje)
        if len(valor) != longitud:
            print(f"El valor ingresado debe tener {longitud} caracteres")
        elif not valor.isdigit():
            print("El valor ingresado debe ser un número entero")
        elif valor[0] == '0':
            print("El valor ingresado no puede comenzar con 0")
        else:
            rut = int(valor)
            if longitud == 8 and rut == 99999999:
                print("El valor ingresado no puede ser 99999999")
            elif longitud == 9 and rut == 999999999:
                print("El valor ingresado no puede ser 999999999")
            else:
                return rut


def main():
    if parser.full:
        digito = None
        rut = []
        rut_ini = int(pedir_valor('Ingrese el RUT inicial (8 dígitos): ', 8))
        rut_fin = int(pedir_valor('Ingrese el RUT final (8 dígitos): ', 8))
        if  rut_ini >  rut_fin:
             rut_ini,  rut_fin =  rut_fin,  rut_ini
        f = open(output_file_name, 'w')
        for i in range(rut_ini, rut_fin + 1):
            rut = str(i)
            suma = sum(int(rut[j]) * (3, 2, 7, 6, 5, 4, 3, 2)[j]
                       for j in range(8))
            digito = str((11 - suma % 11) % 11)
            if digito == '10':
                digito = 'K'
            print(rut[0]+rut[1]+"."+rut[2]+rut[3] +rut[4]+"."+rut[5]+rut[6]+rut[7]+"-"+digito)
            f.write(rut[0]+rut[1]+"."+rut[2]+rut[3]+rut[4] +"."+rut[5]+rut[6]+rut[7]+"-"+digito+"\n")
        f.close()

    elif parser.digit:
        digito = None
        rut = []
        rut_ini = int(pedir_valor('Ingrese el RUT inicial (8 dígitos): ', 8))
        rut_fin = int(pedir_valor('Ingrese el RUT final (8 dígitos): ', 8))
        if  rut_ini >  rut_fin:
             rut_ini,  rut_fin =  rut_fin,  rut_ini
        f = open(output_file_name, 'w')
        for i in range(rut_ini, rut_fin + 1):
            rut = str(i)
            suma = sum(int(rut[j]) * (3, 2, 7, 6, 5, 4, 3, 2)[j]
                       for j in range(8))
            digito = str((11 - suma % 11) % 11)
            if digito == '10':
                digito = 'K'
            print(rut[0]+rut[1]+rut[2]+rut[3] +rut[4]+rut[5]+rut[6]+rut[7]+"-"+digito)
            f.write(rut[0]+rut[1]+rut[2]+rut[3]+rut[4] +rut[5]+rut[6]+rut[7]+"-"+digito+"\n")
        f.close()

    elif parser.list:
        digito = None
        rut = []
        rut_ini = int(pedir_valor('Ingrese el RUT inicial (8 dígitos): ', 8))
        rut_fin = int(pedir_valor('Ingrese el RUT final (8 dígitos): ', 8))
        if  rut_ini >  rut_fin:
             rut_ini,  rut_fin =  rut_fin,  rut_ini
        f = open(output_file_name, 'w')
        for i in range(rut_ini, rut_fin + 1):
            rut = str(i)
            suma = sum(int(rut[j]) * (3, 2, 7, 6, 5, 4, 3, 2)[j]
                       for j in range(8))
            digito = str((11 - suma % 11) % 11)
            if digito == '10':
                digito = 'K'
            print(rut[0]+rut[1]+rut[2]+rut[3] +rut[4]+rut[5]+rut[6]+rut[7]+digito)
            f.write(rut[0]+rut[1]+rut[2]+rut[3]+rut[4] +rut[5]+rut[6]+rut[7]+digito+"\n")
        f.close()

    elif parser.miss:
        digito = None
        rut = []
        rut_ini = int(pedir_valor('Ingrese el RUT inicial (8 dígitos): ', 8))
        rut_fin = int(pedir_valor('Ingrese el RUT final (8 dígitos): ', 8))
        if  rut_ini >  rut_fin:
             rut_ini,  rut_fin =  rut_fin,  rut_ini        
        f = open(output_file_name, 'w')
        
        for i in range(rut_ini, rut_fin + 1):
            rut = str(i)
            suma = sum(int(rut[j]) * (3, 2, 7, 6, 5, 4, 3, 2)[j]
                       for j in range(8))
            digito = str((11 - suma % 11) % 11)
            if digito == '10':
                digito = 'K'
            print(rut[0]+rut[1]+rut[2]+rut[3] +rut[4]+rut[5]+rut[6]+rut[7])
            f.write(rut[0]+rut[1]+rut[2]+rut[3]+rut[4] +rut[5]+rut[6]+rut[7]+"\n")
        f.close()


if __name__ == '__main__':
    main()
