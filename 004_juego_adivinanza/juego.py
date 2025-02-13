#!/usr/bin/env python
# -*- coding: utf-8 -*-
# autor @apuromafo
description = 'Juego de adivinanza del 1 al 100, 10 intentos'
author = 'Apuromafo'
version = '0.1.0'
date = '28.11.2024'
font = 'nancyj-improved'
import sys
import random
from colorama import init, Fore
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

 .d888888        dP oo          oo
d8'    88        88
88aaaaa88a .d888b88 dP dP   .dP dP 88d888b. .d8888b. 88d888b. d888888b .d8888b.
88     88  88'  `88 88 88   d8' 88 88'  `88 88'  `88 88'  `88    .d8P' 88'  `88
88     88  88.  .88 88 88 .88'  88 88    88 88.  .88 88    88  .Y8P    88.  .88
88     88  `88888P8 dP 8888P'   dP dP    dP `88888P8 dP    dP d888888P `88888P8
                     v0.1 
"""

    # Elegir colores aleatorios de las claves del diccionario
    color_keys = list(colors.keys())
    
    for line in banner.split("\n"):
        color = random.choice(color_keys)  # Elegir un color aleatorio
        sys.stdout.write(f"{colors[color]}{line}{clear}\n")  # Imprimir con color del mapa
        time.sleep(0.03)  # Pausa para efecto de tipo máquina de escribir
 

def jugar_adivina_el_numero():
    init()  # Inicializar colorama
    numero_secreto = random.randint(1, 100)
    intentos_restantes = 10

    print("¡Bienvenido a 'Adivina el número'!")
    print("Tienes que adivinar un número entre 1 y 100. ¡Buena suerte!")

    while intentos_restantes > 0:
        print(Fore.BLUE + "Intentos restantes:", intentos_restantes)
        intento = int(input("Ingresa tu número: "))

        if intento == numero_secreto:
            print(Fore.GREEN + "¡Felicitaciones! ¡Has adivinado el número!")
            return

        if intento < numero_secreto:
            print(Fore.BLUE + "El número es más grande. Sigue intentando.")
        else:
            print(Fore.BLUE + "El número es más pequeño. Sigue intentando.")

        intentos_restantes -= 1

    print(Fore.BLUE + "¡Has perdido! El número secreto era:", numero_secreto)

 

def main():
    print_banner()
    jugar_adivina_el_numero()
if __name__ == "__main__":
    main()