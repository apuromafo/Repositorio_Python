#!/usr/bin/env python
# -*- coding: utf-8 -*-
# autor @apuromafo

description = 'Juego de adivinanza del 1 al 100, 10 intentos'
author = 'Apuromafo'
version = '0.1.0'
date = '28.11.2024'

import random
from colorama import init, Fore

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

jugar_adivina_el_numero()