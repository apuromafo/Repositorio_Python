#!/usr/bin/python3
# -*- coding: utf-8 -*-
import os
from generar_aleatorio import generar_ruts_aleatorios_interactivo
from generar_secuencial import generar_ruts_secuenciales_interactivo
from validar_ruts import validar_ruts_interactivo
from banner import mostrar_banner

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
#!/usr/bin/python3
# -*- coding: utf-8 -*-
import random

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
   
if __name__ == '__main__':
    main()