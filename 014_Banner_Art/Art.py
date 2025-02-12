#!/usr/bin/env python3
# Descripción: Herramienta para generación de mini strings tipo art ascii
# Autor: Apuromafo
# Versión: 0.0.5
# Fecha: 12.02.2025

import argparse
import random
import unicodedata
import sys

# Intentar importar pyfiglet; si falla, mostrar un mensaje al usuario
try:
    import pyfiglet
except ImportError:
    print("El módulo 'pyfiglet' no está instalado.")
    print("Por favor, instálalo ejecutando el siguiente comando:")
    print("pip install pyfiglet")
    sys.exit(1)

def imprimir_banner():
    banner = r"""
  __   ____  ____
 / _\ (  _ \(_  _)
/    \ )   /  )(
\_/\_/(__\_) (__)   
                     v0.0.5 Apuromafo
"""
    print(banner)

def ajustar_texto(resultado_ascii):
    """
    Ajusta el texto eliminando el margen común más grande de todas las líneas.
    """
    lineas = resultado_ascii.splitlines()
    
    # Encontrar el número mínimo de espacios iniciales compartidos por todas las líneas
    min_espacios = float('inf')
    for linea in lineas:
        if linea.strip():  # Ignorar líneas vacías
            espacios_iniciales = len(linea) - len(linea.lstrip())
            min_espacios = min(min_espacios, espacios_iniciales)
    
    # Si no hay líneas no vacías, devolver el texto original
    if min_espacios == float('inf'):
        return resultado_ascii
    
    # Eliminar el margen común más grande de todas las líneas
    lineas_ajustadas = [linea[min_espacios:] for linea in lineas]
    return "\n".join(lineas_ajustadas)

def generar_arte_ascii():
    """
    Genera arte ASCII a partir de una cadena de texto, con opciones de fuente aleatoria, ancho y justificación.
    """
    # Crear un objeto de análisis de argumentos
    analizador = argparse.ArgumentParser(description='Generador de arte ASCII')
    
    # Agregar argumentos para personalizar la salida
    analizador.add_argument('-s', '--cadena', type=str, required=True, help='Cadena de texto para convertir a ASCII')
    analizador.add_argument('-r', '--aleatorio', action='store_true', help='Seleccionar una fuente aleatoria')
    analizador.add_argument('-f', '--fuente', type=str, default='slant', help='Fuente a utilizar (ver opciones disponibles en pyfiglet)')
    analizador.add_argument('-w', '--ancho', type=int, default=200, help='Ancho máximo del banner')
    analizador.add_argument('-j', '--justificacion', type=str, choices=['izquierda', 'centro', 'derecha'], default='centro', help='Justificación del texto')
    analizador.add_argument('-o', '--salida', type=str, help='Prefijo del archivo para guardar las versiones original y ajustada')
    
    # Analizar los argumentos proporcionados por el usuario
    argumentos = analizador.parse_args()

    # Lista de fuentes disponibles
    lista_fuentes = pyfiglet.FigletFont.getFonts()

    # Seleccionar fuente aleatoria si se indica la opción `-r`
    if argumentos.aleatorio:
        fuente_seleccionada = random.choice(lista_fuentes)
        print(f"Se ha seleccionado la fuente aleatoria: {fuente_seleccionada}")
    else:
        fuente_seleccionada = argumentos.fuente

    # Verificar si la fuente especificada existe
    if fuente_seleccionada not in lista_fuentes:
        print(f"La fuente '{fuente_seleccionada}' no se encontró. Por favor, elige una de las siguientes:")
        for fuente in lista_fuentes:
            print(fuente)
        sys.exit(1)

    # Mapear justificación en español a inglés para pyfiglet
    justificacion_pyfiglet = {
        "izquierda": "left",
        "centro": "center",
        "derecha": "right"
    }

    # Generar arte ASCII original
    try:
        resultado_original = pyfiglet.figlet_format(
            argumentos.cadena,
            font=fuente_seleccionada,
            width=argumentos.ancho,
            justify=justificacion_pyfiglet[argumentos.justificacion]
        )
    except Exception as e:
        print(f"Error al generar el arte ASCII original: {e}")
        sys.exit(1)

    # Generar arte ASCII ajustado (alineado a la izquierda)
    resultado_ajustado = ajustar_texto(resultado_original)

    # Mostrar resultados en la consola
    #print("\n--- Arte ASCII ORIGINAL ---\n")
    #print(resultado_original)

    #print("\n--- Arte ASCII AJUSTADO (Alineado a la izquierda) ---\n")
    print("\n")
    print(resultado_ajustado)

    # Si se especificó un archivo de salida, guardar ambas versiones
    if argumentos.salida:
        try:
            # Guardar versión original
            archivo_original = f"{argumentos.salida}_original.txt"
            with open(archivo_original, 'w', encoding='utf-8', newline='\n') as archivo:
                archivo.write(resultado_original)
            print(f"\nEl arte ASCII original se guardó en {archivo_original}")

            # Guardar versión ajustada
            archivo_ajustado = f"{argumentos.salida}_ajustado.txt"
            with open(archivo_ajustado, 'w', encoding='utf-8', newline='\n') as archivo:
                archivo.write(resultado_ajustado)
            print(f"El arte ASCII ajustado se guardó en {archivo_ajustado}")
        except IOError as e:
            print(f"Error al escribir en el archivo: {e}")
            sys.exit(1)

if __name__ == "__main__":
    imprimir_banner()
    generar_arte_ascii()