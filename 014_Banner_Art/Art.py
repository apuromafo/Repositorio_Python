#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Descripción: Herramienta para la generación de arte ASCII.
# Autor: Apuromafo
# Versión: 1.0.0
# Fecha: 21.08.2025

import argparse
import random
import sys
import os

try:
    import pyfiglet
except ImportError:
    print("Error: El módulo 'pyfiglet' no está instalado.")
    print("Por favor, instálalo ejecutando: pip install pyfiglet")
    sys.exit(1)

def print_banner():
    """Imprime un banner de bienvenida en arte ASCII."""
    banner = r"""
  __  ____ ____
 / _\ ( _ \( _ )
/    \ )  /  )(
\_/\_/(__\_) (__)
                  v1.0.0 Optimizada
"""
    print(banner)

def get_adjusted_text(ascii_text):
    """
    Ajusta el texto ASCII eliminando el margen común más grande de todas las líneas.
    Esto permite una mejor alineación del resultado.
    """
    lines = ascii_text.splitlines()
    non_empty_lines = [line for line in lines if line.strip()]

    if not non_empty_lines:
        return ascii_text

    min_indent = min(len(line) - len(line.lstrip()) for line in non_empty_lines)
    
    adjusted_lines = [line[min_indent:] for line in lines]
    return "\n".join(adjusted_lines)

def setup_arg_parser():
    """Configura y devuelve el analizador de argumentos de la línea de comandos."""
    parser = argparse.ArgumentParser(
        description="Generador de arte ASCII con opciones de personalización."
    )
    parser.add_argument(
        "-s", "--string", type=str, required=True,
        help="Cadena de texto para convertir a arte ASCII."
    )
    parser.add_argument(
        "-r", "--random", action="store_true",
        help="Seleccionar una fuente aleatoria."
    )
    parser.add_argument(
        "-f", "--font", type=str, default="slant",
        help="Fuente a utilizar. Por defecto es 'slant'."
    )
    parser.add_argument(
        "-w", "--width", type=int, default=200,
        help="Ancho máximo del banner. Por defecto es 200."
    )
    parser.add_argument(
        "-j", "--justify", type=str, choices=["left", "center", "right"],
        default="center", help="Justificación del texto. Por defecto es 'center'."
    )
    parser.add_argument(
        "-o", "--output", type=str,
        help="Prefijo del archivo para guardar las versiones original y ajustada."
    )
    return parser

def generate_ascii_art():
    """
    Genera arte ASCII a partir de la cadena de texto y argumentos del usuario.
    """
    parser = setup_arg_parser()
    args = parser.parse_args()

    # Obtener la lista de fuentes disponibles.
    try:
        fonts_list = pyfiglet.FigletFont.getFonts()
    except Exception as e:
        print(f"Error al obtener la lista de fuentes de pyfiglet: {e}")
        sys.exit(1)

    # Seleccionar la fuente.
    selected_font = args.font
    if args.random:
        selected_font = random.choice(fonts_list)
        print(f"Fuente aleatoria seleccionada: {selected_font}")
    
    if selected_font not in fonts_list:
        print(f"La fuente '{selected_font}' no se encontró.")
        print("Por favor, elige una de las fuentes disponibles o usa -r para una aleatoria.")
        print(f"Fuentes disponibles:\n{', '.join(fonts_list)}")
        sys.exit(1)

    # Generar el arte ASCII.
    try:
        original_art = pyfiglet.figlet_format(
            args.string,
            font=selected_font,
            width=args.width,
            justify=args.justify
        )
    except Exception as e:
        print(f"Error al generar el arte ASCII: {e}")
        sys.exit(1)

    # Ajustar el arte ASCII y mostrarlo.
    adjusted_art = get_adjusted_text(original_art)
    print("\n--- Resultado ---")
    print(adjusted_art)

    # Guardar en archivos si se especifica la opción de salida.
    if args.output:
        save_output(original_art, adjusted_art, args.output)

def save_output(original_text, adjusted_text, prefix):
    """Guarda el arte ASCII original y ajustado en archivos."""
    try:
        # Guardar la versión original.
        original_filename = f"{prefix}_original.txt"
        with open(original_filename, "w", encoding="utf-8") as f:
            f.write(original_text)
        print(f"\nEl arte ASCII original se guardó en: {os.path.abspath(original_filename)}")

        # Guardar la versión ajustada.
        adjusted_filename = f"{prefix}_ajustado.txt"
        with open(adjusted_filename, "w", encoding="utf-8") as f:
            f.write(adjusted_text)
        print(f"El arte ASCII ajustado se guardó en: {os.path.abspath(adjusted_filename)}")
    except IOError as e:
        print(f"Error al escribir los archivos: {e}")

if __name__ == "__main__":
    print_banner()
    generate_ascii_art()