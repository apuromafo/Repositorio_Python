#!/usr/bin/env python

import io
import sys
import os
from datetime import datetime

description = 'Herramienta para validar strings de un cierto largo. Salida en log.txt'
author = 'Apuromafo'
version = '0.0.1'
date = '23.01.2025'
largo = 6
# Generar el nombre del archivo de salida con la fecha actual y hora actual
archivosalida = f'log{datetime.now().strftime("__%m_%d_%Y, %H_%M_%S")}.txt'
# ======================================
# Requiere las siguientes dependencias:
# python3
# ======================================

def strings_util(filename, minimum=largo):
    """Imprime todas las series conectadas de caracteres legibles más largas que el mínimo."""
    with io.open(filename, mode='rb') as f:
        result = ''
        for c in f.read().decode('utf-8', 'ignore'):
            if c in ('0123456789abcdefghijklmnopqrs'
                     'tuvwxyzABCDEFGHIJKLMNOPQRSTUV'
                     'WXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ '):
                result += c
                continue
            if len(result) >= minimum and result[0].isalnum():
                yield '\'' + result + '\''
            result = ''

def procesar_archivo(archivo, log_file):
    """Procesa un archivo y guarda los resultados en el archivo de log."""
    try:
        resultados = list(strings_util(archivo, minimum=largo))
        if resultados:
            log_file.write(f"Resultados para {archivo}:\n")
            for cadena in resultados:
                log_file.write(cadena + '\n')
            log_file.write('\n')
        else:
            log_file.write(f"No se encontraron cadenas legibles en {archivo}.\n\n")
    except Exception as e:
        log_file.write(f"Error al procesar el archivo {archivo}: {e}\n")

def procesar_directorio(directorio, log_file):
    """Procesa todos los archivos en un directorio y sus subdirectorios."""
    for root, dirs, files in os.walk(directorio):
        for file in files:
            archivo = os.path.join(root, file)
            procesar_archivo(archivo, log_file)

def main():
    """Función principal que maneja la entrada del usuario."""
    if len(sys.argv) != 2:
        print(f"Uso: {sys.argv[0]} <archivo_o_directorio>")
        sys.exit(1)

    ruta = sys.argv[1]

    with open(archivosalida, 'w', encoding='utf-8') as log_file:
        if os.path.isfile(ruta):
            procesar_archivo(ruta, log_file)
        elif os.path.isdir(ruta):
            procesar_directorio(ruta, log_file)
        else:
            print("La ruta proporcionada no es un archivo ni un directorio válido.")
            sys.exit(1)

    print(f"El procesamiento ha finalizado. Los resultados se han guardado en {archivosalida}.")

if __name__ == "__main__":
    main()