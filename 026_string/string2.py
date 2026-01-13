#!/usr/bin/env python
import io
import sys
import os
from datetime import datetime
import time

# Metadatos
description = 'Herramienta para validar strings de un cierto largo. Salida en log.txt'
author = 'Apuromafo'
version = '0.0.1'
date = '23.01.2025'

# Configuración
largo = 6  # Largo mínimo de las cadenas a extraer

# Generar el nombre del archivo de salida con la fecha actual y hora actual
archivosalida = f'log{datetime.now().strftime("__%m_%d_%Y, %H_%M_%S")}.txt'

def strings_util(filename, minimum=largo):
    """Generador que extrae todas las series conectadas de caracteres legibles más largas que el mínimo."""
    with io.open(filename, mode='rb') as f:
        result = ''
        for c in f.read().decode('utf-8', 'ignore'):
            if c in ('0123456789abcdefghijklmnopqrs'
                     'tuvwxyzABCDEFGHIJKLMNOPQRSTUV'
                     'WXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ '):
                result += c
                continue
            if len(result) >= minimum and result[0].isalnum():
                yield result
            result = ''

def procesar_archivo(archivo, log_file):
    """Procesa un archivo y guarda los resultados en el archivo de log."""
    try:
        log_file.write(f"Procesando archivo: {archivo}\n")
        start_time = time.time()  # Inicio del cronómetro
        resultados = list(strings_util(archivo, minimum=largo))
        elapsed_time = time.time() - start_time  # Tiempo transcurrido

        if resultados:
            log_file.write(f"Resultados para {archivo}:\n")
            for cadena in resultados:
                log_file.write(f"'{cadena}'\n")
            log_file.write(f"\nTotal de cadenas encontradas: {len(resultados)}\n")
        else:
            log_file.write(f"No se encontraron cadenas legibles en {archivo}.\n")

        log_file.write(f"Tiempo de procesamiento: {elapsed_time:.2f} segundos\n\n")
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
    total_start_time = time.time()  # Inicio del cronómetro global

    with open(archivosalida, 'w', encoding='utf-8') as log_file:
        log_file.write(f"=== INICIO DEL PROCESAMIENTO ===\n")
        log_file.write(f"Fecha y hora: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

        if os.path.isfile(ruta):
            procesar_archivo(ruta, log_file)
        elif os.path.isdir(ruta):
            procesar_directorio(ruta, log_file)
        else:
            print("La ruta proporcionada no es un archivo ni un directorio válido.")
            sys.exit(1)

        total_elapsed_time = time.time() - total_start_time  # Tiempo total transcurrido
        log_file.write(f"=== FIN DEL PROCESAMIENTO ===\n")
        log_file.write(f"Tiempo total de procesamiento: {total_elapsed_time:.2f} segundos\n")

    print(f"El procesamiento ha finalizado. Los resultados se han guardado en {archivosalida}.")

if __name__ == "__main__":
    main()