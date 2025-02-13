#!/usr/bin/env python

description = 'herramienta de uso de ffmpeg para bajar o convertir a mp4 desde una carpeta dada'
author = 'Apuromafo'
version = '0.0.1'
date = '28.11.2024'
#!/usr/bin/env python

import logging
import os
import subprocess
from datetime import datetime
import sys
import shutil

# Logger
logger = logging.getLogger("convertidor_videos")

def configurar_log(detallado):
    """Configura la salida del log para el convertidor de videos."""
    formato_mensaje = '%(asctime)s :: %(levelname)5s ::  %(name)10s :: %(message)s'
    formato_fecha = '%Y-%m-%d %H:%M:%S'
    logging.basicConfig(format=formato_mensaje, datefmt=formato_fecha)
    
    if detallado:
        logger.setLevel(logging.DEBUG)  # Muestra mensajes DEBUG y superiores
    else:
        logger.setLevel(logging.INFO)  # Muestra solo mensajes INFO y superiores
    
    manejador_archivo = logging.FileHandler("errores_conversion.log")
    manejador_archivo.setLevel(logging.DEBUG)
    logger.addHandler(manejador_archivo)

def validar_ffmpeg():
    """Valida si ffmpeg está instalado en el sistema."""
    if shutil.which("ffmpeg") is None:
        print("Error: ffmpeg no está instalado en su sistema.")
        print("Por favor, instale ffmpeg e inténtelo nuevamente.")
        print("Puede descargarlo desde https://ffmpeg.org/download.html")
        logger.error("ffmpeg no está instalado en el sistema.")
        sys.exit(1)
    else:
        logger.info("ffmpeg está instalado correctamente.")
        print("ffmpeg está instalado correctamente.")

def descargar_desde_m3u8(url_m3u8, directorio_salida, detallado=False):
    """Descarga un video desde una URL M3U8."""
    archivo_salida = os.path.join(directorio_salida, "video_descargado.mp4")
    comando = [
        'ffmpeg',
        '-i', url_m3u8,
        '-c', 'copy',
        archivo_salida
    ]
    try:
        subprocess.run(comando, check=True)
        logger.info(f"Descargado: {archivo_salida}")
        print(f"Video descargado exitosamente: {archivo_salida}")
    except subprocess.CalledProcessError as e:
        logger.error(f"Error al descargar desde M3U8: {e}")
        print(f"Error al descargar el video. Revisa el archivo de log para más detalles.")

def convertir_video(archivo_entrada, archivo_salida, detallado=False):
    """Convierte un archivo de video a MP4."""
    comando = [
        'ffmpeg',
        '-i', archivo_entrada,
        '-c:v', 'copy',
        '-c:a', 'aac',
        '-strict', 'experimental',
        archivo_salida
    ]
    try:
        with open(os.devnull, 'w') as devnull:
            subprocess.run(comando, stderr=devnull, check=True)
        logger.info(f"Convertido: {archivo_salida}")
        print(f"Video convertido exitosamente: {archivo_salida}")
    except subprocess.CalledProcessError as e:
        logger.error(f"Error al convertir {archivo_entrada}: {e}")
        print(f"Error al convertir el video. Revisa el archivo de log para más detalles.")

def procesar_directorio(directorio_entrada, directorio_salida, detallado=False):
    """Procesa todos los archivos de video en un directorio."""
    formatos_soportados = (".ts", ".flv", ".mkv", ".avi", ".mov", ".wmv", ".mp4")
    for nombre_archivo in os.listdir(directorio_entrada):
        if nombre_archivo.lower().endswith(formatos_soportados):
            archivo_entrada = os.path.join(directorio_entrada, nombre_archivo)
            nombre_base = os.path.splitext(nombre_archivo)[0]
            marca_tiempo = datetime.now().strftime("%Y%m%d_%H%M%S")
            archivo_salida = os.path.join(directorio_salida, f"{nombre_base}_convertido_{marca_tiempo}.mp4")
            if os.path.exists(archivo_salida):
                respuesta = input(f"El archivo {archivo_salida} ya existe. ¿Desea continuar con un nuevo nombre? (s/n): ").strip().lower()
                if respuesta != 's':
                    logger.info(f"Conversión cancelada para: {archivo_salida}.")
                    print(f"Conversión cancelada para: {archivo_salida}.")
                    continue  # Continuar con el siguiente archivo
            convertir_video(archivo_entrada, archivo_salida, detallado)

def menu_principal():
    """Menú principal interactivo en español."""
    print("\n--- Convertidor de Videos CLI ---")
    print("1. Convertir videos desde un directorio")
    print("2. Descargar video desde una URL M3U8")
    print("3. Salir")
    opcion = input("Seleccione una opción (1/2/3): ").strip()

    if opcion == '1':
        directorio_entrada = input("Ingrese el directorio de entrada: ").strip()
        directorio_salida = input("Ingrese el directorio de salida (deje en blanco para usar el directorio actual): ").strip() or os.getcwd()
        detallado = input("¿Activar modo detallado? (s/n): ").strip().lower() == 's'
        configurar_log(detallado)
        procesar_directorio(directorio_entrada, directorio_salida, detallado)
    elif opcion == '2':
        url_m3u8 = input("Ingrese la URL del archivo M3U8: ").strip()
        directorio_salida = input("Ingrese el directorio de salida (deje en blanco para usar el directorio actual): ").strip() or os.getcwd()
        detallado = input("¿Activar modo detallado? (s/n): ").strip().lower() == 's'
        configurar_log(detallado)
        descargar_desde_m3u8(url_m3u8, directorio_salida, detallado)
    elif opcion == '3':
        print("Saliendo...")
        exit()
    else:
        print("Opción inválida. Intente nuevamente.")
        menu_principal()

if __name__ == '__main__':
    # Validar si ffmpeg está instalado
    validar_ffmpeg()

    while True:
        menu_principal()