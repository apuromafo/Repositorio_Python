#!/usr/bin/env python

description = 'Herramienta de uso de ffmpeg para bajar o convertir a mp4, o unir video/audio.'
author = 'Apuromafo'
version = '0.0.1'
date = '28.11.2024'

import logging
import os
import subprocess
from datetime import datetime
import sys
import shutil
import re # Necesario para el análisis de metadatos del archivo unido

# --- Configuración por Defecto para la Opción 3 ---
# Estas constantes se usan como valores sugeridos en el menú.
DEFAULT_DIR = "Video"
DEFAULT_VIDEO_INPUT = os.path.join(DEFAULT_DIR, "video.ts")
DEFAULT_AUDIO_INPUT = os.path.join(DEFAULT_DIR, "audio.ts")
DEFAULT_OUTPUT = os.path.join(DEFAULT_DIR, "video_ok.mp4")
# --------------------------------------------------

# Logger
logger = logging.getLogger("herramienta_ffmpeg")

# --- Funciones de Configuración y Utilidad ---

def configurar_log(detallado):
    """Configura la salida del log para la herramienta de ffmpeg."""
    formato_mensaje = '%(asctime)s :: %(levelname)5s ::  %(name)10s :: %(message)s'
    formato_fecha = '%Y-%m-%d %H:%M:%S'
    
    # Restablecer handlers existentes si se llama varias veces (importante para el bucle del menú)
    if logger.handlers:
        logger.handlers.clear()
        
    logging.basicConfig(format=formato_mensaje, datefmt=formato_fecha, level=logging.INFO)
    
    if detallado:
        logger.setLevel(logging.DEBUG)  # Muestra mensajes DEBUG y superiores
    else:
        logger.setLevel(logging.INFO)  # Muestra solo mensajes INFO y superiores
    
    manejador_archivo = logging.FileHandler("errores_ffmpeg.log")
    manejador_archivo.setLevel(logging.DEBUG)
    formatter = logging.Formatter(formato_mensaje, datefmt=formato_fecha)
    manejador_archivo.setFormatter(formatter)
    logger.addHandler(manejador_archivo)

def validar_ffmpeg():
    """Valida si ffmpeg está instalado en el sistema."""
    if shutil.which("ffmpeg") is None:
        print("❌ Error: ffmpeg no está instalado en su sistema.")
        print("Por favor, instale ffmpeg e inténtelo nuevamente.")
        print("Puede descargarlo desde https://ffmpeg.org/download.html")
        sys.exit(1)
    else:
        logger.info("ffmpeg está instalado correctamente.")
        print("✅ ffmpeg está instalado correctamente.")

# --- Funciones de Análisis de Metadatos (Usando solo ffmpeg) ---

def analizar_con_ffmpeg(ruta_archivo):
    """
    Usa ffmpeg en modo "solo lectura" y expresiones regulares para extraer
    la duración, resolución y bitrate estimado del archivo analizando su log.
    """
    comando_analisis = [
        "ffmpeg",
        "-i", ruta_archivo,
        "-f", "null",
        "-"
    ]

    caracteristicas = {
        'duracion': None,
        'resolucion': "N/A",
        'bitrate_video': "N/A",
        'bitrate_audio': "N/A"
    }

    try:
        resultado = subprocess.run(
            comando_analisis,
            check=False,
            capture_output=True,
            text=True
        )

        log_text = resultado.stderr

        # 1. Duración (Pattern: Duration: 00:02:48.00)
        match_duracion = re.search(r"Duration: (\d{2}):(\d{2}):(\d{2}\.\d{2})", log_text)
        if match_duracion:
            horas = int(match_duracion.group(1))
            minutos = int(match_duracion.group(2))
            segundos = float(match_duracion.group(3))
            caracteristicas['duracion'] = horas * 3600 + minutos * 60 + segundos

        # 2. Resolución (Pattern: Video: h264 (...), 1920x1080 ...)
        match_resolucion = re.search(r"Video:.*?(\d{3,4}x\d{3,4})", log_text)
        if match_resolucion:
            caracteristicas['resolucion'] = match_resolucion.group(1)

        # 3. Bitrate Global (Pattern: bitrate: 785 kb/s)
        match_bitrate_global = re.search(r"bitrate: (\d+) kb/s", log_text)
        if match_bitrate_global:
            br_kbps = match_bitrate_global.group(1)
            
            # Estimación del Bitrate de Video (el más grande, se muestra en Mbps)
            br_video_mbps = int(br_kbps) / 1000
            caracteristicas['bitrate_video'] = f"{br_video_mbps:.2f} Mbps (Estimado)"
            
            # Bitrate de Audio (se asume el valor predeterminado de AAC)
            caracteristicas['bitrate_audio'] = "Aprox. 128-192 Kbps (AAC predeterminado)"
            
    except Exception as e:
        logger.error(f"Error al analizar el log de ffmpeg: {e}")

    return caracteristicas

def mostrar_caracteristicas(ruta_archivo, datos):
    """Muestra la duración, resolución y bitrates en consola."""
    print("\n--- Características del Archivo de Salida ---")
    if datos and datos['duracion'] is not None:
        duracion_segundos = datos['duracion']
        horas = int(duracion_segundos // 3600)
        minutos = int((duracion_segundos % 3600) // 60)
        segundos = duracion_segundos % 60
        duracion_formateada = f"{horas:02d}:{minutos:02d}:{segundos:.2f}"
        
        print(f"🕒 Duración total: {duracion_formateada} ({duracion_segundos:.2f} segundos)")
        print(f"🖼️  Resolución de Video: {datos['resolucion']}")
        print(f"📊 Bitrate de Video: {datos['bitrate_video']}")
        print(f"🔊 Bitrate de Audio: {datos['bitrate_audio']}")
        print("\n*Nota: Los bitrates son **estimados** a partir del log general de ffmpeg.")
    else:
        print(f"❌ No se pudieron obtener las características del archivo: {ruta_archivo}")

# --- Funciones de las Opciones del Menú (Abreviadas por espacio) ---

def opcion_convertir_directorio(directorio_entrada, directorio_salida, detallado):
    """[Funcionalidad de la Opción 1 - Procesar todos los archivos en directorio]"""
    # ... (El código de la Opción 1 es extenso, se mantiene como estaba) ...
    formatos_soportados = (".ts", ".flv", ".mkv", ".avi", ".mov", ".wmv", ".mp4")
    
    if not os.path.isdir(directorio_entrada):
        print(f"❌ Error: El directorio de entrada '{directorio_entrada}' no existe.")
        logger.error(f"Directorio no encontrado: {directorio_entrada}")
        return

    os.makedirs(directorio_salida, exist_ok=True)
    
    for nombre_archivo in os.listdir(directorio_entrada):
        if nombre_archivo.lower().endswith(formatos_soportados):
            archivo_entrada = os.path.join(directorio_entrada, nombre_archivo)
            nombre_base = os.path.splitext(nombre_archivo)[0]
            archivo_salida_base = os.path.join(directorio_salida, f"{nombre_base}.mp4")

            archivo_salida = archivo_salida_base
            contador = 1
            while os.path.exists(archivo_salida):
                archivo_salida = os.path.join(directorio_salida, f"{nombre_base}_conv_{contador}.mp4")
                contador += 1

            convertir_video_simple(archivo_entrada, archivo_salida)

            datos_analisis = analizar_con_ffmpeg(archivo_salida)
            mostrar_caracteristicas(archivo_salida, datos_analisis)

def convertir_video_simple(archivo_entrada, archivo_salida):
    """Convierte un archivo de video a MP4."""
    comando = [
        'ffmpeg',
        '-y',
        '-i', archivo_entrada,
        '-c:v', 'copy',
        '-c:a', 'aac',
        '-strict', 'experimental',
        archivo_salida
    ]
    
    logger.info(f"Iniciando conversión: {archivo_entrada} -> {archivo_salida}")
    print(f"\n⚙️ Iniciando conversión: {archivo_entrada}...")
    
    try:
        subprocess.run(comando, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        logger.info(f"✅ Convertido exitosamente: {archivo_salida}")
        print(f"✅ Video convertido exitosamente: {archivo_salida}")
    except subprocess.CalledProcessError as e:
        error_msg = e.stderr.decode('utf-8', errors='ignore')
        logger.error(f"❌ Error al convertir {archivo_entrada}:\n{error_msg}")
        print(f"❌ Error al convertir el video. Revisa el archivo de log para más detalles.")
    except Exception as e:
        logger.error(f"❌ Error inesperado: {e}")


def opcion_descargar_m3u8(url_m3u8, directorio_salida, detallado):
    """[Funcionalidad de la Opción 2 - Descargar M3U8]"""
    # ... (El código de la Opción 2 es extenso, se mantiene como estaba) ...
    os.makedirs(directorio_salida, exist_ok=True)
    archivo_salida = os.path.join(directorio_salida, "video_descargado.mp4")
    
    contador = 1
    while os.path.exists(archivo_salida):
        archivo_salida = os.path.join(directorio_salida, f"video_descargado_{contador}.mp4")
        contador += 1
        
    comando = [
        'ffmpeg',
        '-i', url_m3u8,
        '-c', 'copy',
        archivo_salida
    ]
    
    logger.info(f"Iniciando descarga M3U8: {url_m3u8} -> {archivo_salida}")
    print(f"\n🌍 Iniciando descarga desde M3U8 a: {archivo_salida}")
    
    try:
        subprocess.run(comando, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        logger.info(f"✅ Descargado exitosamente: {archivo_salida}")
        print(f"✅ Video descargado exitosamente: {archivo_salida}")
        
        datos_analisis = analizar_con_ffmpeg(archivo_salida)
        mostrar_caracteristicas(archivo_salida, datos_analisis)

    except subprocess.CalledProcessError as e:
        error_msg = e.stderr.decode('utf-8', errors='ignore')
        logger.error(f"❌ Error al descargar desde M3U8:\n{error_msg}")
        print(f"❌ Error al descargar el video. Revisa el archivo de log para más detalles.")

def validar_archivos_union(video, audio):
    """Valida la existencia de los dos archivos de entrada para la unión."""
    if not os.path.isfile(video):
        return f"❌ Error: El archivo de video '{video}' no se encuentra."
    if not os.path.isfile(audio):
        return f"❌ Error: El archivo de audio '{audio}' no se encuentra."
    return None

def opcion_unir_audio_video():
    """Opción 3: Combina un archivo de video y uno de audio en un solo MP4."""
    print("\n--- Unir Streams de Video y Audio (.ts a .mp4) ---")
    
    # --- Consulta con Valores por Defecto ---
    ruta_video = input(f"Ingrese la ruta del video (Default: {DEFAULT_VIDEO_INPUT}): ").strip() or DEFAULT_VIDEO_INPUT
    ruta_audio = input(f"Ingrese la ruta del audio (Default: {DEFAULT_AUDIO_INPUT}): ").strip() or DEFAULT_AUDIO_INPUT
    ruta_salida_base = input(f"Ingrese el archivo de salida (Default: {DEFAULT_OUTPUT}): ").strip() or DEFAULT_OUTPUT
    
    # 1. Validación de entradas
    error_validacion = validar_archivos_union(ruta_video, ruta_audio)
    if error_validacion:
        print(error_validacion)
        logger.error(error_validacion)
        return
        
    # 2. Manejo de nombre de salida
    if not ruta_salida_base.lower().endswith(".mp4"):
        ruta_salida_base += ".mp4"
        
    # Crear el directorio por defecto si no existe y si se usa la ruta por defecto
    if ruta_salida_base.startswith(DEFAULT_DIR) and not os.path.isdir(DEFAULT_DIR):
        os.makedirs(DEFAULT_DIR, exist_ok=True)
    
    ruta_salida = ruta_salida_base
    
    # Si ya existe, añadir un sufijo para no sobreescribir
    nombre_base, extension = os.path.splitext(ruta_salida)
    contador = 1
    # Bucle para encontrar un nombre de archivo único
    while os.path.exists(ruta_salida):
        # La ruta de salida se reconstruye para incluir el sufijo
        ruta_salida = f"{nombre_base.split('_unido')[0]}_unido_{contador}{extension}" 
        contador += 1
    
    # 3. Ejecutar ffmpeg
    comando_ffmpeg = [
        "ffmpeg",
        "-y",
        "-i", ruta_video,
        "-i", ruta_audio,
        "-c:v", "copy",
        "-c:a", "aac",
        "-map", "0:v:0",
        "-map", "1:a:0",
        "-shortest",
        ruta_salida
    ]

    logger.info(f"Iniciando unión: {ruta_video} + {ruta_audio} -> {ruta_salida}")
    print("\n🛠️ Ejecutando comando ffmpeg...")
    print(f"Comando: {' '.join(comando_ffmpeg)}")

    try:
        subprocess.run(
            comando_ffmpeg,
            check=True,
            capture_output=True,
            text=True
        )
        print(f"\n🎉 ¡Éxito! El archivo se ha generado correctamente en: '{ruta_salida}'")
        logger.info(f"✅ Unión exitosa: {ruta_salida}")
        
        # 4. Análisis y características del archivo de salida
        datos_analisis = analizar_con_ffmpeg(ruta_salida)
        mostrar_caracteristicas(ruta_salida, datos_analisis)

    except subprocess.CalledProcessError as e:
        error_msg = e.stderr
        logger.error(f"❌ Error al unir archivos:\n{error_msg}")
        print(f"❌ Ocurrió un error durante la ejecución de ffmpeg. Revisa el log.")
    except Exception as e:
        logger.error(f"❌ Error inesperado en la unión: {e}")
        print("❌ Error inesperado. Revisa el log.")

# --- Menú Principal ---

def menu_principal():
    """Menú principal interactivo en español."""
    print("\n=============================================")
    print("      🎥 HERRAMIENTA MULTI-USO DE FFmpeg      ")
    print("=============================================")
    print("1. Convertir videos desde un directorio a MP4")
    print("2. Descargar video desde una URL M3U8")
    print("3. Unir Video (.ts) y Audio (.ts) en un MP4")
    print("4. Salir")
    print("---------------------------------------------")
    opcion = input("Seleccione una opción (1/2/3/4): ").strip()
    print("---------------------------------------------")

    # Pedir configuración de log una sola vez
    detallado = input("¿Activar modo detallado para el log? (s/n): ").strip().lower() == 's'
    configurar_log(detallado)

    if opcion == '1':
        directorio_entrada = input("📁 Ingrese el directorio de entrada: ").strip()
        directorio_salida = input("📂 Ingrese el directorio de salida (deje en blanco para usar el directorio actual): ").strip() or os.getcwd()
        opcion_convertir_directorio(directorio_entrada, directorio_salida, detallado)
    elif opcion == '2':
        url_m3u8 = input("🔗 Ingrese la URL del archivo M3U8: ").strip()
        directorio_salida = input("📂 Ingrese el directorio de salida (deje en blanco para usar el directorio actual): ").strip() or os.getcwd()
        opcion_descargar_m3u8(url_m3u8, directorio_salida, detallado)
    elif opcion == '3':
        opcion_unir_audio_video()
    elif opcion == '4':
        print("👋 Saliendo de la herramienta. ¡Hasta pronto!")
        sys.exit(0)
    else:
        print("Opción inválida. Intente nuevamente.")

if __name__ == '__main__':
    # 0. Validar si ffmpeg está instalado una sola vez al inicio
    validar_ffmpeg()
    
    # Bucle principal del menú
    while True:
        menu_principal()
        # Preguntar si el usuario quiere realizar otra operación
        continuar = input("\n¿Desea realizar otra operación? (s/n): ").strip().lower()
        if continuar != 's':
            print("👋 Saliendo de la herramienta. ¡Hasta pronto!")
            break