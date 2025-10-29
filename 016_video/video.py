#!/usr/bin/env python

description = 'Herramienta de uso de ffmpeg para bajar o convertir a mp4, o unir video/audio.'
author = 'Apuromafo'
version = '0.0.5-kb-fixed' # Versión actualizada: Incluye extracción de audio.
date = '30.10.2025' # Fecha actualizada

import logging
import os
import subprocess
from datetime import datetime
import sys
import shutil
import re 
import signal 

# --- Configuración por Defecto para la Opción 3 ---
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
    
    if logger.handlers:
        logger.handlers.clear()
        
    if detallado:
        nivel_log = logging.DEBUG
    else:
        nivel_log = logging.INFO
        
    logger.setLevel(nivel_log)
    
    # Manejador de consola (StreamHandler)
    manejador_consola = logging.StreamHandler(sys.stdout)
    manejador_consola.setFormatter(logging.Formatter(formato_mensaje, datefmt=formato_fecha))
    manejador_consola.setLevel(nivel_log)
    logger.addHandler(manejador_consola)
    
    # Manejador de archivo (FileHandler) - ¡CORRECCIÓN: Añadir encoding='utf-8'!
    # Esto soluciona el UnicodeEncodeError al usar el emoji '✅'
    manejador_archivo = logging.FileHandler("errores_ffmpeg.log", encoding='utf-8')
    manejador_archivo.setLevel(logging.DEBUG) 
    formatter = logging.Formatter(formato_mensaje, datefmt=formato_fecha)
    manejador_archivo.setFormatter(formatter)
    logger.addHandler(manejador_archivo)
    
    logger.info("Configuración de log aplicada. Detallado: %s", detallado)

def validar_ffmpeg():
    """Valida si ffmpeg está instalado en el sistema."""
    if shutil.which("ffmpeg") is None:
        print("❌ Error: ffmpeg no está instalado en su sistema.")
        sys.exit(1)
    else:
        print("✅ ffmpeg está instalado correctamente.")

# --- Funciones de Análisis de Metadatos ---

def analizar_con_ffmpeg(ruta_archivo):
    """
    Usa ffmpeg en modo "solo lectura" y expresiones regulares para extraer
    la duración, resolución y bitrate estimado del archivo analizando su log.
    """
    if not os.path.exists(ruta_archivo):
        logger.error(f"El archivo para analizar no existe: {ruta_archivo}")
        return None
        
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
            
            br_video_mbps = int(br_kbps) / 1000
            caracteristicas['bitrate_video'] = f"{br_video_mbps:.2f} Mbps (Estimado)"
            
            caracteristicas['bitrate_audio'] = "Aprox. 128-192 Kbps (AAC predeterminado)"
            
    except Exception as e:
        logger.error(f"Error al analizar el log de ffmpeg: {e}")
        return None

    return caracteristicas

def mostrar_caracteristicas(ruta_archivo, datos, modo_union_simple=False):
    """Muestra la duración, resolución y bitrates en consola con un indicador del origen del audio."""
    if datos is None:
        print(f"❌ No se pudieron obtener las características del archivo: {ruta_archivo}")
        return
        
    print("\n--- Características del Archivo de Salida ---")
    if datos['duracion'] is not None:
        duracion_segundos = datos['duracion']
        horas = int(duracion_segundos // 3600)
        minutos = int((duracion_segundos % 3600) // 60)
        segundos = duracion_segundos % 60
        duracion_formateada = f"{horas:02d}:{minutos:02d}:{segundos:.2f}"
        
        print(f"🕒 Duración total: {duracion_formateada} ({duracion_segundos:.2f} segundos)")
        print(f"🖼️  Resolución de Video: {datos['resolucion']}")
        print(f"📊 Bitrate de Video: {datos['bitrate_video']}")
        
        if modo_union_simple:
            print(f"🔊 Bitrate de Audio: {datos['bitrate_audio']} (El audio fue copiado/extraído de la fuente única).")
        else:
            print(f"🔊 Bitrate de Audio: {datos['bitrate_audio']} (El audio fue extraído de 'audio.ts' y recodificado).")

        print("\n*Nota: Los bitrates son **estimados** a partir del log general de ffmpeg.")
    else:
        print(f"❌ No se pudieron obtener las características del archivo: {ruta_archivo}")

# --- Funciones de las Opciones del Menú (Core) ---

def convertir_video_simple(archivo_entrada, archivo_salida):
    """
    Convierte un archivo de video a MP4.
    Retorna True si tiene éxito, False si falla.
    """
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
        return True # Éxito
    
    except subprocess.CalledProcessError as e:
        error_msg = e.stderr.decode('utf-8', errors='ignore')
        logger.error(f"❌ Error al convertir {archivo_entrada}:\n{error_msg}")
        print(f"❌ Error al convertir el video. Revisa el archivo de log para más detalles.")
        return False # Fallo

    except KeyboardInterrupt: # <-- Manejo de interrupción (Ctrl+C)
        logger.warning("🛑 Interrupción manual (Ctrl+C) detectada durante la conversión.")
        print("\n🛑 Proceso cancelado por el usuario (Ctrl+C).")
        if os.path.exists(archivo_salida):
             os.remove(archivo_salida)
             print(f"🧹 Archivo incompleto '{archivo_salida}' eliminado.")
        return False # Fallo / Cancelación

    except Exception as e:
        logger.error(f"❌ Error inesperado: {e}")
        print("❌ Error inesperado. Revisa el log.")
        return False # Fallo


def opcion_convertir_directorio(directorio_entrada, directorio_salida, detallado):
    """[Funcionalidad de la Opción 1 - Procesar todos los archivos en directorio]"""
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

            if convertir_video_simple(archivo_entrada, archivo_salida):
                datos_analisis = analizar_con_ffmpeg(archivo_salida)
                mostrar_caracteristicas(archivo_salida, datos_analisis, modo_union_simple=True) 
            else:
                logger.warning(f"Se omitirá el análisis de metadatos para {archivo_entrada} debido a un error de conversión o cancelación.")


def opcion_descargar_m3u8(url_m3u8, directorio_salida, detallado):
    """
    [Funcionalidad de la Opción 2 - Descargar M3U8]
    Retorna True si tiene éxito, False si falla.
    """
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
        mostrar_caracteristicas(archivo_salida, datos_analisis, modo_union_simple=True)
        return True # Éxito

    except subprocess.CalledProcessError as e:
        error_msg = e.stderr.decode('utf-8', errors='ignore')
        logger.error(f"❌ Error al descargar desde M3U8:\n{error_msg}")
        print(f"❌ Error al descargar el video. Revisa el archivo de log para más detalles.")
        return False # Fallo

    except KeyboardInterrupt: # <-- Manejo de interrupción (Ctrl+C)
        logger.warning("🛑 Interrupción manual (Ctrl+C) detectada durante la descarga.")
        print("\n🛑 Proceso cancelado por el usuario (Ctrl+C).")
        if os.path.exists(archivo_salida):
             os.remove(archivo_salida)
             print(f"🧹 Archivo incompleto '{archivo_salida}' eliminado.")
        return False # Fallo / Cancelación


def validar_o_preguntar_archivos_union(ruta_video, ruta_audio):
    """
    Valida la existencia del video y pregunta al usuario si desea continuar si falta el audio.
    """
    # 1. Validar Video
    if not os.path.isfile(ruta_video):
        print(f"❌ Error: El archivo de video '{ruta_video}' no se encuentra.")
        logger.error(f"Video no encontrado: {ruta_video}")
        return None, None, None 
    
    # 2. Validar Audio y Preguntar
    usar_solo_video_como_input = False
    
    if not os.path.isfile(ruta_audio):
        print(f"⚠️ Advertencia: El archivo de audio '{ruta_audio}' no se encuentra.")
        logger.warning(f"Audio no encontrado: {ruta_audio}")
        
        while True:
            try:
                respuesta = input("¿Desea procesar el video usando SOLAMENTE el audio/video que contiene 'video.ts' (s/n)?: ").strip().lower()
                if not respuesta:
                     raise ValueError
            except (EOFError, KeyboardInterrupt, ValueError):
                print("\n🛑 Proceso detenido por interrupción o entrada no válida.")
                return None, None, None
                
            if respuesta == 's':
                usar_solo_video_como_input = True
                print("✅ Se continuará procesando usando 'video.ts' como fuente única.")
                ruta_audio = None
                break
            elif respuesta == 'n':
                print("🛑 Proceso detenido por solicitud del usuario.")
                return None, None, None
            else:
                print("Respuesta no válida. Por favor, ingrese 's' para sí o 'n' para no.")
    else:
        print("✅ Archivos de entrada validados correctamente. Se procederá a unirlos.")
        
    return ruta_video, ruta_audio, usar_solo_video_como_input


def ejecutar_union_ffmpeg(ruta_video, ruta_audio, ruta_salida, usar_solo_video_como_input):
    """
    Construye y ejecuta el comando ffmpeg, adaptándose a si se usa un solo input o dos.
    Retorna True si la ejecución fue exitosa, False si falla.
    """
    comando_ffmpeg = ["ffmpeg", "-y"]

    if usar_solo_video_como_input:
        comando_ffmpeg.extend(["-i", ruta_video])
        comando_ffmpeg.extend(["-c", "copy"])
        comando_ffmpeg.extend(["-map", "0"]) 
        logger.info(f"Modo: Procesando {ruta_video} como fuente única (-c copy, -map 0).")
        print("\n🛠️ Modo: Procesando 'video.ts' como ÚNICA fuente (se intenta usar su audio interno)...")
    else:
        comando_ffmpeg.extend(["-i", ruta_video])
        comando_ffmpeg.extend(["-i", ruta_audio])
        comando_ffmpeg.extend(["-c:v", "copy", "-c:a", "aac"])
        comando_ffmpeg.extend(["-map", "0:v:0", "-map", "1:a:0"])
        comando_ffmpeg.append("-shortest")
        logger.info(f"Modo: Mezclando {ruta_video} y {ruta_audio} (-c:v copy, -c:a aac, -map 0:v:0, -map 1:a:0, -shortest).")
        print("\n🛠️ Modo: Procesando y MEZCLANDO 'video.ts' y 'audio.ts'...")
        
    comando_ffmpeg.append(ruta_salida)

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
        return True

    except subprocess.CalledProcessError as e:
        error_msg = e.stderr
        logger.error(f"❌ Error al unir archivos:\n{error_msg}")
        print(f"❌ Ocurrió un error durante la ejecución de ffmpeg. Revisa el log.")
        return False

    except KeyboardInterrupt: # <-- Manejo de interrupción (Ctrl+C)
        logger.warning("🛑 Interrupción manual (Ctrl+C) detectada durante la ejecución de ffmpeg.")
        print("\n🛑 Proceso cancelado por el usuario (Ctrl+C).")
        if os.path.exists(ruta_salida):
             os.remove(ruta_salida)
             print(f"🧹 Archivo incompleto '{ruta_salida}' eliminado.")
        return False

    except Exception as e:
        logger.error(f"❌ Error inesperado en la unión: {e}")
        print("❌ Error inesperado. Revisa el log.")
        return False


def opcion_unir_audio_video():
    """Opción 3: Combina un archivo de video y uno de audio en un solo MP4, con manejo de ausencia de audio."""
    print("\n--- Unir Streams de Video y Audio (.ts a .mp4) ---")
    
    try:
        ruta_video = input(f"Ingrese la ruta del video (Default: {DEFAULT_VIDEO_INPUT}): ").strip() or DEFAULT_VIDEO_INPUT
        ruta_audio = input(f"Ingrese la ruta del audio (Default: {DEFAULT_AUDIO_INPUT}): ").strip() or DEFAULT_AUDIO_INPUT
        ruta_salida_base = input(f"Ingrese el archivo de salida (Default: {DEFAULT_OUTPUT}): ").strip() or DEFAULT_OUTPUT
    except (EOFError, KeyboardInterrupt):
        print("\n🛑 Proceso detenido por interrupción del usuario.")
        return
        
    # 1. Validación de entradas y manejo de la ausencia de audio
    ruta_video, ruta_audio, usar_solo_video_como_input = validar_o_preguntar_archivos_union(ruta_video, ruta_audio)
    
    if ruta_video is None:
        return
        
    # 2. Manejo de nombre de salida
    if not ruta_salida_base.lower().endswith(".mp4"):
        ruta_salida_base += ".mp4"
        
    if ruta_salida_base.startswith(DEFAULT_DIR) and not os.path.isdir(DEFAULT_DIR):
        os.makedirs(DEFAULT_DIR, exist_ok=True)
        
    ruta_salida = ruta_salida_base
    
    nombre_base, extension = os.path.splitext(ruta_salida)
    contador = 1
    while os.path.exists(ruta_salida):
        base_sin_sufijo = nombre_base.split('_unido')[0]
        ruta_salida = f"{base_sin_sufijo}_unido_{contador}{extension}" 
        contador += 1
    
    # 3. Ejecutar ffmpeg
    if ejecutar_union_ffmpeg(ruta_video, ruta_audio, ruta_salida, usar_solo_video_como_input):
        # 4. Análisis y características del archivo de salida
        datos_analisis = analizar_con_ffmpeg(ruta_salida)
        mostrar_caracteristicas(ruta_salida, datos_analisis, modo_union_simple=usar_solo_video_como_input)

# --- NUEVA OPCIÓN 4: Extraer Audio ---

def opcion_extraer_audio():
    """Opción 4: Extrae el audio de un video y lo guarda en formato MP3."""
    print("\n--- Extraer Audio de Video a MP3 ---")
    
    try:
        archivo_entrada = input("🎬 Ingrese la ruta del archivo de video (ej: video.mp4): ").strip()
        if not os.path.isfile(archivo_entrada):
            print(f"❌ Error: El archivo de entrada '{archivo_entrada}' no existe.")
            logger.error(f"Archivo de entrada no encontrado para extracción de audio: {archivo_entrada}")
            return
            
        directorio_salida = input("📂 Ingrese el directorio de salida (deje en blanco para usar el directorio actual): ").strip() or os.getcwd()
    except (EOFError, KeyboardInterrupt):
        print("\n🛑 Proceso detenido por interrupción del usuario.")
        return
    
    os.makedirs(directorio_salida, exist_ok=True)
    
    # Generar nombre de salida basado en el nombre del archivo de entrada
    nombre_base = os.path.splitext(os.path.basename(archivo_entrada))[0]
    ruta_salida_base = os.path.join(directorio_salida, f"{nombre_base}.mp3")
    
    # Manejar si el archivo de salida ya existe
    ruta_salida = ruta_salida_base
    contador = 1
    while os.path.exists(ruta_salida):
        ruta_salida = os.path.join(directorio_salida, f"{nombre_base}_audio_{contador}.mp3")
        contador += 1
        
    # Comando FFmpeg para extraer y recodificar a MP3 (libmp3lame para MP3 de alta calidad)
    comando = [
        'ffmpeg',
        '-y',
        '-i', archivo_entrada,
        '-vn',             # Deshabilitar el stream de video
        '-c:a', 'libmp3lame', # Usar codec MP3 
        '-q:a', '2',        # Calidad VBR media/alta para MP3 (0 es la mejor, 9 es la peor)
        ruta_salida
    ]
    
    logger.info(f"Iniciando extracción de audio: {archivo_entrada} -> {ruta_salida}")
    print(f"\n🎵 Iniciando extracción de audio a: {ruta_salida}...")

    try:
        # Se usa stdout/stderr=subprocess.PIPE para no inundar la consola si no se usa el modo detallado.
        subprocess.run(comando, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        logger.info(f"✅ Audio extraído exitosamente: {ruta_salida}")
        print(f"✅ Audio extraído exitosamente: {ruta_salida}")
        print(f"\n🎉 ¡Éxito! El archivo de audio MP3 se ha generado correctamente en: '{ruta_salida}'")
        
    except subprocess.CalledProcessError as e:
        error_msg = e.stderr.decode('utf-8', errors='ignore')
        logger.error(f"❌ Error al extraer audio de {archivo_entrada}:\n{error_msg}")
        print(f"❌ Error al extraer el audio. Revisa el archivo de log para más detalles.")

    except KeyboardInterrupt:
        logger.warning("🛑 Interrupción manual (Ctrl+C) detectada durante la extracción de audio.")
        print("\n🛑 Proceso cancelado por el usuario (Ctrl+C).")
        if os.path.exists(ruta_salida):
             os.remove(ruta_salida)
             print(f"🧹 Archivo incompleto '{ruta_salida}' eliminado.")

    except Exception as e:
        logger.error(f"❌ Error inesperado durante la extracción de audio: {e}")
        print("❌ Error inesperado. Revisa el log.")


# --- Menú Principal ---

def menu_principal():
    """Menú principal interactivo en español."""
    print("\n=============================================")
    print("      🎥 HERRAMIENTA MULTI-USO DE FFmpeg       ")
    print(f"         Versión: {version} ({date})")
    print("=============================================")
    print("1. Convertir videos desde un directorio a MP4")
    print("2. Descargar video desde una URL M3U8")
    print("3. Unir Video (.ts) y Audio (.ts) en un MP4")
    print("4. Extraer Audio de Video a MP3") # ¡NUEVA OPCIÓN 4!
    print("5. Salir") # ¡NUEVA OPCIÓN 5!
    print("---------------------------------------------")

    try:
        opcion = input("Seleccione una opción (1/2/3/4/5): ").strip()
        print("---------------------------------------------")

        detallado = input("¿Activar modo detallado para el log? (s/n): ").strip().lower() == 's'
        configurar_log(detallado)
    except (EOFError, KeyboardInterrupt):
        print("\n🛑 Saliendo de la herramienta por interrupción.")
        sys.exit(0)
    
    try:
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
        elif opcion == '4': # Lógica para la nueva Opción 4
            opcion_extraer_audio()
        elif opcion == '5': # Lógica para la nueva Opción 5 (Salir)
            print("👋 Saliendo de la herramienta. ¡Hasta pronto!")
            sys.exit(0)
        else:
            print("Opción inválida. Intente nuevamente.")
    except (EOFError, KeyboardInterrupt):
        logger.error("Interrupción en el input de la opción, volviendo al menú.")
        print("\n🛑 Operación cancelada, volviendo al menú principal.")


if __name__ == '__main__':
    # 0. Validar si ffmpeg está instalado una sola vez al inicio
    validar_ffmpeg()
    
    # Bucle principal del menú
    while True:
        menu_principal()
        try:
            continuar = input("\n¿Desea realizar otra operación? (s/n): ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            continuar = 'n'
            
        if continuar != 's':
            print("👋 Saliendo de la herramienta. ¡Hasta pronto!")
            break