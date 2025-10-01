import subprocess
import os
import sys
import re # Necesario para buscar patrones de texto en el log de ffmpeg

# --- Configuración (Constantes) ---
DIRECTORIO_TRABAJO = "Video"
ARCHIVO_VIDEO_ENTRADA = "video.ts"
ARCHIVO_AUDIO_ENTRADA = "audio.ts"
ARCHIVO_SALIDA = "video_ok.mp4"
# -----------------------------------

def validar_archivos(directorio, video, audio):
    """Valida la existencia del directorio de trabajo y de los archivos de entrada."""
    if not os.path.isdir(directorio):
        print(f"❌ Error: El directorio '{directorio}' no existe.")
        sys.exit(1)

    if not os.path.isfile(video):
        print(f"❌ Error: El archivo de video '{video}' no se encuentra.")
        sys.exit(1)

    if not os.path.isfile(audio):
        print(f"❌ Error: El archivo de audio '{audio}' no se encuentra.")
        sys.exit(1)

    print("✅ Archivos de entrada y directorio validados correctamente.")
    return True

# --- Función clave para el análisis sin ffprobe ---
def analizar_con_ffmpeg(ruta_archivo):
    """
    Usa ffmpeg en modo "solo lectura" y expresiones regulares para extraer
    la duración, resolución y bitrate estimado del archivo analizando su log.

    :param ruta_archivo: Ruta completa del archivo.
    :return: Un diccionario con las características o un diccionario vacío.
    """
    # Comando ffmpeg para generar el log de metadatos (en stderr)
    comando_analisis = [
        "ffmpeg",
        "-i", ruta_archivo, # Lee el archivo de salida
        "-f", "null",      # El formato de salida es "null" (no procesa nada)
        "-"                # La salida es el stream nulo
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
            check=False, # No forzamos error, ya que la salida nula genera un código de retorno no-cero
            capture_output=True,
            text=True
        )

        # La información de metadatos aparece en la salida de error (stderr)
        log_text = resultado.stderr

        # 1. Extracción de Duración (Duration)
        # Patrón: Duration: 00:02:48.00, start: 0.000000, bitrate: 785 kb/s
        match_duracion = re.search(r"Duration: (\d{2}):(\d{2}):(\d{2}\.\d{2})", log_text)
        if match_duracion:
            horas = int(match_duracion.group(1))
            minutos = int(match_duracion.group(2))
            segundos = float(match_duracion.group(3))
            duracion_segundos = horas * 3600 + minutos * 60 + segundos
            caracteristicas['duracion'] = duracion_segundos

        # 2. Extracción de Resolución (Resolution)
        # Patrón: Video: h264 (...), 1920x1080 [SAR 1:1 DAR 16:9], ...
        match_resolucion = re.search(r"Video:.*?(\d{3,4}x\d{3,4})", log_text)
        if match_resolucion:
            caracteristicas['resolucion'] = match_resolucion.group(1)

        # 3. Extracción de Bitrate Global
        # Patrón: bitrate: 785 kb/s
        match_bitrate_global = re.search(r"bitrate: (\d+) kb/s", log_text)
        if match_bitrate_global:
            br_kbps = match_bitrate_global.group(1)
            
            # Estimación del Bitrate de Video (el más grande, se muestra en Mbps)
            br_video_mbps = int(br_kbps) / 1000
            caracteristicas['bitrate_video'] = f"{br_video_mbps:.2f} Mbps (Estimado)"
            
            # Bitrate de Audio (se asume el valor predeterminado de AAC)
            caracteristicas['bitrate_audio'] = "Aprox. 128-192 Kbps (AAC predeterminado)"
            
    except FileNotFoundError:
        # Esto solo debería ocurrir si ffmpeg se pierde del PATH
        print("\n❌ Error: No se encontró el ejecutable 'ffmpeg' para el análisis.")
    except Exception as e:
        # Captura errores de regex o parsing inesperados
        print(f"\n⚠️ Advertencia: Error al analizar el log de ffmpeg: {e}")

    return caracteristicas

def ejecutar_ffmpeg(ruta_video, ruta_audio, ruta_salida):
    """
    Construye y ejecuta el comando ffmpeg para mezclar video y audio.
    Retorna True si la ejecución fue exitosa.
    """
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
        return True

    except FileNotFoundError:
        print("\n❌ Error: No se encontró el ejecutable 'ffmpeg'. Asegúrate de que esté en el PATH.")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print("\n❌ Ocurrió un error durante la ejecución de ffmpeg:")
        print("--- Salida de error de ffmpeg ---")
        print(e.stderr)
        print("---------------------------------")
        sys.exit(1)

# --- Ejecución Principal ---
def main():
    """Función principal del script."""
    ruta_video = os.path.join(DIRECTORIO_TRABAJO, ARCHIVO_VIDEO_ENTRADA)
    ruta_audio = os.path.join(DIRECTORIO_TRABAJO, ARCHIVO_AUDIO_ENTRADA)
    ruta_salida = os.path.join(DIRECTORIO_TRABAJO, ARCHIVO_SALIDA)

    # 1. Validar archivos
    validar_archivos(DIRECTORIO_TRABAJO, ruta_video, ruta_audio)

    # 2. Ejecutar ffmpeg (Conversión)
    if ejecutar_ffmpeg(ruta_video, ruta_audio, ruta_salida):
        # 3. Obtener y mostrar las características del archivo de salida
        print("\n--- Características del Archivo de Salida ---")
        
        datos = analizar_con_ffmpeg(ruta_salida)

        if datos and datos['duracion'] is not None:
            # Formateo de Duración
            duracion_segundos = datos['duracion']
            horas = int(duracion_segundos // 3600)
            minutos = int((duracion_segundos % 3600) // 60)
            segundos = duracion_segundos % 60
            duracion_formateada = f"{horas:02d}:{minutos:02d}:{segundos:.2f}"
            
            print(f"🕒 Duración total: {duracion_formateada} ({duracion_segundos:.2f} segundos)")
            print(f"🖼️  Resolución de Video: {datos['resolucion']}")
            print(f"📊 Bitrate de Video: {datos['bitrate_video']}")
            print(f"🔊 Bitrate de Audio: {datos['bitrate_audio']}")
            print("\n*Nota: Los bitrates son **estimados** ya que se extrajeron del log general de ffmpeg.")
        else:
            print("❌ No se pudieron obtener las características del archivo de salida con el análisis de ffmpeg.")


if __name__ == "__main__":
    main()