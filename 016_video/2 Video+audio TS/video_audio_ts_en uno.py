import subprocess
import os
import sys
import re

# --- Configuración (Constantes) ---
DIRECTORIO_TRABAJO = "Video"
ARCHIVO_VIDEO_ENTRADA = "video.ts"
ARCHIVO_AUDIO_ENTRADA = "audio.ts"
ARCHIVO_SALIDA = "video_ok.mp4"
# -----------------------------------

def validar_archivos(directorio, ruta_video, ruta_audio):
    """
    Valida la existencia del directorio de trabajo y de los archivos de entrada.
    Pregunta si se desea continuar si falta audio.ts.

    :return: Una tupla (ruta_video, ruta_audio, usar_solo_video_como_input)
    """
    if not os.path.isdir(directorio):
        print(f"❌ Error: El directorio '{directorio}' no existe.")
        sys.exit(1)

    if not os.path.isfile(ruta_video):
        print(f"❌ Error: El archivo de video '{ruta_video}' no se encuentra.")
        sys.exit(1)
    
    # Por defecto, asumimos que usaremos la mezcla de dos archivos (video.ts y audio.ts)
    usar_solo_video_como_input = False
    
    if not os.path.isfile(ruta_audio):
        print(f"⚠️ Advertencia: El archivo de audio '{ruta_audio}' no se encuentra.")
        
        while True:
            # Pregunta si desea continuar usando SOLO el video.ts como fuente
            respuesta = input("¿Desea procesar el video usando SOLAMENTE el audio/video que contiene 'video.ts'? (s/n): ").strip().lower()
            if respuesta == 's':
                usar_solo_video_como_input = True
                print("✅ Se continuará procesando usando 'video.ts' como fuente única.")
                # Establecemos ruta_audio a None, ya que no se usará
                ruta_audio = None 
                break
            elif respuesta == 'n':
                print("🛑 Proceso detenido por solicitud del usuario.")
                sys.exit(0)
            else:
                print("Respuesta no válida. Por favor, ingrese 's' para sí o 'n' para no.")
    else:
        print("✅ Archivos de entrada y directorio validados correctamente.")

    return ruta_video, ruta_audio, usar_solo_video_como_input

# --- Función clave para el análisis sin ffprobe (Se mantiene igual) ---
# Se omite por brevedad, pero debe incluir tu código original de 'analizar_con_ffmpeg'.
# ... (Tu función 'analizar_con_ffmpeg' va aquí) ...

def analizar_con_ffmpeg(ruta_archivo):
    # Función de análisis (la dejé aquí para que el script funcione, aunque la omití arriba)
    comando_analisis = ["ffmpeg", "-i", ruta_archivo, "-f", "null", "-"]
    caracteristicas = {'duracion': None, 'resolucion': "N/A", 'bitrate_video': "N/A", 'bitrate_audio': "N/A"}
    try:
        resultado = subprocess.run(comando_analisis, check=False, capture_output=True, text=True)
        log_text = resultado.stderr
        match_duracion = re.search(r"Duration: (\d{2}):(\d{2}):(\d{2}\.\d{2})", log_text)
        if match_duracion:
            horas, minutos = int(match_duracion.group(1)), int(match_duracion.group(2))
            segundos = float(match_duracion.group(3))
            caracteristicas['duracion'] = horas * 3600 + minutos * 60 + segundos
        match_resolucion = re.search(r"Video:.*?(\d{3,4}x\d{3,4})", log_text)
        if match_resolucion:
            caracteristicas['resolucion'] = match_resolucion.group(1)
        match_bitrate_global = re.search(r"bitrate: (\d+) kb/s", log_text)
        if match_bitrate_global:
            br_kbps = match_bitrate_global.group(1)
            br_video_mbps = int(br_kbps) / 1000
            caracteristicas['bitrate_video'] = f"{br_video_mbps:.2f} Mbps (Estimado)"
            caracteristicas['bitrate_audio'] = "Aprox. 128-192 Kbps (AAC predeterminado)"
    except FileNotFoundError:
        print("\n❌ Error: No se encontró el ejecutable 'ffmpeg' para el análisis.")
    except Exception as e:
        print(f"\n⚠️ Advertencia: Error al analizar el log de ffmpeg: {e}")
    return caracteristicas

# --- Función de Ejecución Modificada ---
def ejecutar_ffmpeg(ruta_video, ruta_audio, ruta_salida, usar_solo_video_como_input):
    """
    Construye y ejecuta el comando ffmpeg, adaptándose a si se usa un solo input (video.ts) o dos (video.ts + audio.ts).
    Retorna True si la ejecución fue exitosa.
    """
    comando_ffmpeg = ["ffmpeg", "-y"]

    if usar_solo_video_como_input:
        # 1. MODO: SOLO 'video.ts' (usa el audio interno)
        comando_ffmpeg.extend(["-i", ruta_video])
        
        # Copia todos los streams (video, audio, subtítulos) del input 0
        comando_ffmpeg.extend(["-c", "copy"]) 
        comando_ffmpeg.extend(["-map", "0"]) # Mapea todos los streams del input 0
        
        print("\n🛠️ Modo: Procesando 'video.ts' como ÚNICA fuente (se intenta usar su audio interno)...")
    else:
        # 2. MODO: MEZCLA DE 'video.ts' y 'audio.ts' (comportamiento original)
        comando_ffmpeg.extend(["-i", ruta_video])
        comando_ffmpeg.extend(["-i", ruta_audio])
        
        # Copia video del input 0, recodifica audio del input 1 a AAC
        comando_ffmpeg.extend(["-c:v", "copy", "-c:a", "aac"])
        comando_ffmpeg.extend(["-map", "0:v:0", "-map", "1:a:0"])
        comando_ffmpeg.append("-shortest")
        
        print("\n🛠️ Modo: Procesando y MEZCLANDO 'video.ts' y 'audio.ts'...")
        
    # 3. Salida
    comando_ffmpeg.append(ruta_salida)

    print(f"Comando: {' '.join(comando_ffmpeg)}")

    try:
        subprocess.run(comando_ffmpeg, check=True, capture_output=True, text=True)
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
        return False 

# --- Ejecución Principal ---
def main():
    """Función principal del script."""
    ruta_video_completa = os.path.join(DIRECTORIO_TRABAJO, ARCHIVO_VIDEO_ENTRADA)
    ruta_audio_completa = os.path.join(DIRECTORIO_TRABAJO, ARCHIVO_AUDIO_ENTRADA)
    ruta_salida = os.path.join(DIRECTORIO_TRABAJO, ARCHIVO_SALIDA)

    # 1. Validar archivos (con la nueva lógica de consulta)
    ruta_video_final, ruta_audio_final, usar_solo_video_como_input = validar_archivos(
        DIRECTORIO_TRABAJO, ruta_video_completa, ruta_audio_completa
    )
    
    # 2. Ejecutar ffmpeg (Conversión)
    if ejecutar_ffmpeg(ruta_video_final, ruta_audio_final, ruta_salida, usar_solo_video_como_input):
        # 3. Obtener y mostrar las características del archivo de salida
        print("\n--- Características del Archivo de Salida ---")
        
        datos = analizar_con_ffmpeg(ruta_salida)

        if datos and datos['duracion'] is not None:
            duracion_segundos = datos['duracion']
            horas = int(duracion_segundos // 3600)
            minutos = int((duracion_segundos % 3600) // 60)
            segundos = duracion_segundos % 60
            duracion_formateada = f"{horas:02d}:{minutos:02d}:{segundos:.2f}"
            
            print(f"🕒 Duración total: {duracion_formateada} ({duracion_segundos:.2f} segundos)")
            print(f"🖼️  Resolución de Video: {datos['resolucion']}")
            print(f"📊 Bitrate de Video: {datos['bitrate_video']}")
            
            # Ajuste de mensaje según el modo de procesamiento
            if usar_solo_video_como_input:
                 print(f"🔊 Bitrate de Audio: {datos['bitrate_audio']} (El audio fue copiado de 'video.ts' junto con el video).")
            else:
                 print(f"🔊 Bitrate de Audio: {datos['bitrate_audio']} (El audio fue extraído de 'audio.ts' y recodificado).")

            print("\n*Nota: Los bitrates son **estimados** ya que se extrajeron del log general de ffmpeg.")
        else:
            print("❌ No se pudieron obtener las características del archivo de salida con el análisis de ffmpeg.")


if __name__ == "__main__":
    main()