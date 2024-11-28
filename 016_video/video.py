import logging
import os
import click
import subprocess
from datetime import datetime
import time

# Logger
logger = logging.getLogger("video_converter")

def setuplog(verbose):
    """Configura la salida del log para video_converter."""
    log_msg_format = '%(asctime)s :: %(levelname)5s ::  %(name)10s :: %(message)s'
    log_date_format = '%Y-%m-%d %H:%M:%S'
    logging.basicConfig(format=log_msg_format, datefmt=log_date_format)
    
    # Ajustar el nivel de logging según el modo verbose
    if verbose:
        logger.setLevel(logging.DEBUG)  # Muestra DEBUG y superiores
    else:
        logger.setLevel(logging.INFO)  # Muestra solo INFO y superiores

    # Configurar el manejo de archivos de log
    file_handler = logging.FileHandler("conversion_errors.log")
    file_handler.setLevel(logging.DEBUG)  # Registrar todos los mensajes en el archivo
    logger.addHandler(file_handler)

@click.command()
@click.option('-f', '--input_dir', required=True, type=click.Path(exists=True),
              help="Directorio que contiene archivos de video de entrada.")
@click.option('-o', '--output_dir', default=None, type=click.Path(),
              help='Directorio donde se guardarán los archivos de salida. Si no se especifica, se guardará en la misma ruta de entrada.')
@click.option('--verbose', is_flag=True, help="Activar el logging detallado.")
def convert_videos(input_dir, output_dir, verbose):
    """Convierte todos los archivos de video en un directorio a MP4."""
    
    setuplog(verbose)

    # Determinar el directorio de salida
    if output_dir is None:
        output_dir = input_dir

    # Lista de formatos soportados
    SUPPORTED_FORMATS = (".ts", ".flv", ".mkv", ".avi", ".mov", ".wmv", ".mp4")

    # Iniciar temporizador
    start_time = time.time()

    # Procesar cada archivo en el directorio de entrada
    for videofname in os.listdir(input_dir):
        if videofname.lower().endswith(SUPPORTED_FORMATS):
            input_file = os.path.join(input_dir, videofname)
            base_name = os.path.splitext(videofname)[0]
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = os.path.join(output_dir, f"{base_name}_converted_{timestamp}.mp4")

            # Comprobar si el archivo de salida ya existe
            if os.path.exists(output_file):
                # Preguntar al usuario si desea continuar con otro nombre
                respuesta = input(f"El archivo {output_file} ya existe. ¿Desea continuar con un nuevo nombre? (s/n): ").strip().lower()
                if respuesta != 's':
                    logger.info(f"Conversión cancelada para: {output_file}. Finalizando el script.")
                    print(f"Conversión cancelada para: {output_file}. Finalizando el script.")
                    return  # Detener la ejecución del script

            # Usar ffmpeg directamente
            command = [
                'ffmpeg',
                '-i', input_file,  # Archivo de entrada
                '-c:v', 'copy',  # Copiar video sin recodificación
                '-c:a', 'aac',  # Codificar audio en AAC
                '-strict', 'experimental',  # Permitir el uso de codecs experimentales
                output_file  # Archivo de salida
            ]

            try:
                # Redirigir stderr a devnull para suprimir las advertencias en la consola
                with open(os.devnull, 'w') as devnull:
                    subprocess.run(command, stderr=devnull, check=True)
                logger.info(f"Convertido: {output_file}")
                print(f"Convertido: {output_file}")  # Mensaje en consola
            except subprocess.CalledProcessError as e:
                logger.error(f"Error al convertir {input_file}: {e}")
                print(f"Error al convertir {input_file}. Revisa el log para más detalles.")

    # Calcular el tiempo transcurrido
    elapsed_time = time.time() - start_time
    print(f"Proceso de conversión finalizado. Tiempo transcurrido: {elapsed_time:.2f} segundos.")

if __name__ == '__main__':
    convert_videos()