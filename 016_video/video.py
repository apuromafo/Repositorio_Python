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
    
    if verbose:
        logger.setLevel(logging.DEBUG)  # Muestra DEBUG y superiores
    else:
        logger.setLevel(logging.INFO)  # Muestra solo INFO y superiores

    file_handler = logging.FileHandler("conversion_errors.log")
    file_handler.setLevel(logging.DEBUG)
    logger.addHandler(file_handler)

@click.command()
@click.option('-f', '--input_dir', required=False, type=click.Path(exists=True),
              help="Directorio que contiene archivos de video de entrada.")
@click.option('-o', '--output_dir', default=None, type=click.Path(),
              help='Directorio donde se guardarán los archivos de salida.')
@click.option('-i', '--input_m3u8', required=False, type=str,
              help='URL del archivo M3U8 para descargar el video.')
@click.option('--verbose', is_flag=True, help="Activar el logging detallado.")
def convert_videos(input_dir, output_dir, input_m3u8, verbose):
    """Convierte archivos de video y descarga videos desde M3U8."""
    
    setuplog(verbose)

    # Determinar el directorio de salida
    if output_dir is None:
        output_dir = input_dir if input_dir else os.getcwd()
    
    # Crear el directorio de salida si no existe
    os.makedirs(output_dir, exist_ok=True)

    # Iniciar temporizador
    start_time = time.time()

    if input_m3u8:
        # Descargar video desde M3U8
        output_file = os.path.join(output_dir, "video_descargado.mp4")
        command = [
            'ffmpeg',
            '-i', input_m3u8,
            '-c', 'copy',
            output_file
        ]
        try:
            subprocess.run(command, check=True)
            logger.info(f"Descargado: {output_file}")
            print(f"Descargado: {output_file}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Error al descargar desde M3U8: {e}")
            print(f"Error al descargar desde M3U8. Revisa el log para más detalles.")
    
    if input_dir:
        SUPPORTED_FORMATS = (".ts", ".flv", ".mkv", ".avi", ".mov", ".wmv", ".mp4")

        # Procesar cada archivo en el directorio de entrada
        for videofname in os.listdir(input_dir):
            if videofname.lower().endswith(SUPPORTED_FORMATS):
                input_file = os.path.join(input_dir, videofname)
                base_name = os.path.splitext(videofname)[0]
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                output_file = os.path.join(output_dir, f"{base_name}_converted_{timestamp}.mp4")

                if os.path.exists(output_file):
                    respuesta = input(f"El archivo {output_file} ya existe. ¿Desea continuar con un nuevo nombre? (s/n): ").strip().lower()
                    if respuesta != 's':
                        logger.info(f"Conversión cancelada para: {output_file}.")
                        print(f"Conversión cancelada para: {output_file}.")
                        continue  # Continuar con el siguiente archivo

                command = [
                    'ffmpeg',
                    '-i', input_file,
                    '-c:v', 'copy',
                    '-c:a', 'aac',
                    '-strict', 'experimental',
                    output_file
                ]

                try:
                    with open(os.devnull, 'w') as devnull:
                        subprocess.run(command, stderr=devnull, check=True)
                    logger.info(f"Convertido: {output_file}")
                    print(f"Convertido: {output_file}")
                except subprocess.CalledProcessError as e:
                    logger.error(f"Error al convertir {input_file}: {e}")
                    print(f"Error al convertir {input_file}. Revisa el log para más detalles.")

    # Calcular el tiempo transcurrido
    elapsed_time = time.time() - start_time
    print(f"Proceso finalizado. Tiempo transcurrido: {elapsed_time:.2f} segundos.")

if __name__ == '__main__':
    convert_videos()