import os
import markdownify
import argparse
import subprocess # Necesario para ejecutar comandos externos como markitdown o docker
import sys # Necesario para verificar los argumentos de la línea de comandos
import datetime # Importar para añadir fecha y hora a los nombres de archivo
author = 'Apuromafo'
version = '0.0.1'
date = '14.07.2025'

def check_docker_available():
    """Verifica si Docker está instalado y accesible."""
    try:
        subprocess.run(['docker', '--version'], capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

def leer_archivo(archivo_entrada):
    """Lee el contenido de un archivo HTML o Markdown, intentando varias codificaciones.

    Args:
        archivo_entrada: Ruta del archivo.

    Returns:
        Contenido del archivo como cadena, o None si hay un error.
    """
    for encoding in ['utf-8', 'ISO-8859-1']:  # Lista de codificaciones a probar
        try:
            with open(archivo_entrada, 'r', encoding=encoding) as f:
                return f.read()
        except UnicodeDecodeError:
            print(f"Error: No se pudo leer el archivo {archivo_entrada} con {encoding}.")
        except FileNotFoundError:
            print(f"Error: El archivo {archivo_entrada} no se encontró.")
            return None
    return None  # Retorna None si no se pudo leer con ninguna codificación

def convertir_html_a_md(archivo_entrada_html, carpeta_salida=None):
    """Convierte un archivo HTML a Markdown.

    Args:
        archivo_entrada_html: Ruta del archivo HTML.
        carpeta_salida: Ruta de la carpeta donde se guardará el archivo Markdown.
          Si es None, se crea en la misma carpeta que el archivo HTML.
    """
    print(f"\n--- Convirtiendo HTML a Markdown: {archivo_entrada_html} ---")
    # Lee el contenido HTML
    html_content = leer_archivo(archivo_entrada_html)
    if html_content is None:
        return

    # Convierte a Markdown usando markdownify (para HTML a MD)
    markdown_text = markdownify.markdownify(html_content, heading_style='ATX')

    # Determina la ruta del archivo Markdown
    if carpeta_salida:
        nombre_base = os.path.basename(archivo_entrada_html).replace(".html", "")
        # Añadir timestamp al nombre del archivo
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        ruta_markdown = os.path.join(carpeta_salida, f"{nombre_base}_{timestamp}.md")
    else:
        nombre_base = os.path.splitext(archivo_entrada_html)[0]
        # Añadir timestamp al nombre del archivo
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        ruta_markdown = f"{nombre_base}_{timestamp}.md"

    # Asegúrate de que se guarde el Markdown en UTF-8
    try:
        with open(ruta_markdown, 'w', encoding='utf-8') as f:
            f.write(markdown_text)
        print(f"Archivo Markdown creado: {ruta_markdown}")
    except IOError as e:
        print(f"Error al guardar el archivo Markdown: {e}")
        return

def _procesar_pdf_individual_a_md(single_pdf_path, carpeta_salida):
    """Función auxiliar para convertir un único archivo PDF a Markdown usando Docker."""
    print(f"  Procesando PDF individual: {single_pdf_path}")

    try:
        # Obtener rutas absolutas
        abs_single_pdf_path = os.path.abspath(single_pdf_path)
        
        if carpeta_salida:
            abs_carpeta_salida = os.path.abspath(carpeta_salida)
        else:
            abs_carpeta_salida = os.path.abspath(os.path.dirname(single_pdf_path))

        # Asegurarse de que el directorio de salida exista
        os.makedirs(abs_carpeta_salida, exist_ok=True)

        # Determina la ruta del archivo Markdown de salida
        nombre_base = os.path.basename(single_pdf_path).replace(".pdf", "")
        # Añadir timestamp al nombre del archivo
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        ruta_markdown_salida = os.path.join(abs_carpeta_salida, f"{nombre_base}_{timestamp}.md")

        # Leer el contenido binario del PDF para pasarlo a stdin de Docker
        with open(abs_single_pdf_path, 'rb') as f:
            pdf_content_bytes = f.read()

        # Construir el comando Docker para leer de stdin y escribir a stdout
        docker_command = [
            'docker', 'run', '--rm', '-i', # -i para habilitar stdin
            'markitdown:latest'
        ]

        print(f"  Ejecutando comando Docker: {' '.join(docker_command)}")
        result = subprocess.run(docker_command, input=pdf_content_bytes, capture_output=True, check=True, text=False)

        # Decodificar la salida (Markdown) de bytes a string
        markdown_output = result.stdout.decode('utf-8', errors='ignore')

        # Guardar la salida de Markdown en el archivo local
        with open(ruta_markdown_salida, 'w', encoding='utf-8') as f:
            f.write(markdown_output)

        print(f"  Conversión de PDF a Markdown completada: {ruta_markdown_salida}")
        if result.stderr:
            print("  Errores de markitdown (si los hay):", result.stderr.decode('utf-8', errors='ignore'))

    except FileNotFoundError:
        print(f"  Error: 'docker' no se encontró. Asegúrate de que Docker esté instalado y en tu PATH.")
    except subprocess.CalledProcessError as e:
        print(f"  Error al ejecutar Docker para PDF a Markdown: {e}")
        print("  Salida de error de Docker (stdout):", e.stdout.decode('utf-8', errors='ignore'))
        print("  Salida de error de Docker (stderr):", e.stderr.decode('utf-8', errors='ignore'))
        print("  Asegúrate de que la imagen 'markitdown:latest' esté construida y disponible.")
    except Exception as e:
        print(f"  Ocurrió un error inesperado durante la conversión de PDF a Markdown: {e}")

def convertir_pdf_a_md(entrada_path, carpeta_salida=None):
    """Convierte un archivo o todos los archivos PDF en un directorio a Markdown usando Docker.

    Args:
        entrada_path: Ruta del archivo PDF o del directorio que contiene PDFs.
        carpeta_salida: Ruta de la carpeta donde se guardarán los archivos Markdown.
          Si es None, se crea en la misma carpeta que el archivo PDF o en el directorio de entrada.
    """
    print(f"\n--- Iniciando conversión de PDF(s) a Markdown (usando Docker) ---")

    if not os.path.exists(entrada_path):
        print(f"Error: La ruta '{entrada_path}' no existe.")
        return

    # Validar si Docker está disponible antes de intentar usarlo
    if not check_docker_available():
        print("Error: Docker no está instalado o no está en el PATH. No se puede realizar la conversión de PDF a Markdown.")
        print("Asegúrate de que Docker esté corriendo y la imagen 'markitdown:latest' esté construida.")
        return

    if os.path.isdir(entrada_path):
        print(f"Procesando todos los archivos PDF en el directorio: {entrada_path}")
        pdf_files = [f for f in os.listdir(entrada_path) if f.lower().endswith('.pdf')]
        
        if not pdf_files:
            print(f"No se encontraron archivos PDF en el directorio: {entrada_path}")
            return

        for pdf_file_name in pdf_files:
            full_pdf_path = os.path.join(entrada_path, pdf_file_name)
            _procesar_pdf_individual_a_md(full_pdf_path, carpeta_salida)
        print(f"--- Conversión de PDF(s) completada para el directorio: {entrada_path} ---")

    elif os.path.isfile(entrada_path) and entrada_path.lower().endswith('.pdf'):
        _procesar_pdf_individual_a_md(entrada_path, carpeta_salida)
        print(f"--- Conversión de PDF completada para el archivo: {entrada_path} ---")
    else:
        print(f"Error: La ruta '{entrada_path}' no es un archivo PDF válido ni un directorio.")


def main():
    parser = argparse.ArgumentParser(description="Herramienta de conversión de documentos HTML/PDF.")
    parser.add_argument("--html_entrada", help="Ruta del archivo HTML de entrada para convertir a Markdown.")
    parser.add_argument("--pdf_entrada", help="Ruta del archivo PDF o directorio de entrada para convertir a Markdown.") # Actualizado el help
    parser.add_argument("--salida", help="Ruta de la carpeta de salida (opcional).")
    args = parser.parse_args()

    # Determinar si se ejecuta en modo interactivo o con argumentos de línea de comandos
    if not args.html_entrada and not args.pdf_entrada:
        while True:
            print("\n--- Menú de Conversión ---")
            print("1. Convertir HTML a Markdown")
            print("2. Convertir PDF(s) a Markdown (usando Docker)") # Actualizado el texto de la opción 2
            print("3. Salir")

            choice = input("Seleccione una opción (1, 2 o 3): ").strip()

            if choice == '1':
                archivo_entrada = input("Ingrese la ruta del archivo HTML: ").strip(' "')
                carpeta_salida = input("Ingrese la ruta de la carpeta de salida (dejar vacío para usar la misma carpeta): ").strip(' "') or None
                
                if not os.path.isfile(archivo_entrada):
                    print(f"Error: El archivo {archivo_entrada} no existe.")
                    continue
                if carpeta_salida and not os.path.isdir(carpeta_salida):
                    print(f"Error: La carpeta {carpeta_salida} no existe.")
                    continue
                
                convertir_html_a_md(archivo_entrada, carpeta_salida)

            elif choice == '2':
                # Ahora puede ser un archivo o un directorio
                entrada_pdf_o_dir = input("Ingrese la ruta del archivo PDF o de la carpeta con PDFs: ").strip(' "')
                carpeta_salida = input("Ingrese la ruta de la carpeta de salida (dejar vacío para usar la misma carpeta): ").strip(' "') or None

                if not os.path.exists(entrada_pdf_o_dir):
                    print(f"Error: La ruta '{entrada_pdf_o_dir}' no existe.")
                    continue
                # La validación de si es archivo/directorio y PDF se hace dentro de convertir_pdf_a_md
                
                convertir_pdf_a_md(entrada_pdf_o_dir, carpeta_salida)

            elif choice == '3':
                print("Saliendo del programa.")
                break
            else:
                print("Opción no válida. Por favor, intente de nuevo.")
    else:
        # Modo de línea de comandos
        if args.html_entrada:
            if not os.path.isfile(args.html_entrada):
                print(f"Error: El archivo HTML '{args.html_entrada}' no existe.")
                return
            if args.salida and not os.path.isdir(args.salida):
                print(f"Error: La carpeta de salida '{args.salida}' no existe.")
                return
            convertir_html_a_md(args.html_entrada, args.salida)
        elif args.pdf_entrada:
            if not os.path.exists(args.pdf_entrada): # Cambiado a exists
                print(f"Error: La ruta '{args.pdf_entrada}' no existe.")
                return
            # La validación de si es archivo/directorio y PDF se hace dentro de convertir_pdf_a_md
            convertir_pdf_a_md(args.pdf_entrada, args.salida)

if __name__ == "__main__":
    main()
