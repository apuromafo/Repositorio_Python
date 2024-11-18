import os
import markdownify
import argparse

def leer_archivo(archivo_entrada):
    """Lee el contenido de un archivo HTML, intentando varias codificaciones.

    Args:
        archivo_entrada: Ruta del archivo HTML.

    Returns:
        Contenido del archivo como cadena, o None si hay un error.
    """
    for encoding in ['utf-8', 'ISO-8859-1']:  # Lista de codificaciones a probar
        try:
            with open(archivo_entrada, 'r', encoding=encoding) as f:
                return f.read()
        except UnicodeDecodeError:
            print(f"Error: No se pudo leer el archivo {archivo_entrada} con {encoding}.")
    return None  # Retorna None si no se pudo leer con ninguna codificación

def convertir_archivo(archivo_entrada, carpeta_salida=None):
    """Convierte un archivo HTML a Markdown.

    Args:
        archivo_entrada: Ruta del archivo HTML.
        carpeta_salida: Ruta de la carpeta donde se guardará el archivo Markdown.
          Si es None, se crea en la misma carpeta que el archivo HTML con el mismo nombre.
    """
    # Lee el contenido HTML
    html_content = leer_archivo(archivo_entrada)
    if html_content is None:
        print(f"Error: No se pudo leer el archivo {archivo_entrada}.")
        return

    # Convierte a Markdown
    markdown_text = markdownify.markdownify(html_content, heading_style='ATX')

    # Guarda el archivo Markdown
    if carpeta_salida:
        ruta_markdown = os.path.join(carpeta_salida, os.path.basename(archivo_entrada).replace(".html", ".md"))
    else:
        ruta_markdown = os.path.splitext(archivo_entrada)[0] + ".md"

    # Asegúrate de que se guarde en UTF-8
    with open(ruta_markdown, 'w', encoding='utf-8') as f:
        f.write(markdown_text)

    print(f"Archivo convertido: {archivo_entrada} -> {ruta_markdown}")

def main():
    parser = argparse.ArgumentParser(description="Convierte archivos HTML a Markdown.")
    parser.add_argument("entrada", nargs='?', help="Ruta del archivo HTML")
    parser.add_argument("--salida", help="Ruta de la carpeta de salida (opcional)")
    args = parser.parse_args()  # Parse the arguments and store them in `args`

    # Si no se proporciona un archivo de entrada, entrar en modo interactivo
    if args.entrada is None:
        archivo_entrada = input("Ingrese la ruta del archivo HTML: ").strip(' "')
        carpeta_salida = input("Ingrese la ruta de la carpeta de salida (dejar vacío para usar la misma carpeta): ").strip(' "') or None
    else:
        archivo_entrada = args.entrada
        carpeta_salida = args.salida

    # Validar la existencia del archivo
    if not os.path.isfile(archivo_entrada):
        print(f"Error: El archivo {archivo_entrada} no existe.")
        return

    # Validar la carpeta de salida si se proporciona
    if carpeta_salida and not os.path.isdir(carpeta_salida):
        print(f"Error: La carpeta {carpeta_salida} no existe.")
        return

    # Llamar a la función de conversión
    convertir_archivo(archivo_entrada, carpeta_salida)

if __name__ == "__main__":
    main()