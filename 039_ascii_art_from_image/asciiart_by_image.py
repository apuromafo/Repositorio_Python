import argparse
from PIL import Image

# Conjunto de caracteres ASCII ordenados de oscuro a claro
# Tu conjunto original era "@%#*+=-:. ", que es de oscuro a claro.
# Un conjunto más largo puede dar más detalle, pero el tuyo funciona bien.
# ASCII_CHARS = ["@", "#", "S", "%", "?", "*", "+", ";", ":", ",", ".", " "] # Ejemplo de un conjunto más largo
ASCII_CHARS = "@%#*+=-:. " # Tu conjunto original

def resize_image(image, new_width=100):
    """Redimensiona una imagen para que se ajuste al ancho deseado, manteniendo la proporción."""
    width, height = image.size
    aspect_ratio = height / width
    # El 0.55 es un factor de corrección aproximado para la relación de aspecto de los caracteres de texto
    # en la mayoría de las terminales (los caracteres son más altos que anchos).
    new_height = int(new_width * aspect_ratio * 0.55)
    resized_image = image.resize((new_width, new_height))
    return resized_image

def grayify(image):
    """Convierte la imagen a escala de grises."""
    return image.convert("L")

def pixels_to_ascii(image):
    """Convierte los píxeles de una imagen en escala de grises a caracteres ASCII."""
    pixels = image.getdata()
    # Mapea el valor del píxel (0-255) a un índice en ASCII_CHARS
    # Dividimos por (256 / len(ASCII_CHARS)) para mapear todo el rango 0-255
    # a los índices disponibles de ASCII_CHARS.
    # Usamos int() para asegurar que el índice sea un entero.
    characters = "".join([ASCII_CHARS[pixel * len(ASCII_CHARS) // 256] for pixel in pixels])
    return characters

def image_to_ascii(path, new_width):
    """Procesa una imagen y la convierte a arte ASCII."""
    try:
        image = Image.open(path)
    except FileNotFoundError:
        print(f"Error: El archivo '{path}' no fue encontrado.")
        return None
    except Exception as e:
        print(f"Error al abrir la imagen '{path}': {e}")
        return None

    # Redimensionar, convertir a grises y mapear a caracteres ASCII
    image = resize_image(image, new_width)
    image = grayify(image)
    ascii_str = pixels_to_ascii(image)

    # Reorganizar la cadena ASCII en líneas para formar la imagen final
    img_width = image.width
    ascii_image = "\n".join(
        [ascii_str[i:i + img_width] for i in range(0, len(ascii_str), img_width)]
    )

    return ascii_image

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Convierte una imagen a arte ASCII.",
        formatter_class=argparse.RawTextHelpFormatter # Para que la descripción del help se muestre tal cual.
    )
    # Argumento para la ruta del archivo de imagen (requerido)
    parser.add_argument(
        "-a", "--archivo",
        type=str,
        required=True,
        help="Ruta al archivo de imagen de entrada (ej: tu_imagen.jpg)."
    )
    # Argumento para la ruta del archivo de salida (opcional)
    parser.add_argument(
        "-o", "--output",
        type=str,
        help="Ruta opcional para guardar el arte ASCII en un archivo de texto (ej: salida.txt)."
    )
    # Argumento para el tamaño de la imagen de salida (opcional)
    parser.add_argument(
        "-p", "--tamano",
        type=str,
        help="Ancho de la imagen ASCII. Puedes usar un número (ej: 100) o un formato anchoXalto (ej: 100x50)."
             "\nSi no se especifica, se preguntará interactivamente."
    )

    args = parser.parse_args()

    input_path = args.archivo
    output_path = args.output
    desired_width = None

    # Manejar el argumento -p/--tamano
    if args.tamano:
        try:
            if 'x' in args.tamano:
                # Si se especifica anchoXalto, solo tomamos el ancho por ahora
                # La función resize_image ya ajusta la altura proporcionalmente.
                parts = args.tamano.split('x')
                desired_width = int(parts[0])
            else:
                desired_width = int(args.tamano)
            if desired_width <= 0:
                raise ValueError("El ancho debe ser un número positivo.")
        except ValueError:
            print("Error: Formato de tamaño inválido. Usa un número entero para el ancho (ej: 100) o anchoXalto (ej: 100x50).")
            exit(1)
    else:
        # Si -p no se especifica, preguntar interactivamente
        while True:
            try:
                user_input = input("Introduce el ancho deseado para el arte ASCII (ej: 100): ")
                desired_width = int(user_input)
                if desired_width <= 0:
                    print("Por favor, introduce un número positivo para el ancho.")
                else:
                    break
            except ValueError:
                print("Entrada inválida. Por favor, introduce un número entero.")

    # Generar el arte ASCII
    ascii_art = image_to_ascii(input_path, desired_width)

    if ascii_art:
        # Imprimir en consola
        print(ascii_art)

        # Guardar en archivo si se especificó una ruta de salida
        if output_path:
            try:
                with open(output_path, "w") as f:
                    f.write(ascii_art)
                print(f"\nArte ASCII guardado en '{output_path}'")
            except Exception as e:
                print(f"Error al guardar el archivo en '{output_path}': {e}")