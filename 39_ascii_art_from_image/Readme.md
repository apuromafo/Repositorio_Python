
# Script de Conversión de Imágenes a Arte ASCII

Este script convierte imágenes en arte ASCII, permitiéndote visualizar tus fotos utilizando caracteres del teclado.  Es una herramienta simple y divertida para explorar la conversión de imágenes en representaciones textuales.

## Requisitos

*   **Python 3.6 o superior:** Asegúrate de tener Python instalado en tu sistema.
*   **Pillow (PIL):** La biblioteca Pillow es necesaria para el procesamiento de imágenes.  Puedes instalarla usando pip:

    ```bash
    pip install pillow
    ```

## Descripción

El script `image_to_ascii.py` toma una imagen como entrada y la convierte en arte ASCII, mostrando un resultado visualizado en la consola.  También permite guardar el resultado en un archivo de texto.

## Uso

1.  **Guarda el Script:** Guarda el código proporcionado como un archivo llamado `image_to_ascii.py`.
2.  **Ejecuta desde la línea de comandos:** Abre una terminal o símbolo del sistema y navega hasta el directorio donde guardaste el script. Luego, ejecuta el script con los siguientes argumentos:

    ```bash
    python image_to_ascii.py -a <ruta_al_archivo_de_imagen> [opciones]
    ```

    *   `-a` o `--archivo`:  Especifica la ruta al archivo de imagen que deseas convertir.  **Este argumento es obligatorio.**
    *   `-o` o `--output`: Especifica la ruta del archivo donde se guardará el arte ASCII resultante. Si no se especifica, el resultado se imprimirá en la consola.
    *   `-p` o `--tamano`: Especifica el ancho deseado para la imagen de salida en arte ASCII.  Puedes usar un número entero (ej: `100`) o un formato anchoXalto (ej: `100x50`). Si no se especifica, el script te pedirá que introduzcas el tamaño interactivamente.

    **Ejemplos:**

    *   Convertir `imagen.jpg` a arte ASCII con un ancho de 80 caracteres y guardarlo en `salida.txt`:
        ```bash
        python image_to_ascii.py -a imagen.jpg -o salida.txt -p 80
        ```

    *   Convertir `foto.png` a arte ASCII, imprimiendo el resultado en la consola:
        ```bash
        python image_to_ascii.py -a foto.png
        ```

    *   Convertir `mi_imagen.jpeg` y pedir el tamaño interactivamente:
         ```bash
         python image_to_ascii.py -a mi_imagen.jpeg
         ```

ejemplo visual
![./demo/img.png](./demo/img.png)
ejemplo de salida
![./img/poc.png](./img/poc.png)

## Argumentos de Línea de Comandos

| Argumento     | Tipo      | Descripción                                                                |
|---------------|-----------|----------------------------------------------------------------------------|
| `-a` o `--archivo` | `str`     | Ruta al archivo de imagen de entrada (obligatorio).                       |
| `-o` o `--output` | `str`     | Ruta opcional para guardar el arte ASCII en un archivo de texto.          |
| `-p` o `--tamano` | `str`     | Ancho deseado para la imagen ASCII. Puede ser un número entero o anchoXalto.|

## Código Fuente (Resumen)

El script utiliza las siguientes bibliotecas:

*   **argparse:** Para analizar los argumentos de línea de comandos.
*   **PIL (Pillow):**  Para abrir, redimensionar y convertir imágenes.

El script funciona en los siguientes pasos:

1.  Analiza los argumentos de la línea de comandos.
2.  Abre la imagen especificada.
3.  Redimensiona la imagen al ancho deseado.
4.  Convierte la imagen a escala de grises.
5.  Mapea cada píxel a un carácter ASCII basado en su valor de gris.
6.  Organiza los caracteres ASCII en líneas para formar la imagen final.
7.  Imprime el arte ASCII en la consola o lo guarda en un archivo, según se especifique.

## Notas

*   La calidad del arte ASCII depende del conjunto de caracteres utilizado (`ASCII_CHARS`). Un conjunto más largo puede producir resultados más detallados, pero también puede requerir una mayor cantidad de espacio para almacenar el resultado.
*   El factor `0.55` en la función `resize_image` está diseñado para compensar la tendencia de los caracteres ASCII a ser más altos que anchos en muchas terminales.  Puedes ajustar este valor si encuentras que el arte ASCII se ve distorsionado.
*   Este script es una implementación básica y puede no funcionar perfectamente con todas las imágenes o terminales.
 