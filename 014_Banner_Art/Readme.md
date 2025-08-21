-----

### **Generador de Arte ASCII en Python**

-----

### Descripción

**`Art.py`** es una herramienta de línea de comandos en Python que te permite transformar cualquier texto en arte ASCII. Es perfecta para crear **banners**, **logotipos** o simplemente para añadir un toque artístico a tus scripts y programas. La herramienta te da la opción de personalizar tus creaciones eligiendo entre una gran variedad de fuentes o seleccionando una al azar.

-----

### Requisitos e Instalación

1.  Asegúrate de tener **Python 3.x** instalado. Puedes verificar tu versión con el siguiente comando:
    ```bash
    python3 --version
    ```
2.  Instala las dependencias necesarias. Puedes hacerlo con `pip` o `pip3`, dependiendo de la configuración de tu sistema:
    ```bash
    pip install pyfiglet
    ```
    Si prefieres usar un archivo de requisitos, puedes ejecutar:
    ```bash
    pip install -r requirements.txt
    ```

-----

### Uso

Para generar arte ASCII, usa el siguiente comando. Simplemente reemplaza `"TU_TEXTO"` con la cadena que deseas convertir.

```bash
python3 Art.py [OPCIONES] -s "TU_TEXTO"
```

#### Opciones de la Línea de Comandos

| Opción               | Descripción                                                                                                        |
| :------------------- | :----------------------------------------------------------------------------------------------------------------- |
| `-s`, `--string`     | **(Obligatorio)** El texto que se convertirá a arte ASCII.                                                         |
| `-f`, `--font`       | Especifica el nombre de la fuente deseada. Por defecto es `slant`. Para ver todas las fuentes disponibles, usa `-h` para ver las opciones. |
| `-r`, `--random`     | Selecciona una fuente de manera aleatoria.                                                                         |
| `-w`, `--width`      | Establece el ancho máximo de la salida en caracteres. El valor predeterminado es `200`.                            |
| `-j`, `--justify`    | Alinea el texto a la `left` (izquierda), `center` (centro) o `right` (derecha). El valor por defecto es `center`.   |
| `-o`, `--output`     | Guarda el resultado en un archivo de texto. Se crearán dos archivos: uno con el arte original y otro con la versión ajustada (sin espacios iniciales). |

-----

### Ejemplos

#### Ejemplo 1: Generar con una fuente aleatoria y guardar

Este comando generará el arte ASCII para el texto "Art" usando una fuente aleatoria y guardará la salida en dos archivos, `poc_original.txt` y `poc_ajustado.txt`.

```bash
python3 Art.py -s "Art" -r -o poc
```

#### Ejemplo 2: Generar con una fuente específica

Este comando genera el texto "Banner" usando la fuente `block` y lo imprime en la terminal.

```bash
python3 Art.py -s "Banner" -f "block"
```

-----
 