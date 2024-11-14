
# Conversor de HTML a Markdown con  markdownify

Pequeña herramienta de conversión de HTML a Markdown. Esta herramienta permite transformar archivos HTML en formato Markdown, facilitando la creación de documentos más legibles y amigables haciendo uso de la librería  markdownify

## Uso Normal

Puedes guardar el contenido de una web o página en un documento de Word, exportarlo como archivo HTML y luego utilizar esta herramienta para convertir ese archivo en .md. Esto asegura que el contenido se adapte al formato Markdown sin perder las imágenes presentes en el HTML, siendo compatible, inclusive con entradas que provienen de otros sitios como gitbook, artículos de linkedin entre otros portales, ya que solo se encarga de procesar el html entregado.

## Instalación

Asegúrate de tener Python 3.x instalado en tu sistema. También necesitarás la biblioteca `markdownify`. Puedes instalarla con el siguiente comando:

```bash
pip install markdownify
````

## Uso

Para convertir un archivo HTML a Markdown, ejecuta el siguiente comando:

bash

Copiar

```
python conv.py archivo.html
```

### Opciones

- **Archivo de entrada**: `archivo.html` es la ruta del archivo HTML que deseas convertir.
- **Carpeta de salida** (opcional): Puedes especificar una carpeta de salida usando el argumento `--salida`:

bash

Copiar

```
python conv.py archivo.html --salida carpeta_salida
```

### Ejemplo

bash

Copiar

```
python conv.py ejemplo.html --salida salida_markdown
```

### Salida esperada

El archivo Markdown resultante se guardará en la misma carpeta que el archivo HTML (o en la carpeta especificada) y tendrá el mismo nombre, con la extensión `.md`.

## Notas

- La herramienta intenta leer el archivo HTML utilizando varias codificaciones (UTF-8 y ISO-8859-1) para garantizar una conversión exitosa.
- Si no se proporciona un archivo de entrada, el script entrará en modo interactivo, permitiendo que ingreses la ruta del archivo manualmente.
-  markdownify normalmente usa licencia MIT





