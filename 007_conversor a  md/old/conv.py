#uso conv .\conv.py .\carpeta\archivo.htm
#Archivo convertido: .\carpeta\archivo.htm -> .\carpeta\archivo.md

import os
import chardet
import markdownify
import argparse

def convertir_archivo(archivo_entrada, carpeta_salida=None):
  """Convierte un archivo HTML a Markdown.

  Args:
    archivo_entrada: Ruta del archivo HTML.
    carpeta_salida: Ruta de la carpeta donde se guardará el archivo Markdown.
      Si es None, se crea en la misma carpeta que el archivo HTML con el mismo nombre.
  """

  # Detecta la codificación del archivo
  with open(archivo_entrada, 'rb') as rawdata:
    result = chardet.detect(rawdata.read())
    encoding = result['encoding']

  # Lee el contenido HTML
  with open(archivo_entrada, 'r', encoding=encoding) as f:
    html_content = f.read()

  # Convierte a Markdown
  markdown_text = markdownify.markdownify(html_content, heading_style='ATX')

  # Guarda el archivo Markdown
  if carpeta_salida:
    ruta_markdown = os.path.join(carpeta_salida, os.path.basename(archivo_entrada).replace(".html", ".md"))
  else:
    ruta_markdown = os.path.splitext(archivo_entrada)[0] + ".md"

  with open(ruta_markdown, 'w', encoding='utf-8') as f:
    f.write(markdown_text)

  print(f"Archivo convertido: {archivo_entrada} -> {ruta_markdown}")

if __name__ == "__main__":
  parser = argparse.ArgumentParser(description="Convierte archivos HTML a Markdown.")
  parser.add_argument("entrada", help="Ruta del archivo HTML")
  parser.add_argument("--salida", help="Ruta de la carpeta de salida (opcional)")
  args = parser.parse_args()  # Parse the arguments and store them in `args`

  convertir_archivo(args.entrada, args.salida)