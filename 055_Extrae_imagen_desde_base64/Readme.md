# Base64 Extractor   (v2.0)

Este script de Python (`extract.py`) está diseñado para **analizar archivos de texto en busca de grandes bloques de cadenas codificadas en Base64**, decodificarlos y **clasificar automáticamente el contenido binario resultante** utilizando firmas mágicas (*magic bytes*).

Es una herramienta útil en el **análisis de *malware*, correo electrónico o documentos ofuscados** para identificar *payloads* incrustados.

## 🚀 Características Principales

* **Decodificación Robusta:** Identifica y decodifica grandes bloques de Base64, ignorando las cadenas cortas (posible ruido) y maneja las variantes comunes como la **omisión de *padding***.
* **Identificación Avanzada:** Clasifica más de 20 tipos de archivos, incluyendo:
    * **Archivos Comprimidos:** `ZIP`, `RAR`, `7z`, `GZ`.
    * **Documentos Office Modernos:** Reconoce la estructura interna de archivos `.docx`, `.xlsx`, y `.pptx`.
    * **Documentos Office Antiguos:** Clasifica archivos `.doc`, `.xls`, `.ppt` basados en el formato OLE2.
    * **Otros:** Imágenes (`PNG`, `JPG`), PDF, ejecutables (`EXE`, `ELF`), y multimedia.
* **Auditoría Detallada:** Genera un archivo `extraction_log.json` que registra metadatos, tamaño y el tipo de cada archivo extraído, junto con un resumen estadístico.

## 📋 Requisitos

* Python 3.x
* No requiere librerías externas más allá de las incluidas en la instalación estándar de Python (`os`, `sys`, `re`, `base64`, `json`, `zipfile`, `io`, `datetime`).

## 🛠️ Uso

Simplemente ejecuta el script, pasando la ruta del archivo de texto que contiene las cadenas Base64 como argumento:

```bash
python3 extract.py <nombre_del_archivo>