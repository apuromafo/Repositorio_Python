# 🤖 PortSwigger Academy Scraper

Herramienta de web scraping en Python diseñada para descargar y limpiar el contenido de la PortSwigger Web Security Academy, convirtiéndolo a formato Markdown. El script organiza el contenido en una estructura de carpetas que imita la jerarquía de la web original.

## 🌟 Características

  * **Extracción de contenido**: Descarga automáticamente los temas y lecciones de la PortSwigger Academy.
  * **Limpieza de HTML**: Elimina elementos innecesarios como cabeceras, pies de página, scripts, estilos y bloques de registro/publicidad para obtener un contenido limpio y legible.
  * **Conversión a Markdown**: Convierte el contenido HTML extraído a formato Markdown utilizando la librería `html2text`.
  * **Gestión de imágenes**: Descarga las imágenes relevantes del contenido y las guarda localmente, reescribiendo sus rutas para que sean accesibles en el archivo Markdown.
  * **Estructura de carpetas intuitiva**: Organiza el contenido descargado en una estructura de directorios que refleja la URL de cada lección, haciendo que la navegación offline sea más sencilla.

## 🚀 Uso

### Requisitos

Asegúrate de tener Python 3.x instalado. Luego, instala las librerías necesarias:

```bash
pip install requests beautifulsoup4 html2text
```

### Ejecución

1.  Clona o descarga este repositorio.
2.  Navega al directorio donde se encuentra el script.
3.  Ejecuta el script desde tu terminal:

<!-- end list -->

```bash
python portswigger_scraper.py
```

El script creará un directorio llamado `portswigger_academy_content_md_cleaned_final_v4` (o el nombre que esté configurado en el script) y guardará todo el contenido ahí.

## ⚙️ Configuración del Script

Puedes modificar las siguientes variables al inicio del script si lo necesitas:

  * `BASE_URL`: URL base de la academia. (Por defecto: `https://portswigger.net`)
  * `ACADEMY_INDEX_URL`: URL del índice de la academia.
  * `OUTPUT_DIR`: Nombre del directorio donde se guardará el contenido descargado.

## ⚠️ Advertencia

Este script realiza múltiples peticiones a un sitio web. Por favor, úsalo de manera responsable.
 Se han añadido pausas (`time.sleep`) para evitar saturar el servidor y respetar las políticas de uso del sitio. 
 El uso indebido de herramientas de scraping puede ser ilegal en algunas jurisdicciones y está en contra de los términos de servicio de muchos sitios web.

 