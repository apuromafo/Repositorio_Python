import os
import re
import urllib.request
from urllib.parse import urljoin, urlparse
import argparse
description = 'Herramienta para descarga, inspirado en wget pero solo para ciertas extensiones'
update = 'version sin dependencias o requisitos adicionales a python3'
author = 'Apuromafo'
version = '0.0.1'
date = '12.02.2024'


# Lista de extensiones permitidas
EXTENSIONES_PERMITIDAS = ['.pdf', '.jpg', '.jpeg', '.png', '.gif', '.zip', '.docx']

def es_url_valida(url):
    """
    Verifica si una URL tiene un formato válido.
    """
    analisis_url = urlparse(url)
    return bool(analisis_url.scheme) and bool(analisis_url.netloc)

def extraer_enlaces(contenido_html, url_base):
    """
    Extrae todos los enlaces (<a href="...">) de un contenido HTML.
    """
    patron_href = re.compile(r'<a\s+(?:[^>]*?\s+)?href="([^"]*)"')
    coincidencias = patron_href.findall(contenido_html)
    return [urljoin(url_base, enlace) for enlace in coincidencias]

def descargar_archivo(url_origen, archivo_destino):
    """
    Descarga un archivo desde una URL y lo guarda en la ubicación especificada.
    """
    try:
        with urllib.request.urlopen(url_origen) as respuesta, open(archivo_destino, 'wb') as archivo:
            archivo.write(respuesta.read())
        print(f"Archivo descargado: {archivo_destino}")
        return True
    except Exception as e:
        print(f"Error al descargar {url_origen}: {e}")
        return False

def descargar_desde_sitio_web(url, carpeta_destino):
    """
    Descarga archivos permitidos desde un sitio web.
    """
    if not es_url_valida(url):
        print(f"URL inválida: {url}")
        return

    try:
        with urllib.request.urlopen(url) as respuesta:
            contenido_html = respuesta.read().decode('utf-8')
        enlaces = extraer_enlaces(contenido_html, url)

        for enlace in enlaces:
            if any(enlace.lower().endswith(ext) for ext in EXTENSIONES_PERMITIDAS):
                nombre_archivo = os.path.basename(enlace)
                archivo_destino = os.path.join(carpeta_destino, nombre_archivo)

                if os.path.exists(archivo_destino):
                    print(f"El archivo ya existe, saltando: {archivo_destino}")
                    continue

                descargar_archivo(enlace, archivo_destino)
            else:
                print(f"Archivo no permitido, saltando: {enlace}")
    except Exception as e:
        print(f"Error al acceder a {url}: {e}")

def main():
    """
    Función principal para ejecutar el descargador.
    """
    parser = argparse.ArgumentParser(description="Herramienta de descarga inspirada en wget.")
    parser.add_argument("url", help="URL del sitio web")
    parser.add_argument("destino", help="Carpeta de destino para las descargas")
    argumentos = parser.parse_args()

    # Crear la carpeta de destino si no existe
    if not os.path.exists(argumentos.destino):
        os.makedirs(argumentos.destino)
        print(f"Carpeta creada: {argumentos.destino}")

    # Iniciar descarga
    print(f"Iniciando descarga desde: {argumentos.url}")
    descargar_desde_sitio_web(argumentos.url, argumentos.destino)
    print(f"Descargas completadas en: {argumentos.destino}")

if __name__ == "__main__":
    main()