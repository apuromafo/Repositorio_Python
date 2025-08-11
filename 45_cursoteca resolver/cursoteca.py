import requests
import re
import datetime
from bs4 import BeautifulSoup
import urllib.parse
import time
import sys
import argparse
import os

# --- Configuración de la lógica de reintentos del resolvedor de links ---
MAX_REINTENTOS = 3
TIEMPO_ESPERA = 3  # segundos
SELECTOR_ELEMENTO_FIJO = 'boton-acceder'
FEED_URL = "https://cupones.cursotecaplus.com/feed.php"
BASE_PAGINA_URL = "https://cupones.cursotecaplus.com/?pagina="

def extract_url_from_hidden_link(url_del_sitio):
    """
    Extrae la URL final de una página, buscando un enlace con el
    selector fijo predefinido. Incluye lógica de reintentos.
    """
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36',
    }

    for intento in range(MAX_REINTENTOS):
        try:
            response = requests.get(url_del_sitio, headers=headers, timeout=10)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')
            
            enlace_oculto = soup.find('a', id=SELECTOR_ELEMENTO_FIJO)
            if not enlace_oculto:
                enlace_oculto = soup.find('a', class_=SELECTOR_ELEMENTO_FIJO)

            if enlace_oculto and enlace_oculto.has_attr('href'):
                return enlace_oculto['href']
            else:
                return None
        except requests.exceptions.ConnectionError:
            if intento < MAX_REINTENTOS - 1:
                print(f"Error de conexión al resolver '{url_del_sitio}' (intento {intento + 1}/{MAX_REINTENTOS}). Reintentando...", file=sys.stderr)
                time.sleep(TIEMPO_ESPERA)
            else:
                print(f"Falló después de {MAX_REINTENTOS} intentos. No se pudo conectar a {url_del_sitio}.", file=sys.stderr)
                return None
        except requests.exceptions.RequestException as e:
            print(f"Error al obtener la URL {url_del_sitio}: {e}", file=sys.stderr)
            return None
    return None

def clean_url(full_url):
    """
    Extrae y decodifica la URL de Udemy del parámetro 'murl'.
    """
    try:
        parsed_url = urllib.parse.urlparse(full_url)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        murl_list = query_params.get('murl')
        if murl_list:
            murl_value = murl_list[0]
            decoded_url = urllib.parse.unquote(murl_value)
            return decoded_url
        else:
            return full_url
    except Exception as e:
        print(f"Error al limpiar la URL: {e}", file=sys.stderr)
        return full_url

def guardar_links(links_limpios, nombre_base_archivo):
    """
    Guarda la lista de links en un archivo con formato de fecha y hora.
    """
    if links_limpios:
        now = datetime.datetime.now()
        timestamp = now.strftime("%Y-%m-%d_%H-%M-%S")
        nombre_archivo = f"{nombre_base_archivo}_{timestamp}.txt"
        
        links_unicos_ordenados = sorted(list(set(links_limpios)))
        
        with open(nombre_archivo, 'w', encoding='utf-8') as f:
            for link in links_unicos_ordenados:
                f.write(link + '\n')
        
        print("-" * 50)
        print(f"Proceso completado. Se guardaron {len(links_unicos_ordenados)} links limpios en el archivo: {nombre_archivo}")
    else:
        print("No se pudieron resolver enlaces finales de Udemy.")

def procesar_links(links_a_procesar):
    """
    Función genérica para procesar una lista de links.
    """
    links_limpios = []
    print(f"Resolviendo y limpiando {len(links_a_procesar)} links. Esto puede tardar unos minutos...")

    for i, link in enumerate(links_a_procesar):
        print(f"    [{i + 1}/{len(links_a_procesar)}] Procesando: {link}")
        resolved_url = extract_url_from_hidden_link(link)
        if resolved_url:
            cleaned_url = clean_url(resolved_url)
            if "udemy.com" in cleaned_url:
                links_limpios.append(cleaned_url)
    
    return links_limpios

def procesar_feed(url_feed):
    """
    Descarga el feed, extrae los links, los limpia y los guarda.
    """
    try:
        print("1. Conectando al feed para obtener los links de los cursos...")
        response = requests.get(url_feed, timeout=15)
        response.raise_for_status()

        feed_content = response.text
        pattern = r'https://cupones\.cursotecaplus\.com/curso/[^"\<\s]+'
        links_encontrados = re.findall(pattern, feed_content)
        
        if not links_encontrados:
            print("No se encontraron links de cursos en el feed. Proceso terminado.")
            return

        links_unicos = sorted(list(set(links_encontrados)))
        print(f"2. Se encontraron {len(links_encontrados)} links en total, {len(links_unicos)} de ellos son únicos.")
        
        links_limpios = procesar_links(links_unicos)
        guardar_links(links_limpios, "links_udemy_limpios_feed")

    except requests.exceptions.RequestException as e:
        print(f"Error al obtener el feed: {e}", file=sys.stderr)
        print("Asegúrate de que la URL es correcta y tu conexión a internet funciona.", file=sys.stderr)
    except Exception as e:
        print(f"Ocurrió un error inesperado: {e}", file=sys.stderr)

def procesar_rango_paginas(pagina_inicio, pagina_fin):
    """
    Procesa un rango de páginas, extrae todos los links y los guarda.
    """
    if pagina_inicio > pagina_fin:
        print("Error: La página de inicio no puede ser mayor que la página final.")
        return

    todos_los_links = []
    
    print(f"1. Procesando desde la página {pagina_inicio} hasta la {pagina_fin}...")
    
    for pagina in range(pagina_inicio, pagina_fin + 1):
        url = f"{BASE_PAGINA_URL}{pagina}"
        print(f"    -> Obteniendo links de la página {pagina}...")
        try:
            response = requests.get(url, timeout=15)
            response.raise_for_status()
            
            feed_content = response.text
            pattern = r'https://cupones\.cursotecaplus\.com/curso/[^"\<\s]+'
            links_encontrados = re.findall(pattern, feed_content)
            
            if links_encontrados:
                print(f"        Se encontraron {len(links_encontrados)} links en la página {pagina}.")
                todos_los_links.extend(links_encontrados)
            else:
                print(f"        No se encontraron links en la página {pagina}.")
                
        except requests.exceptions.RequestException as e:
            print(f"Error al obtener la página {pagina}: {e}", file=sys.stderr)
            # Continuar con la siguiente página si hay un error
            continue

    if not todos_los_links:
        print("No se encontraron links en el rango de páginas especificado. Proceso terminado.")
        return

    links_unicos = sorted(list(set(todos_los_links)))
    print(f"2. Se encontraron {len(todos_los_links)} links en total, {len(links_unicos)} de ellos son únicos.")
    
    links_limpios = procesar_links(links_unicos)
    guardar_links(links_limpios, f"links_udemy_paginas_{pagina_inicio}-{pagina_fin}")


def procesar_archivo_menu():
    """
    (Versión del menú) Pide el nombre del archivo, lo lee, procesa y guarda los links.
    """
    while True:
        nombre_archivo = input("Ingresa el nombre del archivo (ej: links.txt): ")
        if not os.path.exists(nombre_archivo):
            print(f"Error: El archivo '{nombre_archivo}' no se encontró. Inténtalo de nuevo.")
            continue
        
        try:
            with open(nombre_archivo, 'r', encoding='utf-8') as f:
                links = [line.strip() for line in f if line.strip()]
            
            if not links:
                print(f"El archivo '{nombre_archivo}' está vacío o no contiene links. Proceso terminado.")
                return
            
            print(f"1. Se han encontrado {len(links)} links en el archivo '{nombre_archivo}'.")
            links_limpios = procesar_links(links)
            guardar_links(links_limpios, "links_udemy_desde_archivo")
            break
        except Exception as e:
            print(f"Ocurrió un error inesperado al procesar el archivo: {e}", file=sys.stderr)
            break

def procesar_url_unica_menu():
    """
    (Versión del menú) Pide una única URL, la procesa y muestra el resultado en la consola.
    """
    url_unica = input("Ingresa la URL a resolver: ")
    print(f"1. Procesando la URL: {url_unica}")
    resolved_url = extract_url_from_hidden_link(url_unica)
    if resolved_url:
        cleaned_url = clean_url(resolved_url)
        if "udemy.com" in cleaned_url:
            print("-" * 50)
            print("¡URL resuelta con éxito!")
            print(f"URL de Udemy: {cleaned_url}")
        else:
            print("No se pudo obtener una URL de Udemy del enlace proporcionado.")
    else:
        print("No se pudo resolver el enlace.")

def mostrar_menu():
    """
    Muestra el menú de opciones en la consola.
    """
    print("-" * 50)
    print("      RESOLVEDOR DE LINKS CURSOTECA PLUS")
    print("-" * 50)
    print("Selecciona una opción:")
    print("1. Procesar el feed RSS")
    print("2. Procesar un rango de páginas numeradas")
    print("3. Procesar una lista de links desde un archivo")
    print("4. Procesar una URL individual")
    print("5. Salir")
    print("-" * 50)

def main_menu():
    """
    Función principal para ejecutar el menú interactivo.
    """
    while True:
        mostrar_menu()
        opcion = input("Ingresa el número de tu opción: ")
        
        if opcion == '1':
            procesar_feed(FEED_URL)
        elif opcion == '2':
            try:
                pagina_inicio = int(input("Ingresa la página de inicio (ej: 1): "))
                pagina_fin = int(input("Ingresa la página final (ej: 100): "))
                procesar_rango_paginas(pagina_inicio, pagina_fin)
            except ValueError:
                print("Entrada no válida. Por favor, ingresa números enteros.")
        elif opcion == '3':
            procesar_archivo_menu()
        elif opcion == '4':
            procesar_url_unica_menu()
        elif opcion == '5':
            print("Saliendo del programa. ¡Hasta pronto!")
            break
        else:
            print("Opción no válida. Por favor, ingresa un número del 1 al 5.")
        
        if opcion != '5':
            input("\nPresiona Enter para continuar...")
            os.system('cls' if os.name == 'nt' else 'clear')

def main_args(args):
    """
    Procesa los argumentos de la línea de comandos.
    """
    if args.url:
        print(f"Procesando URL desde la línea de comandos: {args.url}")
        resolved_url = extract_url_from_hidden_link(args.url)
        if resolved_url:
            cleaned_url = clean_url(resolved_url)
            if "udemy.com" in cleaned_url:
                print(f"URL de Udemy: {cleaned_url}")
            else:
                print("No se pudo obtener una URL de Udemy del enlace proporcionado.")
        else:
            print("No se pudo resolver el enlace.")
    elif args.file:
        print(f"Procesando archivo desde la línea de comandos: {args.file}")
        try:
            with open(args.file, 'r', encoding='utf-8') as f:
                links = [line.strip() for line in f if line.strip()]
            links_limpios = procesar_links(links)
            guardar_links(links_limpios, "links_udemy_desde_archivo")
        except FileNotFoundError:
            print(f"Error: El archivo '{args.file}' no se encontró.")
    elif args.feed:
        print("Procesando feed desde la línea de comandos...")
        procesar_feed(FEED_URL)
    elif args.pages:
        try:
            pagina_inicio, pagina_fin = args.pages
            print(f"Procesando páginas desde la línea de comandos: {pagina_inicio} a {pagina_fin}")
            procesar_rango_paginas(pagina_inicio, pagina_fin)
        except ValueError:
            print("Error: El argumento -p requiere dos números enteros: página_inicio y página_fin.")
    else:
        print("Comando no reconocido. Ejecute 'python Resuelve.py -h' para ver las opciones.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Resuelve enlaces de Cursoteca Plus. Se ejecuta en modo interactivo si no se especifican argumentos."
    )
    
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        '-u', '--url',
        type=str,
        help="Procesa una única URL y muestra el resultado en la consola."
    )
    group.add_argument(
        '-f', '--file',
        type=str,
        help="Procesa los enlaces de un archivo de texto, uno por línea."
    )
    group.add_argument(
        '-a', '--feed',
        action='store_true',
        help="Procesa el feed RSS principal de Cursoteca Plus."
    )
    group.add_argument(
        '-p', '--pages',
        nargs=2,
        type=int,
        metavar=('PAGINA_INICIO', 'PAGINA_FIN'),
        help="Procesa un rango de páginas numeradas, de inicio a fin."
    )

    if len(sys.argv) > 1:
        args = parser.parse_args()
        main_args(args)
    else:
        main_menu()