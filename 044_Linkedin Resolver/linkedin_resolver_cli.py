import re
import requests
from bs4 import BeautifulSoup
import argparse # Importar el módulo argparse para manejar argumentos de línea de comandos
import sys      # Importar sys para manejar la entrada/salida estándar

def extract_final_url(linkedin_url):
    """
    Intenta extraer la URL final de un enlace acortado de LinkedIn.
    Debido a cómo LinkedIn maneja sus enlaces acortados (redirecciones y metadatos),
    a veces es necesario seguir las redirecciones o parsear el HTML para encontrar
    el enlace externo real.

    Esta versión intenta simular un comportamiento de "navegación anónima"
    para evitar el uso de cookies persistentes y enviar un User-Agent común.
    """
    # Configuración de encabezados para simular una solicitud de navegador
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Connection': 'keep-alive',
    }

    try:
        # Usar una nueva sesión de requests para asegurar que no se envíen cookies previas
        # y que la sesión sea "limpia" para cada URL.
        with requests.Session() as session:
            session.headers.update(headers) # Aplicar los encabezados a la sesión

            # Realiza una solicitud GET para obtener la respuesta del enlace.
            # Permite redirecciones automáticamente (allow_redirects=True por defecto).
            response = session.get(linkedin_url, timeout=10)
            response.raise_for_status() # Lanza una excepción para códigos de estado HTTP erróneos (4xx o 5xx)

            # Si la URL final después de las redirecciones no es la original, la devuelve.
            # Esto maneja la mayoría de los casos de redirección directa.
            if response.url != linkedin_url:
                return response.url

            # Si no hubo una redirección directa, intenta parsear el HTML
            # para encontrar un enlace externo, como lo haría LinkedIn.
            soup = BeautifulSoup(response.text, 'html.parser')

            # --- LÓGICA: Buscar el enlace específico en las páginas de advertencia de LinkedIn ---
            # LinkedIn usa una etiqueta 'a' con clases y atributos específicos para el enlace externo.
            specific_external_link = soup.find(
                'a',
                class_='artdeco-button artdeco-button--tertiary',
                attrs={'data-tracking-control-name': 'external_url_click', 'href': True}
            )
            if specific_external_link and specific_external_link['href'].startswith('http'):
                return specific_external_link['href']
            # --- FIN LÓGICA ---

            # Busca un meta tag de redirección
            meta_refresh = soup.find('meta', attrs={'http-equiv': 'refresh'})
            if meta_refresh and 'content' in meta_refresh.attrs:
                match = re.search(r'url=(["\']?)(.*?)\1', meta_refresh['content'], re.IGNORECASE)
                if match:
                    return match.group(2)

            # Busca un enlace canónico
            canonical_link = soup.find('link', rel='canonical', href=True)
            if canonical_link and canonical_link['href'].startswith('http'):
                return canonical_link['href']

            # Si no se encuentra un enlace específico, intenta buscar el primer enlace saliente.
            # Esto es un fallback y puede no ser siempre la URL deseada.
            external_link = soup.find('a', href=True)
            if external_link and external_link['href'].startswith('http'):
                return external_link['href']

            # Si no se puede resolver, devuelve la URL original.
            return linkedin_url
    except requests.exceptions.RequestException as e:
        print(f"Error al obtener la URL {linkedin_url}: {e}", file=sys.stderr) # Imprime errores a stderr
        return linkedin_url
    except Exception as e:
        print(f"Ocurrió un error inesperado al procesar {linkedin_url}: {e}", file=sys.stderr) # Imprime errores a stderr
        return linkedin_url

def replace_urls_in_text(text):
    """
    Encuentra todos los enlaces acortados de LinkedIn (lnkd.in) en el texto
    y los reemplaza con sus URLs finales.
    """
    # Expresión regular para encontrar URLs de lnkd.in
    # Asegura que coincida con el formato esperado de lnkd.in
    linkedin_urls = re.findall(r"https://lnkd\.in/[a-zA-Z0-9_-]+", text)
    
    processed_text = text
    for url in linkedin_urls:
        resolved_url = extract_final_url(url)
        # Reemplaza todas las ocurrencias de la URL acortada con la resuelta
        processed_text = processed_text.replace(url, resolved_url)
    return processed_text

if __name__ == "__main__":
    # Configuración del parser de argumentos
    parser = argparse.ArgumentParser(
        description="Resuelve enlaces acortados de LinkedIn (lnkd.in) en un texto."
    )
    parser.add_argument(
        "-a", "--archivo", 
        help="Ruta al archivo de texto de entrada para procesar."
    )
    parser.add_argument(
        "-o", "--output", 
        help="Ruta al archivo donde se guardará el texto procesado. Si no se especifica, se imprime en la consola."
    )

    args = parser.parse_args()

    input_text = ""

    # Leer el texto de entrada
    if args.archivo:
        try:
            with open(args.archivo, 'r', encoding='utf-8') as f:
                input_text = f.read()
            print(f"Leyendo texto desde: {args.archivo}")
        except FileNotFoundError:
            print(f"Error: El archivo '{args.archivo}' no fue encontrado.", file=sys.stderr)
            sys.exit(1) # Salir con un código de error
        except Exception as e:
            print(f"Error al leer el archivo '{args.archivo}': {e}", file=sys.stderr)
            sys.exit(1)
    else:
        # Si no se especifica un archivo, leer desde la entrada estándar (consola)
        print("--- LinkedIn URL Resolver (Python) ---")
        print("Pega tu publicación de LinkedIn a continuación y este script")
        print("reemplazará las URLs acortadas con sus enlaces originales.")
        print("Presiona Enter dos veces para finalizar la entrada de texto.")
        
        lines = []
        while True:
            try:
                line = input()
                if not line: # Si se presiona Enter en una línea vacía
                    break
                lines.append(line)
            except EOFError: # Para manejar Ctrl+D (Unix) o Ctrl+Z (Windows)
                break
        input_text = "\n".join(lines)

    if input_text.strip(): # Verifica si el texto de entrada no está vacío
        print("\nResolviendo URLs...")
        resolved_text = replace_urls_in_text(input_text)

        # Escribir el texto de salida
        if args.output:
            try:
                with open(args.output, 'w', encoding='utf-8') as f:
                    f.write(resolved_text)
                print(f"Texto procesado guardado en: {args.output}")
            except Exception as e:
                print(f"Error al escribir en el archivo '{args.output}': {e}", file=sys.stderr)
                sys.exit(1)
        else:
            print("\n--- Texto Procesado ---")
            print(resolved_text)
            print("----------------------")
    else:
        print("\nNo se ingresó texto para procesar.")
