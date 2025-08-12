import re
import sys
import asyncio
import aiohttp
from bs4 import BeautifulSoup
import argparse

# Configuración de encabezados para simular una solicitud de navegador.
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.5',
    'Accept-Language': 'en-US,en;q=0.5',
    'Connection': 'keep-alive',
}

async def extract_final_url_async(session, linkedin_url):
    """
    Intenta extraer la URL final de un enlace acortado de LinkedIn de forma asíncrona,
    resolviendo las redirecciones basadas en HTML de la página de advertencia.
    """
    try:
        # Hacemos una solicitud sin permitir redirecciones automáticas.
        # Esto nos permite analizar la página de advertencia de LinkedIn.
        async with session.get(linkedin_url, headers=HEADERS, timeout=10, allow_redirects=False) as response:
            
            # Si el código de estado es una redirección directa (3xx), la seguimos.
            if response.status in (301, 302, 303, 307, 308):
                final_url_from_header = response.headers.get('Location')
                if final_url_from_header:
                    return final_url_from_header
            
            # Si la respuesta es 200 (OK), significa que obtuvimos la página de advertencia.
            response.raise_for_status()
            html_content = await response.text()
            soup = BeautifulSoup(html_content, 'html.parser')

            # --- Estrategia 1: Buscar un meta tag de redirección ---
            # Algunos enlaces usan un meta tag para redirigir.
            meta_refresh = soup.find('meta', attrs={'http-equiv': 'refresh'})
            if meta_refresh and 'content' in meta_refresh.attrs:
                match = re.search(r'url=(["\']?)(.*?)\1', meta_refresh['content'], re.IGNORECASE)
                if match:
                    meta_url = match.group(2)
                    if meta_url.startswith('http'):
                        return meta_url
                    
            # --- Estrategia 2: Buscar el enlace en el botón de la página de advertencia ---
            # Esta es la estrategia más común para los enlaces de lnkd.in.
            # Buscamos un enlace con texto "Continuar" o "Continue".
            specific_external_link = soup.find(
                'a',
                class_='artdeco-button',
                attrs={'href': True},
                string=lambda text: text and ('Continue' in text or 'Continuar' in text)
            )

            if specific_external_link:
                # El enlace real suele estar en el parámetro 'url' de la URL del botón.
                button_href = specific_external_link['href']
                if 'url=' in button_href:
                    from urllib.parse import unquote
                    final_url = re.search(r'url=(.*)', button_href)
                    if final_url:
                        return unquote(final_url.group(1))

            # --- Estrategia 3: Buscar un enlace canónico ---
            # Algunos enlaces tienen un enlace canónico que apunta a la URL original.
            canonical_link = soup.find('link', rel='canonical', href=True)
            if canonical_link and canonical_link['href'].startswith('http'):
                return canonical_link['href']

            # Si ninguna de las estrategias funciona, devolvemos la URL original.
            return linkedin_url
            
    except aiohttp.ClientError as e:
        print(f"Error asíncrono al obtener la URL {linkedin_url}: {e}", file=sys.stderr)
        return linkedin_url
    except Exception as e:
        print(f"Ocurrió un error inesperado al procesar {linkedin_url}: {e}", file=sys.stderr)
        return linkedin_url

async def resolve_urls_concurrently(text):
    """
    Encuentra y reemplaza URLs de lnkd.in en un texto de forma asíncrona.
    """
    # Expresión regular mejorada para URLs de lnkd.in.
    linkedin_urls = sorted(list(set(re.findall(r"https://lnkd\.in/[a-zA-Z0-9./_?&=-]+", text))))
    if not linkedin_urls:
        return text

    async with aiohttp.ClientSession(headers=HEADERS) as session:
        tasks = [extract_final_url_async(session, url) for url in linkedin_urls]
        resolved_urls_list = await asyncio.gather(*tasks)

    resolved_urls_map = dict(zip(linkedin_urls, resolved_urls_list))

    processed_text = text
    for url, resolved_url in resolved_urls_map.items():
        processed_text = processed_text.replace(url, resolved_url)

    return processed_text

def read_input_from_cli():
    """Lee el texto desde la entrada estándar hasta EOF (Ctrl+D/Ctrl+Z)."""
    print("--- LinkedIn URL Resolver ---")
    print("Pega tu publicación de LinkedIn a continuación.")
    print("Presiona Ctrl+D (Unix) o Ctrl+Z (Windows) y Enter para finalizar la entrada.")
    lines = sys.stdin.readlines()
    return "".join(lines)

if __name__ == "__main__":
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
    if args.archivo:
        try:
            with open(args.archivo, 'r', encoding='utf-8') as f:
                input_text = f.read()
            print(f"Leyendo texto desde: {args.archivo}")
        except FileNotFoundError:
            print(f"Error: El archivo '{args.archivo}' no fue encontrado.", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Error al leer el archivo '{args.archivo}': {e}", file=sys.stderr)
            sys.exit(1)
    else:
        input_text = read_input_from_cli()

    if input_text.strip():
        print("\nResolviendo URLs...")
        resolved_text = asyncio.run(resolve_urls_concurrently(input_text))

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