
# =============================================================================
# AVISO LEGAL / LEGAL NOTICE
# -----------------------------------------------------------------------------
# Esta herramienta es unicamente para fines educativos y de auditoria de
# seguridad autorizada. El uso no autorizado contra sistemas sin el
# consentimiento explicito del propietario es ilegal.
# El usuario asume toda responsabilidad por el uso indebido.
#
# This tool is for educational and authorized security auditing purposes only.
# Unauthorized use against systems without the owner's explicit consent is
# illegal. The user assumes all responsibility for misuse.
# =============================================================================

import re
import sys
import asyncio
from playwright.async_api import async_playwright
import argparse
from urllib.parse import quote
import json

# === CONFIGURACIÓN ===
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36',
}

# === FUNCIONES ===

async def find_details_url(page, linkedin_url):
    """
    Usa Playwright para navegar a la página de búsqueda y encontrar la URL
    completa del reporte de detalles.
    """
    try:
        encoded_url = quote(linkedin_url, safe='')
        double_encoded_url = quote(encoded_url, safe='')
        search_url = f"https://www.virustotal.com/gui/search/{double_encoded_url}"

        print(f"\n🔎 Paso 1: Buscando URL de detalles para: {linkedin_url}")
        print(f"🌐 Accediendo a la página de búsqueda: {search_url}")

        await page.goto(search_url, wait_until="domcontentloaded", timeout=30000)
        
        print("⏳ Esperando la redirección o la actualización de la URL...")
        
        await page.wait_for_url(re.compile(r"virustotal\.com/gui/url/[a-f0-9]{64}"), timeout=15000)
        
        current_url = page.url
        
        if "/details" not in current_url:
            details_url = current_url + "/details"
        else:
            details_url = current_url

        print(f"✅ URL de detalles del reporte encontrada: {details_url}")
        
        return details_url

    except Exception as e:
        print(f"❌ Error al procesar {linkedin_url}: {e}")
        return None
    finally:
        print("--- Proceso de búsqueda de URL completado ---")
        await asyncio.sleep(3)

async def find_all_details_urls(text):
    """
    Procesa cada URL lnkd.in, una por una, para encontrar la URL de detalles.
    """
    linkedin_urls = sorted(list(set(re.findall(r"https://lnkd\.in/[a-zA-Z0-9./_?&=-]+", text))))
    if not linkedin_urls:
        return {}

    details_urls = {}
    
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(extra_http_headers=HEADERS)
        page = await context.new_page()

        try:
            for url in linkedin_urls:
                details_url = await find_details_url(page, url)
                details_urls[url] = details_url
        finally:
            await browser.close()
    
    return details_urls

# === ENTRADA/SALIDA ===

def read_input_from_cli():
    """Lee la entrada estándar para el texto a procesar."""
    print("--- LinkedIn URL Resolver (Paso 1) ---")
    print("Pega las URLs de LinkedIn que quieres verificar.")
    print("Presiona Ctrl+D (Unix) o Ctrl+Z (Windows) y Enter para finalizar.")
    lines = sys.stdin.readlines()
    return "".join(lines)


print("\n[!] AVISO LEGAL: Use solo con autorizacion. / LEGAL NOTICE: Authorized use only.\n")
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Resuelve enlaces acortados de LinkedIn (lnkd.in) y se detiene en la URL de detalles de VirusTotal."
    )
    parser.add_argument(
        "-a", "--archivo",
        help="Ruta al archivo de texto de entrada para procesar."
    )
    parser.add_argument(
        "-o", "--output",
        default="poc.txt",
        help="Ruta al archivo donde se guardará el JSON de URLs de detalles. (por defecto: poc.txt)"
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
        print("\n🚀 Iniciando navegador para encontrar URLs de detalles...")
        details_urls = asyncio.run(find_all_details_urls(input_text))
        
        try:
            with open(args.output, 'w', encoding='utf-8') as f:
                # Guardamos los resultados como JSON para que sea fácil de leer en el siguiente script
                json.dump(details_urls, f, indent=4)
            print(f"\n✅ Resultados guardados en: {args.output}")
        except Exception as e:
            print(f"❌ Error al escribir en el archivo '{args.output}': {e}", file=sys.stderr)
            sys.exit(1)
    else:
        print("\n🚫 No se ingresó texto para procesar.")