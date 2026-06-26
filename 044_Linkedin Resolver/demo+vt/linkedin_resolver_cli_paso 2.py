
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

async def extract_final_url_from_details(page, details_url):
    """
    Navega a la URL de detalles y extrae la URL final.
    """
    if not details_url:
        return None

    try:
        print(f"\n➡️ Paso 2: Navegando a la URL de detalles para extraer la tabla: {details_url}")
        await page.goto(details_url, wait_until="networkidle", timeout=30000)
        
        print("⏳ Esperando 5 segundos para que la página se estabilice...")
        await asyncio.sleep(5)
        
        print("🔎 Buscando la URL final en el contenido de la página...")
        
        # Estrategia 1: Buscar la URL en la tabla de redirecciones.
        redirect_links = await page.locator('div:has-text("Redirects") + table a[href^="http"]').all()

        if redirect_links:
            last_link = redirect_links[-1]
            final_url = await last_link.get_attribute('href')
            print(f"✨ URL final extraída de la tabla de redirecciones: {final_url}")
            return final_url

        # Estrategia 2: Si no se encontró, buscar en el div de texto.
        final_url_locator = page.locator('div.text-break')
        if await final_url_locator.count() > 0:
            final_url_text = await final_url_locator.first.inner_text()
            if final_url_text and final_url_text.startswith("http"):
                print(f"✨ URL final extraída directamente: {final_url_text}")
                return final_url_text
        
        print("❌ No se encontró la URL final en la página.")
        return None
            
    except Exception as e:
        print(f"❌ Error al extraer la URL final de la página de detalles: {e}")
        return None
    finally:
        print("--- Proceso de extracción de URL final completado ---")
        await asyncio.sleep(5)

async def resolve_from_file(input_file):
    """
    Lee las URLs de detalles de un archivo y extrae las URLs finales.
    """
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            details_urls = json.load(f)
    except FileNotFoundError:
        print(f"Error: El archivo '{input_file}' no fue encontrado.", file=sys.stderr)
        return
    except json.JSONDecodeError:
        print(f"Error: El archivo '{input_file}' no es un JSON válido.", file=sys.stderr)
        return

    resolved_urls_map = {}
    
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(extra_http_headers=HEADERS)
        page = await context.new_page()

        try:
            for original_url, details_url in details_urls.items():
                final_url = await extract_final_url_from_details(page, details_url)
                resolved_urls_map[original_url] = final_url if final_url else original_url
        finally:
            await browser.close()
    
    print("\n✅ === Resultados Finales ===")
    for original, resolved in resolved_urls_map.items():
        print(f"URL original: {original}")
        print(f"URL final: {resolved}\n")


print("\n[!] AVISO LEGAL: Use solo con autorizacion. / LEGAL NOTICE: Authorized use only.\n")
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Resuelve URLs finales a partir de un archivo de detalles de VirusTotal."
    )
    parser.add_argument(
        "-a", "--archivo",
        default="poc.txt",
        help="Ruta al archivo JSON de entrada con URLs de detalles. (por defecto: poc.txt)"
    )

    args = parser.parse_args()

    print("\n🚀 Iniciando navegador para resolver URLs desde archivo...")
    asyncio.run(resolve_from_file(args.archivo))