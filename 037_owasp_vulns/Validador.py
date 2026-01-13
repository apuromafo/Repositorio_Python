# -*- coding: utf-8 -*-
import requests
import json
import os
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter
import time

# === Configuración y rutas ===
RESULTS_DIR = "results"
os.makedirs(RESULTS_DIR, exist_ok=True)
MAX_THREADS = 10  # Máximo de hilos para validación

# === 1. Funciones de Descarga y Validación ===

def download_json(url):
    """
    Descarga y parsea un archivo JSON de la URL proporcionada.
    """
    print(f"Descargando JSON de: {url}")
    try:
        raw_url = url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
        response = requests.get(raw_url, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as err:
        print(f"Error de solicitud: {err}")
    except json.JSONDecodeError as err_json:
        print(f"Error al decodificar JSON: {err_json}")
    return None

def is_url_online(url):
    """
    Verifica si una URL está en línea y devuelve el resultado con la URL original.
    """
    if not url:
        return url, False
    try:
        response = requests.head(url, timeout=5, allow_redirects=True)
        return url, 200 <= response.status_code < 400
    except requests.exceptions.RequestException:
        return url, False

def validate_urls_sequentially(data):
    """
    Valida las URLs de la lista de datos de forma secuencial.
    """
    if not data:
        return []

    unique_urls = {entry.get("url"): entry.get("name") for entry in data if entry.get("url")}
    total_unique_urls = len(unique_urls)
    validated_entries = []
    
    print(f"\nIniciando validación de {total_unique_urls} URLs únicas de forma secuencial...")
    
    for i, (url, name) in enumerate(unique_urls.items()):
        print(f"Procesando entrada {i+1}/{total_unique_urls}: {name}", end='\r')
        is_online = is_url_online(url)[1]
        validated_entries.append({
            "url": url,
            "name": name,
            "is_online": is_online
        })
        time.sleep(0.1) # Retardo para no sobrecargar el servidor

    print("\nValidación secuencial completa.")
    validated_entries.sort(key=lambda x: x.get("is_online", False), reverse=True)
    return validated_entries

def validate_urls_concurrently(data):
    """
    Valida las URLs únicas de la lista de datos utilizando un pool de hilos.
    """
    if not data:
        return []

    unique_urls = {entry.get("url"): entry.get("name") for entry in data if entry.get("url")}
    total_unique_urls = len(unique_urls)
    
    validated_entries = []
    
    print(f"\nIniciando validación de {total_unique_urls} URLs únicas con {MAX_THREADS} hilos...")
    
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        future_to_url = {executor.submit(is_url_online, url): url for url in unique_urls}
        
        for i, future in enumerate(as_completed(future_to_url)):
            url = future_to_url[future]
            try:
                original_url, is_online = future.result()
                
                validated_entry = {
                    "url": original_url,
                    "name": unique_urls.get(original_url),
                    "is_online": is_online
                }
                validated_entries.append(validated_entry)
                
                print(f"Procesadas {i+1}/{total_unique_urls} URLs...", end='\r')
            except Exception as exc:
                print(f"{url} generó una excepción: {exc}")

    print("\nValidación concurrente completa.")
    validated_entries.sort(key=lambda x: x.get("is_online", False), reverse=True)
    return validated_entries

# === 2. Funciones de Reporte ===

def count_and_report_duplicates(data):
    """
    Cuenta y reporta las URLs duplicadas en la lista original.
    """
    urls = [entry.get("url") for entry in data if entry.get("url")]
    url_counts = Counter(urls)
    
    duplicates = {url: count for url, count in url_counts.items() if count > 1}
    
    if duplicates:
        print("\n" + "="*80)
        print(" " * 20 + "Informe de URLs Duplicadas")
        print("="*80 + "\n")
        
        sorted_duplicates = sorted(duplicates.items(), key=lambda item: item[1], reverse=True)
        for url, count in sorted_duplicates:
            print(f"- '{url}' se repite {count} veces.")
        print("\n" + "="*80)
    else:
        print("\nNo se encontraron URLs duplicadas en el archivo de entrada.")


def save_and_display_results(data, filename):
    """
    Guarda los datos en un archivo JSON y los muestra en la consola.
    """
    filepath = os.path.join(RESULTS_DIR, filename)
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        print(f"Datos guardados en '{filepath}'")
    except IOError as e:
        print(f"Error al guardar el archivo: {e}")
        return

    # Muestra los resultados en consola
    print("\n" + "="*120)
    print(" " * 45 + "Resultados de la Validación de URLs")
    print(" " * 45 + "(URLs únicas)")
    print("="*120 + "\n")

    online_urls = [entry for entry in data if entry.get("is_online")]
    offline_urls = [entry for entry in data if not entry.get("is_online")]

    if online_urls:
        print("## URLs en línea\n")
        print("{:<5} {:<50} {:<60}".format("No.", "Nombre", "URL"))
        print("-" * 120)
        for i, entry in enumerate(online_urls):
            name = entry.get("name", "N/A")
            url = entry.get("url", "N/A")
            truncated_name = (name[:47] + '...') if len(name) > 50 else name
            truncated_url = (url[:57] + '...') if len(url) > 60 else url
            print("{:<5} {:<50} {:<60}".format(i + 1, truncated_name, truncated_url))
        print("\n")

    if offline_urls:
        print("## URLs fuera de línea\n")
        print("{:<5} {:<50} {:<60}".format("No.", "Nombre", "URL"))
        print("-" * 120)
        for i, entry in enumerate(offline_urls):
            name = entry.get("name", "N/A")
            url = entry.get("url", "N/A")
            truncated_name = (name[:47] + '...') if len(name) > 50 else name
            truncated_url = (url[:57] + '...') if len(url) > 60 else url
            print("{:<5} {:<50} {:<60}".format(i + 1, truncated_name, truncated_url))
        print("\n")


# === 3. Lógica Principal ===

def main():
    """
    Punto de entrada principal del script.
    """
    parser = argparse.ArgumentParser(description="Valida URLs en un archivo JSON y genera un informe.")
    parser.add_argument(
        "url",
        type=str,
        nargs='?',
        default="https://github.com/OWASP/OWASP-VWAD/blob/master/src/data/collection.json",
        help="URL del archivo JSON de entrada. Por defecto usa el de OWASP VWAD."
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        default="validated.json",
        help="Nombre del archivo de salida para guardar los resultados validados."
    )
    parser.add_argument(
        "-s", "--single-thread",
        action="store_true",
        help="Ejecutar en modo de un solo hilo (secuencial)."
    )
    
    args = parser.parse_args()

    # Paso 1: Descargar el JSON
    collection_data = download_json(args.url)

    if collection_data:
        # Paso 2: Reportar duplicados
        count_and_report_duplicates(collection_data)

        # Paso 3: Validar las URLs
        if args.single_thread:
            validated_result = validate_urls_sequentially(collection_data)
        else:
            validated_result = validate_urls_concurrently(collection_data)

        # Paso 4: Guardar y mostrar los resultados
        save_and_display_results(validated_result, args.output)
    else:
        print("No se pudo descargar o procesar el JSON. Saliendo.")

if __name__ == "__main__":
    main()