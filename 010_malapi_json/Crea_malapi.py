import requests
import re
import json
from bs4 import BeautifulSoup
author = 'Apuromafo'
version = '0.0.1'
date = '23.06.2025'

def extraer_tablas(url):
    """Extrae las tablas que contienen <tbody> y no tienen atributos."""
    try:
        response = requests.get(url)
        response.raise_for_status()  # Lanza un error si la solicitud falla
    except requests.exceptions.HTTPError as http_err:
        print(f"Error HTTP: {http_err}")
        return []
    except requests.exceptions.RequestException as req_err:
        print(f"Error de solicitud: {req_err}")
        return []

    # Obtener el contenido completo de la página
    html_contenido = response.text

    # Expresión regular para encontrar tablas que contienen <tbody> sin atributos
    tablas = re.findall(r'(<table[^>]*?>\s*<tbody.*?>.*?</tbody>\s*</table>)', html_contenido, re.DOTALL)

    return tablas

def extraer_funciones(html_contenido):
    """Extrae las funciones de un contenido HTML y las guarda en una lista."""
    soup = BeautifulSoup(html_contenido, 'html.parser')
    
    # Encuentra todas las etiquetas <a> que tienen la clase especificada
    enlaces_funciones = soup.find_all('a', class_='white-link map-item-link')
    
    # Extraer el texto de cada enlace
    funciones = [enlace.get_text(strip=True) for enlace in enlaces_funciones]
    
    return funciones

def main():
    url = 'https://malapi.io'  # Cambia esta URL si es necesario

    # 1. Extraer tablas
    tablas = extraer_tablas(url)
    
    if not tablas:
        print("No se encontraron tablas.")
        return

    categorias = ['Enumeration', 'Injection', 'Evasion', 'Spying', 'Internet', 'Anti-Debugging', 'Ransomware', 'Helper']
    resultado = {"Categories": {}}

    # 2. Procesar tablas para extraer funciones
    for i, tabla in enumerate(tablas, start=1):
        lista_funciones = extraer_funciones(tabla)

        # Usar la categoría correspondiente
        if i <= len(categorias):
            categoria = categorias[i - 1]
            resultado["Categories"][categoria] = lista_funciones

    # 3. Guardar el resultado final en un archivo JSON
    with open('malapi.json', 'w', encoding='utf-8') as f:
        json.dump(resultado, f, indent=4)

    print(f"Funciones combinadas y guardadas en 'malapi.json'")

if __name__ == "__main__":
    main()