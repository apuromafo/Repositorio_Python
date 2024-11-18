import requests
import re
import json
import glob
import os
from bs4 import BeautifulSoup

def extraer_tablas(url):
    """Extrae las tablas que contienen <tbody> y no tienen atributos."""
    response = requests.get(url)
    response.raise_for_status()  # Lanza un error si la solicitud falla

    # Obtener el contenido completo de la página
    html_contenido = response.text

    # Expresión regular para encontrar tablas que contienen <tbody> sin atributos
    tablas = re.findall(r'(<table[^>]*?>\s*<tbody.*?>.*?</tbody>\s*</table>)', html_contenido, re.DOTALL)

    for i, tabla in enumerate(tablas, start=1):
        # Guardar la tabla en un archivo de texto
        nombre_archivo = f'tabla{i}.txt'
        with open(nombre_archivo, 'w', encoding='utf-8') as f:
            f.write(tabla.strip())
        print(f"Tabla {i} guardada en '{nombre_archivo}'")

def extraer_funciones(html_contenido):
    """Extrae las funciones de un contenido HTML y las guarda en una lista."""
    soup = BeautifulSoup(html_contenido, 'html.parser')
    
    # Encuentra todas las etiquetas <a> que tienen la clase especificada
    enlaces_funciones = soup.find_all('a', class_='white-link map-item-link')
    
    # Extraer el texto de cada enlace
    funciones = [enlace.get_text(strip=True) for enlace in enlaces_funciones]
    
    return funciones

def procesar_tablas():
    """Procesa las tablas generadas y extrae las funciones."""
    archivos = glob.glob('tabla*.txt')  # Busca todos los archivos que comienzan con 'tabla'
    for i, archivo in enumerate(archivos, start=1):
        with open(archivo, 'r', encoding='utf-8') as f:
            html_contenido = f.read()
        
        lista_funciones = extraer_funciones(html_contenido)

        # Guardar la lista en un archivo de salida con categoría
        categoria = ['Enumeration', 'Injection', 'Evasion', 'Spying', 'Internet', 'Anti-Debugging', 'Ransomware', 'Helper'][i - 1]
        archivo_salida = f'fun{i}_{categoria}.json'
        with open(archivo_salida, 'w', encoding='utf-8') as f_salida:
            json.dump(lista_funciones, f_salida, indent=4)

        print(f"Las funciones extraídas de '{archivo}' se han guardado en '{archivo_salida}'")

def cargar_funciones(archivo):
    """Carga las funciones desde un archivo JSON."""
    with open(archivo, 'r', encoding='utf-8') as f:
        return json.load(f)

def combinar_funciones_por_categoria():
    """Combina las funciones de los archivos en un diccionario organizado por categorías."""
    categorias = {}

    archivos = glob.glob('fun*_*.json')  # Busca archivos JSON que comienzan con 'fun'
    for archivo in archivos:
        # Obtener el nombre de la categoría a partir del nombre del archivo
        nombre_categoria = os.path.splitext(os.path.basename(archivo))[0]  # 'fun1_Enumeration'
        _, categoria = nombre_categoria.split('_', 1)  # Separar en 'fun1' y 'Enumeration'
        
        funciones = cargar_funciones(archivo)
        
        # Agregar la lista de funciones a las categorías
        categorias[categoria] = funciones

    return {"Categories": categorias}

def guardar_en_json(data, archivo_salida):
    """Guarda el diccionario combinado en un archivo JSON."""
    with open(archivo_salida, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4)

def main():
    url = 'https://malapi.io'  # Cambia esta URL si es necesario

    # 1. Extraer tablas
    extraer_tablas(url)

    # 2. Procesar tablas para extraer funciones
    procesar_tablas()

    # 3. Combinar funciones por categoría
    resultado = combinar_funciones_por_categoria()

    # 4. Guardar el resultado final en un archivo JSON
    guardar_en_json(resultado, 'malapi.json')

    print(f"Funciones combinadas y guardadas en 'malapi.json'")

if __name__ == "__main__":
    main()