# gen_exporter.py

import json
import csv
import os # <-- NUEVO
from typing import List, Dict, Any
from datetime import date

# =================================================================
# 1. FUNCIONES DE EXPORTACIÓN A ARCHIVO
# =================================================================

def export_to_json(data_list: List[Dict[str, Any]], filename_prefix: str = "data_export", output_folder: str = "") -> str:
    """
    Exporta una lista de diccionarios a un archivo JSON.

    Args:
        data_list: La lista de diccionarios a exportar.
        filename_prefix: Prefijo del nombre del archivo.
        output_folder: Carpeta donde se guardará el archivo (e.g., 'output').

    Returns:
        Mensaje de éxito o error.
    """
    # Crear un nombre de archivo único con fecha
    today_str = date.today().strftime("%Y%m%d")
    filename = f"{filename_prefix}_{today_str}.json"
    
    # Construir la ruta completa
    full_path = os.path.join(output_folder, filename)

    try:
        with open(full_path, 'w', encoding='utf-8') as f:
            # Usar indentación para que el JSON sea legible
            json.dump(data_list, f, ensure_ascii=False, indent=4)
        return f"✅ Archivo JSON creado con éxito en: {full_path}"
    except Exception as e:
        return f"❌ Error al escribir el archivo JSON en {full_path}: {e}"

def flatten_dict(d: Dict[str, Any], parent_key: str = '', sep: str = '_') -> Dict[str, Any]:
    """
    Función auxiliar para aplanar diccionarios anidados (necesario para CSV).
    Convierte {'detalle': {'comuna': 'Santiado'}} en {'detalle_comuna': 'Santiago'}.
    """
    items = []
    for k, v in d.items():
        new_key = parent_key + sep + k if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        elif isinstance(v, list):
             # Simplemente unirse si es una lista de valores simples
             items.append((new_key, "; ".join(map(str, v)) if all(not isinstance(i, dict) for i in v) else str(v)))
        else:
            items.append((new_key, v))
    return dict(items)

def export_to_csv(data_list: List[Dict[str, Any]], filename_prefix: str = "data_export", output_folder: str = "") -> str:
    """
    Exporta una lista de diccionarios a un archivo CSV.

    Args:
        data_list: La lista de diccionarios a exportar.
        filename_prefix: Prefijo del nombre del archivo.
        output_folder: Carpeta donde se guardará el archivo (e.g., 'output').

    Returns:
        Mensaje de éxito o error.
    """
    if not data_list:
        return "⚠️ La lista de datos está vacía. No se creó el archivo CSV."

    # Aplanar todos los diccionarios primero
    flat_data = [flatten_dict(record) for record in data_list]

    # Obtener todos los nombres de las columnas (headers)
    fieldnames = set()
    for row in flat_data:
        fieldnames.update(row.keys())
    
    sorted_fieldnames = sorted(list(fieldnames)) # Ordenar para consistencia

    today_str = date.today().strftime("%Y%m%d")
    filename = f"{filename_prefix}_{today_str}.csv"
    
    # Construir la ruta completa
    full_path = os.path.join(output_folder, filename)
    
    try:
        with open(full_path, 'w', newline='', encoding='utf-8') as csvfile:
            # Usar ';' como delimitador ya que la "," es común en español
            writer = csv.DictWriter(csvfile, fieldnames=sorted_fieldnames, delimiter=';') 
            writer.writeheader()
            writer.writerows(flat_data)
            
        return f"✅ Archivo CSV creado con éxito en: {full_path}"
    except Exception as e:
        return f"❌ Error al escribir el archivo CSV en {full_path}: {e}"