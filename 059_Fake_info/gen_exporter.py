# gen_exporter.py (v4.1.1 - Soporte TXT Añadido)

import json
import csv
import os
from typing import List, Dict, Any
from datetime import date

# =================================================================
# 1. FUNCIONES DE EXPORTACIÓN A ARCHIVO
# =================================================================

def export_to_json(data_list: List[Dict[str, Any]], filename_prefix: str = "data_export", output_folder: str = "") -> str:
    """
    Exporta una lista de diccionarios a un archivo JSON.
    """
    today_str = date.today().strftime("%Y%m%d")
    filename = f"{filename_prefix}_{today_str}.json"
    full_path = os.path.join(output_folder, filename)

    try:
        with open(full_path, 'w', encoding='utf-8') as f:
            json.dump(data_list, f, ensure_ascii=False, indent=4)
        return f"✅ Archivo JSON creado con éxito en: {full_path}"
    except Exception as e:
        return f"❌ Error al escribir el archivo JSON en {full_path}: {e}"

def flatten_dict(d: Dict[str, Any], parent_key: str = '', sep: str = '_') -> Dict[str, Any]:
    """
    Función auxiliar para aplanar diccionarios anidados.
    Mejorada para manejar listas de diccionarios de forma segura.
    """
    items = []
    for k, v in d.items():
        new_key = parent_key + sep + k if parent_key else k
        
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
            
        elif isinstance(v, list):
            if all(not isinstance(i, dict) for i in v):
                # Lista de valores simples: unir con ';'
                items.append((new_key, "; ".join(map(str, v))))
            else:
                # Lista de diccionarios o compleja: guardar como cadena JSON
                try:
                    items.append((new_key, json.dumps(v, ensure_ascii=False)))
                except TypeError:
                    items.append((new_key, str(v)))
                    
        else:
            items.append((new_key, v))
            
    return dict(items)

def export_to_csv(data_list: List[Dict[str, Any]], filename_prefix: str = "data_export", output_folder: str = "") -> str:
    """
    Exporta una lista de diccionarios a un archivo CSV.
    """
    if not data_list:
        return "⚠️ La lista de datos está vacía. No se creó el archivo CSV."

    flat_data = [flatten_dict(record) for record in data_list]

    fieldnames = set()
    for row in flat_data:
        fieldnames.update(row.keys())
    
    sorted_fieldnames = sorted(list(fieldnames)) # Ordenar para consistencia

    today_str = date.today().strftime("%Y%m%d")
    filename = f"{filename_prefix}_{today_str}.csv"
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

def export_to_txt(data_list: List[Dict[str, Any]], filename_prefix: str = "data_export", output_folder: str = "") -> str:
    """
    Exporta una lista de diccionarios a un archivo TXT de texto plano.
    Cada registro se convierte a una línea de texto simple (JSON en una línea).
    """
    if not data_list:
        return "⚠️ La lista de datos está vacía. No se creó el archivo TXT."

    today_str = date.today().strftime("%Y%m%d")
    filename = f"{filename_prefix}_{today_str}.txt"
    full_path = os.path.join(output_folder, filename)

    try:
        with open(full_path, 'w', encoding='utf-8') as f:
            for record in data_list:
                # Convertir cada registro a JSON en una sola línea y escribirlo.
                # Esto es la forma más limpia de exportar un registro complejo a TXT.
                line = json.dumps(record, ensure_ascii=False)
                f.write(line + '\n')
                
        return f"✅ Archivo TXT creado con éxito en: {full_path} (JSON por línea)"
    except Exception as e:
        return f"❌ Error al escribir el archivo TXT en {full_path}: {e}"