"""
patrones.py - Versión 1.1.3
Carga y compilación de patrones, sin impresión de metadatos, con manejo robusto de errores.
"""

import json
import re
from pathlib import Path
from typing import List, Dict, Any
from .logger_manager import registrar_log, Colores, texto_coloreado

__version__ = "1.1.3"

ESTADO_PATRONES: Dict[str, Any] = {
    'sensibles': [],
    'informativos': [],
    'compilados': [],
    'metadatos': {}
}

def cargar_todos_los_patrones(directorio_patrones: str, configuracion: Dict) -> bool:
    """
    Carga y compila patrones desde archivos JSON, ignorando config.json.  
    Entrada: ruta carpeta patrones, configuración.  
    Salida: True si carga al menos un patrón; False si fallo crítico.
    """
    ruta_patrones = Path(directorio_patrones)
    if not ruta_patrones.exists():
        print(texto_coloreado(f"ERROR: Carpeta de patrones inexistente: {ruta_patrones}", Colores['FALLO']))
        return False

    archivos = [archivo for archivo in ruta_patrones.glob("*.json") if archivo.name.lower() != 'config.json']

    if not archivos:
        print(texto_coloreado(f"ERROR: No se encontraron archivos JSON válidos en {ruta_patrones}", Colores['FALLO']))
        return False

    print(texto_coloreado(f"📂 Cargando patrones desde: {ruta_patrones}", Colores['CIAN_OK']))
    total_cargados = 0
    errores_carga = 0
    
    ESTADO_PATRONES['sensibles'].clear()
    ESTADO_PATRONES['informativos'].clear()
    ESTADO_PATRONES['compilados'].clear()
    ESTADO_PATRONES['metadatos'].clear()

    for archivo in archivos:
        try:
            with open(archivo, 'r', encoding='utf-8') as f:
                datos = json.load(f)
            for clave in list(datos.keys()):
                if clave.lower().startswith("_metadata"):
                    ESTADO_PATRONES['metadatos'] = datos.pop(clave, {})
                    # No imprimir metadatos para salida limpia
                    break

            for clave_regla, patron in datos.items():
                if not patron.get("activo", False):
                    continue
                try:
                    expresion = re.compile(patron["patron"])
                    patron_completo = {
                        "clave": clave_regla,
                        "regex": expresion,
                        **patron
                    }
                    if patron.get("es_sensible", False):
                        ESTADO_PATRONES['sensibles'].append(patron_completo)
                    else:
                        ESTADO_PATRONES['informativos'].append(patron_completo)
                    ESTADO_PATRONES['compilados'].append(patron_completo)
                    total_cargados += 1
                except re.error as e:
                    mensaje_error = f"ERROR compilando regex en {clave_regla} del archivo {archivo.name}: {e}"
                    print(texto_coloreado(mensaje_error, Colores['FALLO']))
                    registrar_log(mensaje_error, False, "ERROR")
                    errores_carga += 1
        except Exception as e:
            mensaje_error = f"ERROR cargando archivo {archivo.name}: {e}"
            print(texto_coloreado(mensaje_error, Colores['FALLO']))
            registrar_log(mensaje_error, False, "ERROR")
            errores_carga += 1

    print(texto_coloreado(f"✅ Patrones cargados: {total_cargados} (sensibles: {len(ESTADO_PATRONES['sensibles'])}, informativos: {len(ESTADO_PATRONES['informativos'])})", Colores['VERDE_OK']))
    if errores_carga > 0:
        print(texto_coloreado(f"⚠️ Errores durante carga: {errores_carga}", Colores['ADVERTENCIA']))

    return total_cargados > 0
