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
    Soporta patrones definidos con la clave 'patron' o 'regex'.
    """
    ruta_patrones = Path(directorio_patrones)
    if not ruta_patrones.exists():
        print(texto_coloreado(f"ERROR: Carpeta de patrones inexistente: {ruta_patrones}", Colores['FALLO']))
        return False

    archivos = [archivo for archivo in ruta_patrones.glob("*.json") if archivo.name.lower() != 'config.json']

    if not archivos:
        print(texto_coloreado(f"ERROR: No se encontraron archivos JSON de patrones en {ruta_patrones}", Colores['FALLO']))
        return False

    total_cargados = 0
    errores_carga = 0
    
    for archivo in archivos:
        try:
            with open(archivo, 'r', encoding='utf-8') as f:
                datos_archivo = json.load(f)
        except Exception as e:
            mensaje_error = f"ERROR cargando archivo {archivo.name}: {e}"
            print(texto_coloreado(mensaje_error, Colores['FALLO']))
            registrar_log(mensaje_error, False, "ERROR")
            errores_carga += 1
            continue

        for clave_regla, patron in datos_archivo.items():
            if clave_regla.startswith("_METADATA_"):
                ESTADO_PATRONES['metadatos'][clave_regla] = patron
                continue

            # 1. VALIDACIÓN y OBTENCIÓN del patrón crudo (SOPORTE para 'patron' y 'regex')
            if not patron.get("activo", False):
                continue
                
            # 🔑 CAMBIO CLAVE: Prioriza 'patron', pero acepta 'regex' como alternativa.
            patron_crudo = patron.get("patron") or patron.get("regex")
            
            if not patron_crudo:
                mensaje_error = f"ADVERTENCIA: Regla {clave_regla} en {archivo.name} no tiene clave 'patron' ni 'regex'."
                print(texto_coloreado(mensaje_error, Colores['ADVERTENCIA']))
                errores_carga += 1
                continue

            try:
                # 2. COMPILACIÓN DE REGEX
                expresion = re.compile(patron_crudo, re.IGNORECASE)
                
                # 3. CREACIÓN DEL OBJETO DE PATRÓN FINAL
                patron_completo = {
                    "clave": clave_regla,
                    "regex": expresion,  # OBJETO COMPILADO (el que usa el escáner)
                    **patron
                }
                
                # Aseguramos que la clave 'patron' tenga la cadena cruda si solo vino como 'regex'
                if 'patron' not in patron_completo:
                    patron_completo['patron'] = patron_crudo 

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

    print(texto_coloreado(f"✅ Patrones cargados: {total_cargados} (sensibles: {len(ESTADO_PATRONES['sensibles'])}, informativos: {len(ESTADO_PATRONES['informativos'])})", Colores['VERDE_OK']))
    if errores_carga > 0:
        print(texto_coloreado(f"⚠️ Atención: {errores_carga} errores de carga/compilación fueron registrados.", Colores['ADVERTENCIA']))
        
    return total_cargados > 0