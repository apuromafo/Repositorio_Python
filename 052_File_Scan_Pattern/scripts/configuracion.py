"""
configuracion.py - Versión 1.0.0
Carga y gestión de la configuración con validación y control robusto.
"""

import json
from typing import Dict, Any

__version__ = "1.0.0"

def obtener_configuracion_por_defecto() -> Dict[str, Any]:
    """
    Retorna configuración por defecto anidada.
    Salida: diccionario con parámetros generales del escáner.
    """
    return {
        "version": "1.2",
        "scan_config": {
            "extensiones_excluidas": [".exe", ".dll", ".so", ".bin", ".obj", ".pyc"],
            "tamano_maximo_mb": 1500,
            "umbral_deteccion_binaria": 0.05,
            "timeout_por_archivo_segundos": 60
        },
        "rendimiento": {
            "tamano_buffer": 100,
            "multiprocesamiento": False,
            "max_trabajadores": 4
        },
        "salida": {
            "mostrar_progreso": True,
            "nivel_verbose": "INFO",
            "salida_coloreada": True
        },
        "rutas": {
            "directorio_patrones": "./Pattern",
            "archivo_sugerencias": "./Pattern/suggestions.json"
        }
    }

def cargar_configuracion_desde_archivo(ruta_configuracion: str) -> Dict[str, Any]:
    """
    Carga configuración desde JSON seguro.  
    Entrada: ruta archivo configuración.  
    Salida: diccionario configuración con valores por defecto si falla.  
    Valida tipos críticos y controla excepciones.
    """
    configuracion = obtener_configuracion_por_defecto()
    try:
        with open(ruta_configuracion, 'r', encoding='utf-8') as f:
            datos_archivo = json.load(f)
        if not isinstance(datos_archivo, dict):
            print("ERROR: El archivo de configuración raíz no es un diccionario. Usando configuración por defecto.")
            return configuracion
        
        for clave, valor in datos_archivo.items():
            if clave in configuracion and isinstance(configuracion[clave], dict) and isinstance(valor, dict):
                configuracion[clave].update(valor)
            else:
                configuracion[clave] = valor
        
        # Validaciones simples
        tam_buffer = configuracion.get('rendimiento', {}).get('tamano_buffer')
        if not isinstance(tam_buffer, int) or tam_buffer <= 0:
            print("⚠️ tamano_buffer inválido, usando valor por defecto 100")
            configuracion['rendimiento']['tamano_buffer'] = 100
        
        tam_max = configuracion.get('scan_config', {}).get('tamano_maximo_mb')
        if not isinstance(tam_max, (int, float)) or tam_max <= 0:
            print("⚠️ tamano_maximo_mb inválido, usando valor por defecto 1500")
            configuracion['scan_config']['tamano_maximo_mb'] = 1500

        return configuracion

    except FileNotFoundError:
        print(f"⚠️ No se encontró archivo configuración: {ruta_configuracion}. Usando por defecto.")
        return configuracion
    except Exception as e:
        print(f"❌ Error cargando configuración: {e}. Usando por defecto.")
        return configuracion
