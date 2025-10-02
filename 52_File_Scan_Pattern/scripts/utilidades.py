"""
utilidades.py - Versión 1.0.1
Funciones auxiliares: carga de sugerencias, formato e impresión de hallazgos.
"""

import json
from pathlib import Path
from .logger_manager import texto_coloreado, Colores


__version__ = "1.0.1"

def cargar_sugerencias(ruta_sugerencias: str) -> dict:
    """
    Carga JSON de sugerencias para análisis binario u otras.  
    Entrada: ruta archivo JSON  
    Salida: diccionario con sugerencias o vacío si falla.
    """
    try:
        with open(ruta_sugerencias, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}

def mostrar_recomendaciones_binario(ruta_archivo: Path, sugerencias: dict) -> None:
    """
    Imprime recomendaciones para análisis de archivos binarios.  
    Entrada: Path archivo y diccionario sugerencias.  
    Salida: Ninguna, impresión directa.
    """
    print(texto_coloreado(f"\n⚠️ Archivo binario detectado: {ruta_archivo.name}", Colores['ADVERTENCIA']))
    print(texto_coloreado("→ Este archivo será omitido del análisis de patrones regex.", Colores['ADVERTENCIA']))
    
    herramientas = sugerencias.get('analisis_binario', {}).get('herramientas', [])
    if herramientas:
        print(texto_coloreado("\n🔧 Herramientas recomendadas para análisis de binarios:", Colores['CIAN_OK']))
        for herramienta in herramientas[:3]:
            print(f"  • {herramienta['nombre']}: {herramienta['uso']}")
            print(f"    Comando: {herramienta['comando']}")
        print()

def formatear_texto_hallazgo(hallazgo: dict, contador: int) -> str:
    """
    Formatea un hallazgo para escribirlo o mostrar.  
    Entrada: diccionario hallazgo y número.  
    Salida: cadena formateada multilinea.
    """
    lineas = [
        f"Hallazgo [{contador}]",
        f"Línea: {hallazgo['lineanum']} - Contenido: {hallazgo['lineacontenido'][:100]}",
        f"Regla: {hallazgo['clave']} (ID: {hallazgo.get('id_regla', 'N/A')})",
        f"Categoría: {hallazgo.get('categoria', 'N/A')}",
        f"Descripción: {hallazgo.get('descripcion', 'N/A')}",
        f"CWE: {hallazgo.get('cwe', 'N/A')}",
        f"OWASP: {hallazgo.get('owasp', 'N/A')}",
        f"Mitigación: {hallazgo.get('recomendacion_mitigacion', 'N/A')}"
    ]
    urls = []
    if hallazgo.get('url_hallazgo'):
        urls.extend(hallazgo['url_hallazgo'].split('|'))
    if hallazgo.get('url_mitigacion'):
        urls.extend(hallazgo['url_mitigacion'].split('|'))
    if urls:
        lineas.append("Referencias:")
        for url in urls:
            lineas.append(f"  - {url.strip()}")
    lineas.append('-'*70)
    return '\n'.join(lineas)

def imprimir_hallazgo(hallazgo: dict, contador: int) -> None:
    """
    Imprime el detalle de un hallazgo en consola con color.  
    Entrada: dict hallazgo y número.  
    Salida: None (impresión).
    """
    color = Colores['FALLO'] if hallazgo.get('es_sensible', False) else Colores['AZUL_OK']
    print(texto_coloreado(f"Hallazgo [{contador}]", color))
    print(f"Línea: {hallazgo['lineanum']} - Contenido: {hallazgo['lineacontenido'][:100]}")
    print(texto_coloreado(f"Regla: {hallazgo['clave']} (ID: {hallazgo.get('id_regla', 'N/A')})", color))
    if hallazgo.get('categoria'):
        print(f"Categoría: {hallazgo['categoria']}")
    print(f"Descripción: {hallazgo.get('descripcion', 'N/A')}")
    print(f"CWE: {hallazgo.get('cwe', 'N/A')}")
    print(f"OWASP: {hallazgo.get('owasp', 'N/A')}")
    print(f"Mitigación: {hallazgo.get('recomendacion_mitigacion', 'N/A')}")
    urls = []
    if hallazgo.get('url_hallazgo'):
        urls.extend(hallazgo['url_hallazgo'].split('|'))
    if hallazgo.get('url_mitigacion'):
        urls.extend(hallazgo['url_mitigacion'].split('|'))
    if urls:
        print("Referencias:")
        for url in urls:
            print(f"  - {url.strip()}")
    print(texto_coloreado('-'*70, Colores['CIAN_OK']))
