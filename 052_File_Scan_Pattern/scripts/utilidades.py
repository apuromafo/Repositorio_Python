
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

"""
utilidades.py - Versión 1.0.2
Funciones auxiliares: carga de sugerencias, formato e impresión de hallazgos.
Ajustado para mostrar el 'Match Contexto' dedupado y la descripción con conteo.
"""

import json
from pathlib import Path
from .logger_manager import texto_coloreado, Colores

print("\n[!] AVISO LEGAL: Use solo con autorizacion. / LEGAL NOTICE: Authorized use only.\n")


__version__ = "1.0.2"

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
    Ajustado para incluir Match Contexto (dato sensible puro) y el conteo en la descripción.
    Entrada: diccionario hallazgo y número.  
    Salida: cadena formateada multilinea.
    """
    lineas = [
        f"Hallazgo [{contador}]",
        # AGREGADO: Mostrar el dato sensible puro
        f"Match Contexto: {hallazgo.get('match_contexto', 'N/A')}", 
        f"Línea: {hallazgo['lineanum']} - Contenido (Snippet): {hallazgo['lineacontenido'][:100]}", # Se ajustó el texto a "Snippet"
        f"Regla: {hallazgo['clave']} (ID: {hallazgo.get('id_regla', 'N/A')})",
        f"Categoría: {hallazgo.get('categoria', 'N/A')}",
        # La descripción ya trae el conteo inyectado desde escaneo.py
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
    Ajustado para incluir Match Contexto (dato sensible puro) y el conteo en la descripción.
    Entrada: dict hallazgo y número.  
    Salida: None (impresión).
    """
    color = Colores['FALLO'] if hallazgo.get('es_sensible', False) else Colores['AZUL_OK']
    print(texto_coloreado(f"Hallazgo [{contador}]", color))
    
    # AGREGADO: Mostrar el dato sensible/match puro (que ya no es el contexto largo)
    if hallazgo.get('match_contexto'):
        print(texto_coloreado(f"Match Contexto: {hallazgo['match_contexto']}", Colores['NEGRITA'])) # Se añade negrita para destacarlo
        
    print(f"Línea: {hallazgo['lineanum']} - Contenido (Snippet): {hallazgo['lineacontenido'][:100]}") # Se ajustó el texto a "Snippet"
    print(texto_coloreado(f"Regla: {hallazgo['clave']} (ID: {hallazgo.get('id_regla', 'N/A')})", color))
    if hallazgo.get('categoria'):
        print(f"Categoría: {hallazgo['categoria']}")
        
    # La descripción ya incluye el conteo (ej. "Email address (Encontrado 5 veces)")
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