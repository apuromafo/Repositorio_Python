"""
escaneo.py - Versión 1.9.10 (Configuración de Snippet Interna)

Cambios:
1.  **NUEVA CONFIGURACIÓN INTERNA:** Se añade la variable global MOSTRAR_SNIPPETS en la sección 
    de configuración lógica para controlar la visibilidad del snippet.
2.  **IMPRESIÓN MODIFICADA:** Las funciones de impresión leen la variable global 
    MOSTRAR_SNIPPETS para decidir si imprimen o no el contexto (snippet).
"""

import time
import os
import re
from pathlib import Path
from typing import Dict, List, Any
# Dependencias de módulos locales
from .logger_manager import registrar_log, actualizar_estadistica, registrar_hallazgo_por_archivo, vaciar_buffer_hallazgos, Colores, texto_coloreado
from .utilidades import mostrar_recomendaciones_binario, formatear_texto_hallazgo
from .metadatos import obtener_metadatos_archivo

__version__ = "1.9.10" 

# =========================================================================
# ⚙️ CONFIGURACIÓN LÓGICA
# =========================================================================

# Longitud del contexto a mostrar antes y después del match.
CONTEXT_LEN = 45
MODO_REPORTE_CONSOLIDADO_ESTRICTO = True 
UMBRAL_DETECCION_BINARIA_DEFAULT = 0.05 

# 📢 NUEVA CONFIGURACIÓN: Controla si se imprimen los snippets de contexto en la Evidencia Consolidada.
# Cámbialo a 'False' si quieres un reporte más conciso.
MOSTRAR_SNIPPETS = True

# =========================================================================
# 🛠️ FUNCIONES DE UTILIDAD DEL ESCANEO Y REPORTE
# =========================================================================

def es_archivo_binario(ruta_archivo: Path, umbral: float) -> bool:
    """Detecta archivos binarios por su densidad de bytes nulos."""
    # ... (código se mantiene igual) ...
    try:
        with open(ruta_archivo, 'rb') as f:
            bloque = f.read(8192)
            if not bloque:
                return False
            count_nulos = bloque.count(b'\x00')
            return (count_nulos / len(bloque)) > umbral
    except Exception:
        return False

def normalizar_hallazgo_informativo(texto: str) -> str:
    """
    Normaliza un texto (endpoint o URL) para crear una clave de agrupación semántica.
    """
    # ... (código se mantiene igual) ...
    normalized = texto.strip('\'"')
    normalized = re.sub(r'^https?://', '', normalized, 1) 
    normalized = normalized.rstrip('/')
    if normalized.startswith('/') and len(normalized) > 1:
        normalized = normalized.lstrip('/')
        
    return normalized or texto 

def highlight_snippet(snippet: str, match_text: str, match_color: str = Colores['FALLO']) -> str:
    """
    Resalta el texto del match dentro del snippet con contexto.
    """
    # ... (código se mantiene igual) ...
    if not snippet or not match_text:
        return snippet

    try:
        # Encontrar el índice relativo del match dentro del snippet
        relative_start = snippet.index(match_text) 
        relative_end = relative_start + len(match_text)
        
        pre = snippet[:relative_start]
        
        bold_and_color_code = Colores['NEGRITA'] + match_color
        match_text_to_highlight = snippet[relative_start:relative_end]
        
        match_highlighted = texto_coloreado(match_text_to_highlight, bold_and_color_code)
        
        post = snippet[relative_end:]
        
        return pre + match_highlighted + post
    except ValueError:
        # Fallback: reemplazar la primera ocurrencia del match_text en el snippet
        bold_and_color_code = Colores['NEGRITA'] + match_color
        match_highlighted_fallback = texto_coloreado(match_text, bold_and_color_code)
        return snippet.replace(match_text, match_highlighted_fallback, 1)


def imprimir_hallazgo_informativo_consolidado(hallazgo: dict, contador: int) -> None:
    """
    Imprime el detalle de un hallazgo informativo consolidado (URLs/Endpoints).
    """
    global MOSTRAR_SNIPPETS # 👈 Acceso a la variable global
    
    color = Colores['AZUL_OK']
    print(texto_coloreado(f"Hallazgo [{contador}]", color))
    
    # 1. Imprimir la Evidencia Consolidada (TODAS LAS RAMAS)
    if hallazgo.get('evidencia_consolidada'):
        print(texto_coloreado(f"Evidencia Consolidada ({hallazgo['evidencia_total_grupos']} Ramas):", Colores['CIAN_OK']))
        
        for i, evid in enumerate(hallazgo['evidencia_consolidada'], 1): 
            lineas_str = ', '.join(map(str, evid['lineas']))
            match_color = Colores['CIAN_OK'] # Usar color informativo
            
            # Línea de Match, Conteo y Líneas
            print(f"Rama [{i}] Match: \"{evid['contexto']}\" (Encontrado {evid['conteo']} veces) [Líneas: {lineas_str}]")
            
            # 🚨 LÓGICA CONDICIONAL DE SNIPPET 🚨
            if MOSTRAR_SNIPPETS:
                snippet_resaltado = highlight_snippet(evid.get('lineacontenido', ''), evid.get('match_contexto', ''), match_color)
                print(f"Contenido (Snippet): {snippet_resaltado}")

    # 2. Imprimir el resto de los metadatos de la regla
    print(texto_coloreado(f"Regla: {hallazgo['clave']} (ID: {hallazgo.get('id_regla', 'N/A')})", color))
    # ... (resto del código se mantiene igual) ...
    if hallazgo.get('categoria'):
        print(f"Categoría: {hallazgo['categoria']}")
    print(f"Descripción: {hallazgo.get('descripcion', 'N/A')}")
    print(f"CWE: {hallazgo.get('cwe', 'N/A')}")
    print(f"OWASP: {hallazgo.get('owasp', 'N/A')}")
    if hallazgo.get('mitigacion'):
        print(f"Mitigación: {hallazgo['mitigacion']}")
    
    if hallazgo.get('url_mitigacion'):
        urls = [url.strip() for url in hallazgo['url_mitigacion'].split('|')]
        if urls:
            print("Referencias:")
            for url in urls:
                print(f"  - {url.strip()}")
                
    print('-'*70)

def imprimir_hallazgo_sensible_consolidado(hallazgo: dict, contador: int) -> None:
    """
    Imprime el detalle de un hallazgo sensible consolidado (agrupado por Regla ID).
    """
    global MOSTRAR_SNIPPETS # 👈 Acceso a la variable global
    
    color = Colores['FALLO'] 
    print(texto_coloreado(f"Hallazgo [{contador}]", color))
    
    # 1. Imprimir la Evidencia Consolidada (TODOS LOS DATOS ÚNICOS)
    if hallazgo.get('evidencia_consolidada'):
        print(texto_coloreado(f"Evidencia Consolidada ({hallazgo['evidencia_total_grupos']} Datos Únicos):", Colores['ADVERTENCIA']))
        
        for i, evid in enumerate(hallazgo['evidencia_consolidada'], 1): 
            lineas_str = ', '.join(map(str, evid['lineas']))
            match_color = Colores['FALLO'] # Usar color sensible
            
            # Línea de Match, Conteo y Líneas
            print(f"Dato Único [{i}] Match: \"{evid['contexto']}\" (Encontrado {evid['conteo']} veces) [Líneas: {lineas_str}]")
            
            # 🚨 LÓGICA CONDICIONAL DE SNIPPET 🚨
            if MOSTRAR_SNIPPETS:
                snippet_resaltado = highlight_snippet(evid.get('lineacontenido', ''), evid.get('match_contexto', ''), match_color)
                print(f"Contenido (Snippet): {snippet_resaltado}")
    
    # 2. Imprimir el resto de los metadatos de la regla
    print(texto_coloreado(f"Regla: {hallazgo['clave']} (ID: {hallazgo.get('id_regla', 'N/A')})", color))
    # ... (resto del código se mantiene igual) ...
    if hallazgo.get('categoria'):
        print(f"Categoría: {hallazgo['categoria']}")
    print(f"Descripción: {hallazgo.get('descripcion', 'N/A')}")
    print(f"CWE: {hallazgo.get('cwe', 'N/A')}")
    print(f"OWASP: {hallazgo.get('owasp', 'N/A')}")
    if hallazgo.get('mitigacion'):
        print(f"Mitigación: {hallazgo['mitigacion']}")
    
    if hallazgo.get('url_mitigacion'):
        urls = [url.strip() for url in hallazgo['url_mitigacion'].split('|')]
        if urls:
            print("Referencias:")
            for url in urls:
                print(f"  - {url.strip()}")
                
    print('-'*70)

# =========================================================================
# 🔎 FUNCIÓN PRINCIPAL DE ESCANEO
# =========================================================================

def escanear_archivo(
    ruta_archivo: Path,
    configuracion: Dict,
    patrones_sensibles: List[Dict],
    patrones_informativos: List[Dict],
    opciones: Dict[str, bool],
    sugerencias: Dict
) -> Dict[str, Any]:
    registrar_log(f"Procesando: {ruta_archivo}", False)

    # ... (Validaciones preliminares y metadatos se mantienen igual) ...
    try:
        if ruta_archivo.suffix.lower() in configuracion.get('scan_config', {}).get('extensiones_excluidas', []):
            actualizar_estadistica('archivos_omitidos')
            return {"archivo": str(ruta_archivo), "sensibles": 0, "informativos": 0, "tiempo": 0, "omitido": True, "metadatos": {}}
        # ... (rest of validations) ...
        umbral_binario = configuracion.get('scan_config', {}).get('umbral_deteccion_binaria', UMBRAL_DETECCION_BINARIA_DEFAULT)
        if es_archivo_binario(ruta_archivo, umbral_binario):
            mostrar_recomendaciones_binario(ruta_archivo, sugerencias)
            actualizar_estadistica('archivos_binarios')
            actualizar_estadistica('archivos_omitidos')
            return {"archivo": str(ruta_archivo), "sensibles": 0, "informativos": 0, "tiempo": 0, "omitido": True, "metadatos": {}}
    except Exception as e:
        registrar_log(f"ERROR verificando archivo {ruta_archivo}: {e}", True, "ERROR")
        actualizar_estadistica('errores')
        return {"archivo": str(ruta_archivo), "sensibles": 0, "informativos": 0, "tiempo": 0, "omitido": True, "metadatos": {}}

    metadatos = obtener_metadatos_archivo(ruta_archivo, sugerencias)
    print(texto_coloreado(f"\n🔎 Escaneando: {ruta_archivo}", Colores['AZUL_OK']))
    
    # ... (Estructuras de reporte, tiempos e iteración de línea se mantienen igual) ...

    # --- ESTRUCTURAS DE REPORTE ---
    hallazgos_sensibles_dedup: Dict[str, Dict[str, Any]] = {} 
    hallazgos_informativos_dedup: Dict[str, Dict[str, Any]] = {} 
    # -----------------------------

    tiempo_inicio = time.time()
    encoding = 'utf-8'
    total_raw_sensibles = 0 
    total_raw_informativos = 0 

    try:
        with open(ruta_archivo, 'r', encoding=encoding, errors='replace') as archivo:
            for num_linea, linea in enumerate(archivo, 1):
                actualizar_estadistica('lineas_analizadas')
                
                # Pre-procesar la línea a minúsculas una sola vez por línea
                linea_lower = linea.lower()
                
                patrones_a_escanear = []
                if opciones.get("sensibles", True):
                    patrones_a_escanear.extend(patrones_sensibles)
                if opciones.get("informativos", False):
                    patrones_a_escanear.extend(patrones_informativos)

                for patron in patrones_a_escanear:
                    
                    # --- Lógica de Exclusión (Negative Search) Mejorada para Case-Insensitive ---
                    if patron.get("negative_search"):
                        if any(neg_keyword.lower() in linea_lower for neg_keyword in patron["negative_search"]):
                            continue 
                    # --- Fin Lógica de Exclusión ---
                        
                    for match in patron['regex'].finditer(linea):
                        
                        texto_real_match = match.group(0).strip() 
                        clave_dedup_regla = str(patron['id_regla'])

                        # --- Captura de Contexto (Snippet) ---
                        full_line = linea
                        start_index = match.start()
                        end_index = match.end()
                        
                        snippet_start = max(0, start_index - CONTEXT_LEN)
                        snippet_end = min(len(full_line), end_index + CONTEXT_LEN)
                        
                        context_snippet_raw = full_line[snippet_start:snippet_end].strip()
                        # ---------------------------
                        
                        if patron.get("es_sensible", False):
                            # --- LÓGICA PII/SENSIBLE (Consolidación por ID de Regla) ---
                            actualizar_estadistica('hallazgos_sensibles')
                            total_raw_sensibles += 1 
                            
                            try:
                                # PII/Secreto único
                                texto_clave_dedup = match.group(1).strip()
                            except IndexError:
                                texto_clave_dedup = texto_real_match
                            
                            if clave_dedup_regla not in hallazgos_sensibles_dedup:
                                # V1.9.9: INCLUIR 'lineanum' y snippet principal para logging
                                hallazgo_consolidado = {
                                    **patron, 
                                    "lineanum": num_linea,                  
                                    "lineacontenido": context_snippet_raw,  
                                    "match_contexto": texto_real_match,     
                                    "es_sensible": True,
                                    "conteo": 0, 
                                    "consolidated_matches": {} 
                                }
                                hallazgos_sensibles_dedup[clave_dedup_regla] = hallazgo_consolidado
                            
                            hall = hallazgos_sensibles_dedup[clave_dedup_regla]
                            
                            # Almacenamiento de números de línea, conteo y SNIPPET INDIVIDUAL
                            if texto_clave_dedup not in hall['consolidated_matches']:
                                hall['consolidated_matches'][texto_clave_dedup] = {
                                    "first_match": texto_clave_dedup,
                                    "count": 0,
                                    "line_numbers": set(),
                                    "lineacontenido": context_snippet_raw, 
                                    "match_contexto": texto_real_match     
                                }
                                
                            hall['consolidated_matches'][texto_clave_dedup]["count"] += 1
                            hall['consolidated_matches'][texto_clave_dedup]["line_numbers"].add(num_linea)


                        else:
                            # --- LÓGICA INFORMATIVA (Consolidación por ID de Regla) ---
                            actualizar_estadistica('hallazgos_informativos')
                            total_raw_informativos += 1 
                            
                            texto_normalizado = normalizar_hallazgo_informativo(texto_real_match)
                            
                            if clave_dedup_regla not in hallazgos_informativos_dedup:
                                # V1.9.9: INCLUIR 'lineanum' y snippet principal para logging
                                hallazgo_consolidado = {
                                    **patron, 
                                    "lineanum": num_linea,                  
                                    "lineacontenido": context_snippet_raw,  
                                    "match_contexto": texto_real_match,     
                                    "es_sensible": False,
                                    "conteo": 0, 
                                    "consolidated_matches": {} 
                                }
                                hallazgos_informativos_dedup[clave_dedup_regla] = hallazgo_consolidado
                            
                            hall = hallazgos_informativos_dedup[clave_dedup_regla]
                            
                            # Almacenamiento de números de línea, conteo y SNIPPET INDIVIDUAL
                            if texto_normalizado not in hall['consolidated_matches']:
                                hall['consolidated_matches'][texto_normalizado] = {
                                    "first_match": texto_real_match,
                                    "count": 0,
                                    "line_numbers": set(),
                                    "lineacontenido": context_snippet_raw, 
                                    "match_contexto": texto_real_match     
                                }
                                
                            hall['consolidated_matches'][texto_normalizado]["count"] += 1
                            hall['consolidated_matches'][texto_normalizado]["line_numbers"].add(num_linea)


    except Exception as e:
        mensaje_error = f"ERROR escaneando {ruta_archivo}: {e}"
        print(texto_coloreado(mensaje_error, Colores['FALLO']))
        registrar_log(mensaje_error, False, "ERROR")
        actualizar_estadistica('errores')

    # ... (Post-procesamiento e inyección de conteos se mantienen igual) ...
    
    duracion = time.time() - tiempo_inicio
    actualizar_estadistica('archivos_procesados')

    # 1. Sensibles
    hallazgos_sensibles_final = list(hallazgos_sensibles_dedup.values())
    total_sensibles_contados_raw = total_raw_sensibles

    for hall in hallazgos_sensibles_final:
        total_conteo_regla = sum(item['count'] for item in hall['consolidated_matches'].values())
        hall['conteo'] = total_conteo_regla 

        evidencia_list = []
        for unique_pii_key, data in hall['consolidated_matches'].items():
            evidencia_list.append({
                "contexto": unique_pii_key, 
                "conteo": data['count'],
                "normalized_key": unique_pii_key,
                "lineas": sorted(list(data['line_numbers'])), 
                "lineacontenido": data['lineacontenido'], 
                "match_contexto": data['match_contexto'] 
            })
            
        evidencia_list.sort(key=lambda x: x['conteo'], reverse=True)
        
        hall['evidencia_consolidada'] = evidencia_list 
        hall['evidencia_total_grupos'] = len(evidencia_list)
        
        hall['descripcion'] = f"{hall['descripcion']} (Consolidado de {hall['evidencia_total_grupos']} datos PII/Secretos únicos, total {total_conteo_regla} matches)."


    # 2. Informativos
    hallazgos_informativos_final = list(hallazgos_informativos_dedup.values())
    total_informativos_contados_raw = total_raw_informativos

    for hall in hallazgos_informativos_final:
        total_conteo_regla = sum(item['count'] for item in hall['consolidated_matches'].values())
        hall['conteo'] = total_conteo_regla 
        
        evidencia_list = []
        for normalized_key, data in hall['consolidated_matches'].items():
            evidencia_list.append({
                "contexto": data['first_match'],
                "conteo": data['count'],
                "normalized_key": normalized_key,
                "lineas": sorted(list(data['line_numbers'])), 
                "lineacontenido": data['lineacontenido'], 
                "match_contexto": data['match_contexto'] 
            })
            
        evidencia_list.sort(key=lambda x: x['conteo'], reverse=True)
        
        hall['evidencia_consolidada'] = evidencia_list 
        hall['evidencia_total_grupos'] = len(evidencia_list)
        
        hall['descripcion'] = f"{hall['descripcion']} (Consolidado de {hall['evidencia_total_grupos']} grupos de endpoints, total {total_conteo_regla} matches)."


    # --- CRITERIO DE ORDENACIÓN ---
    hallazgos_todos_final = hallazgos_sensibles_final + hallazgos_informativos_final
    hallazgos_todos_final.sort(key=lambda h: (
        not h.get('es_sensible', False), 
        h.get('categoria', ''), 
        h.get('clave', '')
    ))
    # --- FIN CRITERIO DE ORDENACIÓN ---

    # --- IMPRESIÓN ---
    numero_hallazgo = 1
    if hallazgos_todos_final:
        print(texto_coloreado("\n===== HALLAZGOS =====", Colores['NEGRITA']))
        
        sensibles_imprimir = [h for h in hallazgos_todos_final if h.get('es_sensible', False)]
        informativos_imprimir = [h for h in hallazgos_todos_final if not h.get('es_sensible', False)]
        
        if sensibles_imprimir:
            print(texto_coloreado("\n--- Hallazgos Sensibles (PII/Secretos - CONSOLIDADO TOTAL POR REGLA) ---", Colores['FALLO']))
            for hall in sensibles_imprimir:
                # 📢 La opción MOSTRAR_SNIPPETS ya es global, no se pasa aquí
                imprimir_hallazgo_sensible_consolidado(hall, numero_hallazgo) 
                registrar_hallazgo_por_archivo(ruta_archivo.name, formatear_texto_hallazgo(hall, numero_hallazgo), tipo="sensibles")
                numero_hallazgo += 1

        if informativos_imprimir:
            print(texto_coloreado("\n--- Hallazgos Informativos (URLs/Endpoints - CONSOLIDADO TOTAL POR REGLA) ---", Colores['AZUL_OK']))
            for hall in informativos_imprimir:
                # 📢 La opción MOSTRAR_SNIPPETS ya es global, no se pasa aquí
                imprimir_hallazgo_informativo_consolidado(hall, numero_hallazgo) 
                registrar_hallazgo_por_archivo(ruta_archivo.name, formatear_texto_hallazgo(hall, numero_hallazgo), tipo="informativos") 
                numero_hallazgo += 1

    print(texto_coloreado(f"\n✅ Escaneo completado en {duracion:.2f} segundos\n", Colores['VERDE_OK']))
    vaciar_buffer_hallazgos()

    return {
        "archivo": str(ruta_archivo),
        "sensibles": total_sensibles_contados_raw, 
        "informativos": total_informativos_contados_raw, 
        "tiempo": duracion,
        "omitido": False,
        "metadatos": metadatos
    }

# =========================================================================
# 🗂️ ESCANEO DE CARPETAS Y RESUMEN (Funciones auxiliares, se mantienen igual)
# =========================================================================
# ... (código auxiliar se mantiene igual) ...

def escanear_carpeta(
    ruta_carpeta: Path,
    configuracion: Dict,
    patrones_sensibles: List[Dict],
    patrones_informativos: List[Dict],
    opciones: Dict[str, bool],
    sugerencias: Dict
) -> List[Dict]:
    """
    Escanea recursivamente una carpeta y retorna un resumen consolidado.
    """
    archivos = [
        archivo for archivo in ruta_carpeta.rglob('*') 
        if archivo.is_file() and not archivo.name.startswith('.') and not os.path.islink(archivo)
    ]
    
    resumenes = []
    total_archivos = len(archivos)
    if total_archivos == 0:
        print(texto_coloreado("No se encontraron archivos.", Colores['ADVERTENCIA']))
        return []

    print(texto_coloreado(f"\n📁 Escaneando carpeta recursiva: {ruta_carpeta}", Colores['AZUL_OK']))
    print(texto_coloreado(f"Archivos encontrados: {total_archivos}", Colores['CIAN_OK']))
    
    for indice, archivo in enumerate(archivos, 1):
        if configuracion.get('salida', {}).get('mostrar_progreso', True):
            print(texto_coloreado(f"\n[{indice}/{total_archivos}] Procesando: {archivo}", Colores['CIAN_OK']))
        resumen = escanear_archivo(archivo, configuracion, patrones_sensibles, patrones_informativos, opciones, sugerencias)
        resumenes.append(resumen)

    return resumenes

def imprimir_resumen_tabla(resumenes: List[Dict]) -> None:
    """
    Imprime una tabla consolidada de resultados de escaneo.
    """
    from .logger_manager import ESTADO_LOGGER
    estadisticas = ESTADO_LOGGER.get('estadisticas', {})

    print(texto_coloreado("\n" + "="*90, Colores['NEGRITA']))
    print(texto_coloreado("📊 TABLA RESUMEN CONSOLIDADO DE HALLAZGOS", Colores['NEGRITA']))
    print(texto_coloreado("="*90, Colores['NEGRITA']))
    
    print(f"{'ARCHIVO':<60} {'SENSIBLES':>8} {'INFORMATIVOS':>12} {'TIEMPO(s)':>12}")
    print("-"*90)

    total_sensibles = 0
    total_informativos = 0
    total_tiempo = 0.0

    for item in resumenes:
        if not item.get('omitido', False):
            print(f"{item['archivo']:<60} {item['sensibles']:>8} {item['informativos']:>12} {item['tiempo']:>12.2f}")
            total_sensibles += item['sensibles']
            total_informativos += item['informativos']
            total_tiempo += item['tiempo']

    print("-"*90)
    print(f"{'TOTALES':<60} {total_sensibles:>8} {total_informativos:>12} {total_tiempo:>12.2f}s")
    print("-"*90)
    
    print(texto_coloreado("\n📈 ESTADÍSTICAS DEL ESCANEO", Colores['NEGRITA']))
    print("-"*90)
    print(f"Archivos procesados:      {estadisticas.get('archivos_procesados', 0)}")
    print(f"Archivos omitidos:        {estadisticas.get('archivos_omitidos', 0)}")
    print(f"  - Binarios:             {estadisticas.get('archivos_binarios', 0)}")
    print(f"  - Tamaño excedido:      {estadisticas.get('archivos_grandes', 0)}")
    print(f"Líneas analizadas:        {estadisticas.get('lineas_analizadas', 0):,}")
    print(f"Hallazgos sensibles:      {estadisticas.get('hallazgos_sensibles', 0)}")
    print(f"Hallazgos informativos:   {estadisticas.get('hallazgos_informativos', 0)}")
    print(f"Errores encontrados:      {estadisticas.get('errores', 0)}")
    print(f"Tiempo total:             {total_tiempo:.2f}s")
    print("-"*90 + "\n")