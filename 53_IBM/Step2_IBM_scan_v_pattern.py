"""
Analizador de Seguridad para Reportes IBM RPG/CL/PF (v3.0 - Modular)
Descripción:
Script que extrae, analiza y reporta hallazgos de seguridad en
reportes de código RPG/CL/PF. Los patrones se cargan desde archivos JSON
para facilitar la modularidad y actualización.
"""

import re
import argparse
import os
import json
import sys
from pathlib import Path
from datetime import datetime
from collections import Counter
from typing import List, Dict, Any

# ======================================================================
#                        CONFIGURACIÓN Y UTILERÍAS
# ======================================================================

# Directorio para los reportes de salida.
DIRECTORIO_SALIDA = "resultados_analisis"
# Carpeta donde se encuentran los patrones JSON.
PATTERNS_DIR = "./Pattern" 

# Patrones para identificar archivos de código válidos.
PATRONES_INCLUIR = ['analisis_cl_', 'analisis_pf_', 'analisis_rpg_']
PATRONES_EXCLUIR = ['header_', 'security_findings_', 'readme', 'log_']

# Definición de colores simple para salida de consola
Colors = {
    'HEADER': '\033[95m', 'OKBLUE': '\033[94m', 'OKCYAN': '\033[96m',
    'OKGREEN': '\033[92m', 'WARNING': '\033[93m', 'FAIL': '\033[91m',
    'ENDC': '\033[0m', 'BOLD': '\033[1m'
}

def color_text(text: str, color: str) -> str:
    """Aplica color al texto si el output es una terminal."""
    if sys.stdout.isatty():
        return f"{color}{text}{Colors['ENDC']}"
    return text

def log(msg: str, is_error: bool, level: str = "INFO"):
    """Simulación simple de log para carga de patrones."""
    prefix = f"[{level}] "
    if is_error:
        print(color_text(prefix + msg, Colors['FAIL']))
    else:
        print(prefix + msg)

# Estado Global de Patrones
PATTERNS_STATE: Dict[str, Any] = {'sensibles': [], 'informativos': [], 'compilados': [], 'metadatos': {}}

# ======================================================================
#                        CARGA DE PATRONES JSON
# ======================================================================

def load_all_patterns(pattern_dir: str) -> bool:
    """
    Carga y compila todos los patrones de seguridad desde archivos JSON.
    """
    pattern_path = Path(pattern_dir)
    if not pattern_path.exists():
        print(color_text(f"ERROR: Carpeta de patrones no encontrada: {pattern_path}", Colors['FAIL']))
        return False
    archivos_patron = list(pattern_path.glob("*.json"))

    print(color_text(f"📂 Cargando patrones desde: {pattern_path}", Colors['OKCYAN']))
    total_patrones = 0
    errores_carga = 0
    
    # Limpiar estado previo
    PATTERNS_STATE['compilados'] = []
    PATTERNS_STATE['sensibles'] = []
    PATTERNS_STATE['informativos'] = []
    
    for archivo in archivos_patron:
        try:
            with open(archivo, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Extraer metadatos si existen
            data.pop("_METADATA_", {})
            
            for clave, patron in data.items():
                if not patron.get("activo", False):
                    continue
                try:
                    # re.compile utiliza el patrón tal como está (incluyendo (?i) para case-insensitive)
                    regex_compilado = re.compile(patron["patron"])
                    patron_completo = {
                        "clave": clave,
                        "regex": regex_compilado,
                        **patron # Incluye todos los metadatos (descripcion, cwe, owasp, etc.)
                    }
                    
                    PATTERNS_STATE['compilados'].append(patron_completo)
                    
                    if patron.get("es_sensible", False):
                        PATTERNS_STATE['sensibles'].append(patron_completo)
                    else:
                        PATTERNS_STATE['informativos'].append(patron_completo)
                    
                    total_patrones += 1
                except re.error as e:
                    log(f"ERROR compilando regex en {clave} de {archivo.name}: {e}", True, "ERROR")
                    errores_carga += 1
        except Exception as e:
            log(f"ERROR cargando archivo {archivo.name}: {e}", True, "ERROR")
            errores_carga += 1

    print(color_text(f"✅ Patrones cargados: {total_patrones} (sensibles: {len(PATTERNS_STATE['sensibles'])}, informativos: {len(PATTERNS_STATE['informativos'])})", Colors['OKGREEN']))
    return total_patrones > 0

# ======================================================================
#                      FUNCIONES AUXILIARES ORIGINALES
# ======================================================================

def extraer_archivo_original(nombre_reporte):
    """Extrae el nombre del archivo original desde el nombre del reporte."""
    try:
        base_name = os.path.splitext(nombre_reporte)[0]
        partes = base_name.split('_')
        for parte in reversed(partes):
            if '.' in parte and not re.search(r'\d{4}-\d{2}-\d{2}', parte):
                return parte
        return "archivo_no_identificado"
    except Exception:
        return "archivo_no_identificado"

def determinar_tipo_archivo_original(nombre_reporte):
    """Determina el tipo de archivo original (RPG, CL, PF) desde el nombre del reporte."""
    nombre_reporte = nombre_reporte.lower()
    if 'analisis_rpg_' in nombre_reporte:
        return 'RPG'
    elif 'analisis_cl_' in nombre_reporte:
        return 'CL'
    elif 'analisis_pf_' in nombre_reporte:
        return 'PF'
    else:
        return 'DESCONOCIDO'

def es_archivo_codigo_valido(nombre_archivo):
    """Determina si un archivo debe ser analizado por el scanner de seguridad."""
    nombre_archivo = nombre_archivo.lower()
    for patron_excluir in PATRONES_EXCLUIR:
        if patron_excluir in nombre_archivo:
            return False
    for patron_incluir in PATRONES_INCLUIR:
        if patron_incluir in nombre_archivo:
            return True
    return False

# ======================================================================
#                  FUNCIONES DE ANÁLISIS Y REPORTE REFRACTORIZADAS
# ======================================================================

def analizar_archivo_seguridad(ruta_archivo: str) -> List[Dict[str, Any]]:
    """
    Analiza un archivo de reporte buscando hallazgos de seguridad,
    utilizando los patrones cargados globalmente.
    """
    hallazgos = []
    nombre_archivo = os.path.basename(ruta_archivo)
    archivo_original = extraer_archivo_original(nombre_archivo)
    tipo_archivo = determinar_tipo_archivo_original(nombre_archivo)
    
    patrones_a_usar = PATTERNS_STATE['compilados'] # Usamos todos los patrones cargados

    try:
        with open(ruta_archivo, 'r', encoding='utf-8') as f:
            for num_linea, linea in enumerate(f, 1):
                linea_limpia = linea.strip()
                if not linea_limpia:
                    continue
                    
                for config in patrones_a_usar:
                    # Usamos la RegEx compilada
                    match = config['regex'].search(linea_limpia)
                    if match:
                        hallazgo = {
                            'archivo_reporte': nombre_archivo,
                            'archivo_original': archivo_original,
                            'tipo_archivo': tipo_archivo,
                            'ruta_completa': ruta_archivo,
                            'linea': num_linea,
                            'contenido': linea_limpia[:100] + ('...' if len(linea_limpia) > 100 else ''),
                            'patron': config['clave'],
                            'id_regla': config.get('id_regla', 'N/A'),
                            'descripcion': config['descripcion'],
                            'categoria': config['categoria'],
                            'cwe': config.get('cwe', 'N/A'),
                            'owasp': config.get('owasp', 'N/A'),
                            'es_sensible': config.get('es_sensible', False),
                            'match': match.group(0) # Captura el texto completo que coincide
                        }
                        hallazgos.append(hallazgo)
    except Exception as e:
        print(color_text(f"🚨 Error analizando {ruta_archivo}: {e}", Colors['FAIL']))
    
    return hallazgos

def generar_reporte_seguridad(hallazgos: List[Dict[str, Any]], ruta_salida: str) -> str or None:
    """
    Genera un reporte de hallazgos de seguridad en formato de texto.
    """
    if not os.path.exists(ruta_salida):
        try:
            os.makedirs(ruta_salida)
        except OSError as e:
            print(color_text(f"❌ Error al crear el directorio '{ruta_salida}': {e}", Colors['FAIL']))
            return None

    # Creamos un mapa de patrones por clave para buscar detalles en el resumen.
    patrones_map = {p['clave']: p for p in PATTERNS_STATE['compilados']}

    fecha_hora = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    nombre_reporte = os.path.join(ruta_salida, f"SECURITY_FINDINGS_{fecha_hora}.txt")
    
    # Ordenar hallazgos para el reporte de archivo
    hallazgos_ordenados = sorted(
        hallazgos, 
        key=lambda h: (h['archivo_original'], h['linea'])
    )

    with open(nombre_reporte, 'w', encoding='utf-8') as f:
        f.write("=" * 100 + "\n")
        f.write("     HALLAZGOS DE SEGURIDAD DETECTADOS\n")
        f.write("     IBM RPG/CL/PF Security Findings Report (JSON Driven)\n")
        f.write("=" * 100 + "\n")
        f.write(f"Fecha de análisis: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total de hallazgos encontrados: {len(hallazgos)}\n")
        f.write("=" * 100 + "\n\n")
        
        if not hallazgos:
            f.write("No se encontraron hallazgos de seguridad en el código analizado.\n")
            f.write("=" * 100 + "\n")
            return nombre_reporte
            
        # Usar la lista ordenada para agrupar por categoría
        por_categoria = {}
        for h in hallazgos_ordenados:
            por_categoria.setdefault(h['categoria'], []).append(h)

        for categoria in sorted(por_categoria.keys()):
            f.write(f"## {categoria.upper()} ({len(por_categoria[categoria])} hallazgos)\n")
            f.write("-" * 80 + "\n")
            for i, hallazgo in enumerate(por_categoria[categoria], 1):
                f.write(f"### Hallazgo #{i}\n")
                f.write(f"**Archivo Original:** {hallazgo['archivo_original']} ({hallazgo['tipo_archivo']})\n")
                f.write(f"**Archivo de Reporte:** {hallazgo['archivo_reporte']}\n")
                f.write(f"**Línea en Reporte:** {hallazgo['linea']}\n")
                f.write(f"**Patrón:** {hallazgo['patron']} (ID: {hallazgo['id_regla']})\n") 
                f.write(f"**Descripción:** {hallazgo['descripcion']}\n")
                f.write(f"**Categoría:** {hallazgo['categoria']}\n")
                f.write(f"**Código detectado:** `{hallazgo['match']}`\n")
                f.write(f"**Contenido de línea:** `{hallazgo['contenido']}`\n")
                f.write(f"**CWE:** {hallazgo['cwe']}\n")
                f.write(f"**OWASP:** {hallazgo['owasp']}\n")
                f.write(f"**Ruta completa del reporte:** {hallazgo['ruta_completa']}\n")
                f.write("\n" + "-" * 60 + "\n")
            f.write("\n")

        # Generar RESUMEN POR ARCHIVO ORIGINAL
        f.write("## RESUMEN POR ARCHIVO ORIGINAL\n")
        f.write("-" * 50 + "\n")
        archivos_afectados = {}
        for h in hallazgos_ordenados:
            archivo_key = f"{h['archivo_original']} ({h['tipo_archivo']})"
            archivos_afectados.setdefault(archivo_key, []).append(h['patron'])
            
        for archivo, patrones in archivos_afectados.items():
            contadores = Counter(patrones)
            f.write(f"**{archivo}:**\n")
            for patron, count in contadores.most_common():
                f.write(f"  - {patron}: {count} ocurrencia(s)\n")
            f.write("\n")
            
        # Generar ESTADÍSTICAS POR PATRÓN
        f.write("## ESTADÍSTICAS POR PATRÓN\n")
        f.write("-" * 50 + "\n")
        contadores = Counter(h['patron'] for h in hallazgos_ordenados)
        for patron_clave, count in contadores.most_common():
            config = patrones_map.get(patron_clave, {}) 
            f.write(f"- **{patron_clave}**: {count} ocurrencias\n")
            f.write(f"  - Descripción: {config.get('descripcion', 'N/A')}\n")
            f.write(f"  - Categoría: {config.get('categoria', 'N/A')}\n")
            f.write(f"  - CWE: {config.get('cwe', 'N/A')}\n")
            f.write(f"  - OWASP: {config.get('owasp', 'N/A')}\n\n")
            
        f.write("=" * 100 + "\n")
        f.write("## INFORMACIÓN ADICIONAL\n")
        f.write("-" * 30 + "\n")
        f.write("Este reporte identifica patrones técnicos encontrados en el código analizado.\n")
        f.write("La interpretación y priorización de estos hallazgos queda a criterio del equipo de desarrollo.\n")
        f.write("Los patrones están basados en estándares técnicos CWE y OWASP, y cargados desde archivos JSON.\n")
        f.write("=" * 100 + "\n")

    return nombre_reporte

# ======================================================================
#                            LÓGICA PRINCIPAL
# ======================================================================

def main():
    # Se mantiene la lógica de argparse con un grupo mutuamente exclusivo
    parser = argparse.ArgumentParser(
        description=color_text("🛡️ Detector de patrones de seguridad para reportes IBM RPG/CL/PF (Modular JSON).", Colors['HEADER']),
        formatter_class=argparse.RawTextHelpFormatter # Para formato más limpio en el help
    )
    # Se elimina el argumento -r/--recursivo
    grupo = parser.add_mutually_exclusive_group(required=True)
    grupo.add_argument(
        '-a', '--archivo', 
        type=str, 
        help='Ruta del archivo de reporte ÚNICO a analizar.'
    )
    grupo.add_argument(
        '-f', '--carpeta', 
        type=str, 
        # Se actualiza el help para indicar que es recursivo
        help='Ruta de la CARPETA (recursivo) con reportes a analizar.'
    )
    
    args = parser.parse_args()
    
    print(color_text("=" * 70, Colors['HEADER']))
    print(color_text("    DETECTOR DE PATRONES DE SEGURIDAD IBM RPG/CL/PF v3.0", Colors['HEADER']))
    print(color_text("      (Patrones cargados dinámicamente desde JSON)", Colors['HEADER']))
    print(color_text("=" * 70, Colors['HEADER']))
    
    # 1. Cargar Patrones
    if not load_all_patterns(PATTERNS_DIR):
        print(color_text("ERROR: La carga de patrones falló. Saliendo del programa.", Colors['FAIL']))
        sys.exit(1)
    
    todos_hallazgos = []
    
    # 2. Lógica de Escaneo
    if args.archivo:
        # Lógica para archivo único
        if not os.path.exists(args.archivo):
            print(color_text(f"❌ Error: El archivo '{args.archivo}' no existe.", Colors['FAIL']))
            return
        if not es_archivo_codigo_valido(os.path.basename(args.archivo)):
            print(color_text(f"⚠️  El archivo '{os.path.basename(args.archivo)}' no es un reporte de código válido (Filtro por nombre).", Colors['WARNING']))
            return
        
        print(f"\n🔍 Analizando archivo: {os.path.basename(args.archivo)}")
        hallazgos = analizar_archivo_seguridad(args.archivo)
        todos_hallazgos.extend(hallazgos)
        
    elif args.carpeta:
        # Lógica para carpeta (AHORA SIEMPRE RECURSIVA)
        if not os.path.exists(args.carpeta):
            print(color_text(f"❌ Error: La carpeta '{args.carpeta}' no existe.", Colors['FAIL']))
            return

        print(f"\n🔍 Analizando carpeta: {args.carpeta} (Modo Recursivo)")
        
        archivos_a_analizar = []
        
        # Siempre usa os.walk para recursividad
        for root, _, files in os.walk(args.carpeta):
            for file in files:
                full_path = os.path.join(root, file)
                if os.path.isfile(full_path) and es_archivo_codigo_valido(file) and file.endswith('.txt'):
                    archivos_a_analizar.append(full_path)
        
        if not archivos_a_analizar:
            print(color_text(f"❌ No se encontraron archivos de reporte de código válidos en '{args.carpeta}'", Colors['FAIL']))
            return
            
        print(f"📂 Archivos de código encontrados: {len(archivos_a_analizar)}")
        
        for archivo in archivos_a_analizar:
            print(f"  - Analizando: {os.path.basename(archivo)}")
            hallazgos = analizar_archivo_seguridad(archivo)
            todos_hallazgos.extend(hallazgos)
            
    # 3. Reporte de Consola y Archivo
    if todos_hallazgos:
        
        # APLICAR ORDENAMIENTO: Primero por Archivo Original, luego por Número de Línea
        hallazgos_ordenados = sorted(
            todos_hallazgos, 
            key=lambda h: (h['archivo_original'], h['linea'])
        )
        
        print("\n" + color_text("=" * 70, Colors['BOLD']))
        print(color_text("    HALLAZGOS DETALLADOS ENCONTRADOS", Colors['BOLD']))
        print(color_text("=" * 70, Colors['BOLD']))
        
        # Imprimir la lista ORDENADA
        for i, hallazgo in enumerate(hallazgos_ordenados, 1):
            color = Colors['FAIL'] if hallazgo['es_sensible'] else Colors['OKBLUE']
            print(color_text(f"\n--- HALLAZGO #{i} ---", color))
            print(f"Archivo Original: {hallazgo['archivo_original']} ({hallazgo['tipo_archivo']})")
            print(f"Línea: {hallazgo['linea']}")
            print(f"Patrón: {hallazgo['patron']} (ID: {hallazgo['id_regla']})")
            print(f"Descripción: {hallazgo['descripcion']}")
            print(f"CWE: {hallazgo['cwe']} | OWASP: {hallazgo['owasp']}")
            print(f"Código detectado: {color_text(f"`{hallazgo['match']}`", Colors['BOLD'])}")
            print(f"Contenido de línea: `{hallazgo['contenido']}`")
        
        print("\n" + color_text("=" * 70, Colors['BOLD']))
        print(color_text("    FIN DEL REPORTE DE CONSOLA", Colors['BOLD']))
        print(color_text("=" * 70, Colors['BOLD']))

        # Generar el reporte en archivo
        archivo_reporte = generar_reporte_seguridad(todos_hallazgos, DIRECTORIO_SALIDA)
        if archivo_reporte:
            print(color_text(f"\n✅ Reporte generado: {archivo_reporte}", Colors['OKGREEN']))
    else:
        print("\n✅ No se detectaron patrones de seguridad en el código analizado.")

if __name__ == "__main__":
    main()