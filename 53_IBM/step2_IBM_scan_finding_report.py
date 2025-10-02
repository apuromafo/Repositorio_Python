"""
Analizador de Seguridad para Reportes IBM RPG/CL/PF
Versión: 2.1.0 - CON ARCHIVO ORIGINAL Y SALIDA EN CONSOLA
Descripción:
Script que extrae, analiza y reporta hallazgos de seguridad en
reportes de código RPG/CL/PF. Muestra los resultados en consola y
genera un reporte detallado en un archivo.
"""

import re
import argparse
import os
from datetime import datetime
from collections import Counter

# ======================================================================
#                            C O N F I G U R A C I Ó N
# ======================================================================

# Directorio para los reportes de salida.
# Si está vacío, se usará el directorio actual.
DIRECTORIO_SALIDA = "resultados_analisis"

# Patrones para identificar archivos de código válidos.
PATRONES_INCLUIR = ['analisis_cl_', 'analisis_pf_', 'analisis_rpg_']
PATRONES_EXCLUIR = ['header_', 'security_findings_', 'readme', 'log_']

# Patrones de seguridad para el análisis.
PATRONES_SEGURIDAD = {
    'DUMP_STATEMENTS': {
        'patron': re.compile(r'(?:DUMP|dump)\s*(?:\([^)]*\)|;)', re.IGNORECASE),
        'descripcion': 'Comando DUMP detectado en el código',
        'categoria': 'Insecure Configuration',
        'cwe': 'CWE-215: Information Exposure Through Debug Information',
        'owasp': 'A05:2021 – Security Misconfiguration'
    },
    'DEBUG_CONFIG': {
        'patron': re.compile(r'DEBUG\s*\(\s*\*YES\s*\)', re.IGNORECASE),
        'descripcion': 'Configuración DEBUG(*YES) detectada',
        'categoria': 'Insecure Configuration',
        'cwe': 'CWE-489: Active Debug Code',
        'owasp': 'A05:2021 – Security Misconfiguration'
    },
    'DEBUG_STATEMENTS': {
        'patron': re.compile(r'(?:^|\s)(?:DEBUG|debug)\s*(?:=|:|\()', re.IGNORECASE),
        'descripcion': 'Instrucción de depuración detectada',
        'categoria': 'Insecure Configuration',
        'cwe': 'CWE-489: Active Debug Code',
        'owasp': 'A05:2021 – Security Misconfiguration'
    },
    'HARDCODED_PASSWORDS': {
        'patron': re.compile(r'(?:PASSWORD|PWD|PASS|CLAVE)\s*(?:=|:)\s*["\']?([^"\'\s;,)]+)', re.IGNORECASE),
        'descripcion': 'Posible contraseña hardcodeada detectada',
        'categoria': 'Hardcoded Credentials',
        'cwe': 'CWE-798: Use of Hard-coded Credentials',
        'owasp': 'A07:2021 – Identification and Authentication Failures'
    },
    'SENSITIVE_COMMENTS': {
        'patron': re.compile(r'(?:TODO|FIXME|HACK|XXX|BUG).*(?:PASSWORD|USER|ADMIN|SECRET|KEY|TOKEN)', re.IGNORECASE),
        'descripcion': 'Comentario con posible información sensible detectado',
        'categoria': 'Information Disclosure',
        'cwe': 'CWE-532: Information Exposure Through Log Files',
        'owasp': 'A09:2021 – Security Logging and Monitoring Failures'
    },
    'IP_ADDRESSES': {
        'patron': re.compile(r'\b(?:192\.168\.|10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|127\.0\.0\.1)\d{1,3}\.\d{1,3}\.\d{1,3}\b'),
        'descripcion': 'Dirección IP privada hardcodeada detectada',
        'categoria': 'Information Disclosure',
        'cwe': 'CWE-200: Information Exposure',
        'owasp': 'A01:2021 – Broken Access Control'
    },
    'SYSTEM_PATHS': {
        'patron': re.compile(r'(?:[C-Z]:\\|/usr/|/etc/|/var/|/home/)[\w\\/.-]+', re.IGNORECASE),
        'descripcion': 'Ruta de sistema hardcodeada detectada',
        'categoria': 'Information Disclosure',
        'cwe': 'CWE-200: Information Exposure',
        'owasp': 'A05:2021 – Security Misconfiguration'
    }
}

# ======================================================================
#                    FUNCIONES AUXILIARES DE EXTRACCIÓN
# ======================================================================

def extraer_archivo_original(nombre_reporte):
    """
    Extrae el nombre del archivo original desde el nombre del reporte.
    """
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
    """
    Determina el tipo de archivo original (RPG, CL, PF) desde el nombre del reporte.
    """
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
    """
    Determina si un archivo debe ser analizado por el scanner de seguridad
    usando los patrones de inclusión y exclusión.
    """
    nombre_archivo = nombre_archivo.lower()
    for patron_excluir in PATRONES_EXCLUIR:
        if patron_excluir in nombre_archivo:
            return False
    for patron_incluir in PATRONES_INCLUIR:
        if patron_incluir in nombre_archivo:
            return True
    return False

# ======================================================================
#                       FUNCIONES DE ANÁLISIS Y REPORTE
# ======================================================================

def analizar_archivo_seguridad(ruta_archivo):
    """
    Analiza un archivo de reporte buscando hallazgos de seguridad.
    """
    hallazgos = []
    nombre_archivo = os.path.basename(ruta_archivo)
    archivo_original = extraer_archivo_original(nombre_archivo)
    tipo_archivo = determinar_tipo_archivo_original(nombre_archivo)

    try:
        with open(ruta_archivo, 'r', encoding='utf-8') as f:
            for num_linea, linea in enumerate(f, 1):
                linea_limpia = linea.strip()
                if not linea_limpia:
                    continue
                for patron_nombre, config in PATRONES_SEGURIDAD.items():
                    match = config['patron'].search(linea_limpia)
                    if match:
                        hallazgo = {
                            'archivo_reporte': nombre_archivo,
                            'archivo_original': archivo_original,
                            'tipo_archivo': tipo_archivo,
                            'ruta_completa': ruta_archivo,
                            'linea': num_linea,
                            'contenido': linea_limpia[:100] + ('...' if len(linea_limpia) > 100 else ''),
                            'patron': patron_nombre,
                            'descripcion': config['descripcion'],
                            'categoria': config['categoria'],
                            'cwe': config['cwe'],
                            'owasp': config['owasp'],
                            'match': match.group(0) if match else ''
                        }
                        hallazgos.append(hallazgo)
    except Exception as e:
        print(f"🚨 Error analizando {ruta_archivo}: {e}")
    
    return hallazgos

def generar_reporte_seguridad(hallazgos, ruta_salida):
    """
    Genera un reporte de hallazgos de seguridad en formato de texto.
    """
    if not os.path.exists(ruta_salida):
        try:
            os.makedirs(ruta_salida)
        except OSError as e:
            print(f"❌ Error al crear el directorio '{ruta_salida}': {e}")
            return None

    fecha_hora = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    nombre_reporte = os.path.join(ruta_salida, f"SECURITY_FINDINGS_{fecha_hora}.txt")

    with open(nombre_reporte, 'w', encoding='utf-8') as f:
        f.write("=" * 100 + "\n")
        f.write("     HALLAZGOS DE SEGURIDAD DETECTADOS\n")
        f.write("     IBM RPG/CL/PF Security Findings Report\n")
        f.write("=" * 100 + "\n")
        f.write(f"Fecha de análisis: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total de hallazgos encontrados: {len(hallazgos)}\n")
        f.write("=" * 100 + "\n\n")
        
        if not hallazgos:
            f.write("No se encontraron hallazgos de seguridad en el código analizado.\n")
            f.write("=" * 100 + "\n")
            return nombre_reporte
        
        por_categoria = {}
        for h in hallazgos:
            por_categoria.setdefault(h['categoria'], []).append(h)

        for categoria in sorted(por_categoria.keys()):
            f.write(f"## {categoria.upper()} ({len(por_categoria[categoria])} hallazgos)\n")
            f.write("-" * 80 + "\n")
            for i, hallazgo in enumerate(por_categoria[categoria], 1):
                f.write(f"### Hallazgo #{i}\n")
                f.write(f"**Archivo Original:** {hallazgo['archivo_original']} ({hallazgo['tipo_archivo']})\n")
                f.write(f"**Archivo de Reporte:** {hallazgo['archivo_reporte']}\n")
                f.write(f"**Línea en Reporte:** {hallazgo['linea']}\n")
                f.write(f"**Patrón:** {hallazgo['patron']}\n")
                f.write(f"**Descripción:** {hallazgo['descripcion']}\n")
                f.write(f"**Categoría:** {hallazgo['categoria']}\n")
                f.write(f"**Código detectado:** `{hallazgo['match']}`\n")
                f.write(f"**Contenido de línea:** `{hallazgo['contenido']}`\n")
                f.write(f"**CWE:** {hallazgo['cwe']}\n")
                f.write(f"**OWASP:** {hallazgo['owasp']}\n")
                f.write(f"**Ruta completa del reporte:** {hallazgo['ruta_completa']}\n")
                f.write("\n" + "-" * 60 + "\n")
            f.write("\n")

        f.write("## RESUMEN POR ARCHIVO ORIGINAL\n")
        f.write("-" * 50 + "\n")
        archivos_afectados = {}
        for h in hallazgos:
            archivo_key = f"{h['archivo_original']} ({h['tipo_archivo']})"
            archivos_afectados.setdefault(archivo_key, []).append(h['patron'])
        
        for archivo, patrones in archivos_afectados.items():
            contadores = Counter(patrones)
            f.write(f"**{archivo}:**\n")
            for patron, count in contadores.most_common():
                f.write(f"  - {patron}: {count} ocurrencia(s)\n")
            f.write("\n")
        
        f.write("## ESTADÍSTICAS POR PATRÓN\n")
        f.write("-" * 50 + "\n")
        contadores = Counter(h['patron'] for h in hallazgos)
        for patron, count in contadores.most_common():
            config = PATRONES_SEGURIDAD[patron]
            f.write(f"- **{patron}**: {count} ocurrencias\n")
            f.write(f"  - Categoría: {config['categoria']}\n")
            f.write(f"  - CWE: {config['cwe']}\n")
            f.write(f"  - OWASP: {config['owasp']}\n\n")
        
        f.write("=" * 100 + "\n")
        f.write("## INFORMACIÓN ADICIONAL\n")
        f.write("-" * 30 + "\n")
        f.write("Este reporte identifica patrones técnicos encontrados en el código analizado.\n")
        f.write("La interpretación y priorización de estos hallazgos queda a criterio del equipo de desarrollo.\n")
        f.write("Los patrones están basados en estándares técnicos CWE y OWASP.\n")
        f.write("=" * 100 + "\n")

    return nombre_reporte

# ======================================================================
#                            LÓGICA PRINCIPAL
# ======================================================================

def main():
    parser = argparse.ArgumentParser(description="Detector de patrones de seguridad para reportes IBM RPG/CL/PF")
    grupo = parser.add_mutually_exclusive_group(required=True)
    grupo.add_argument('-a', '--archivo', type=str, help='Ruta del archivo de reporte a analizar.')
    grupo.add_argument('-f', '--carpeta', type=str, help='Ruta de la carpeta con reportes a analizar.')
    parser.add_argument('-r', '--recursivo', action='store_true', help='Analizar de forma recursiva en la carpeta.')
    
    args = parser.parse_args()
    
    print("=" * 70)
    print("   DETECTOR DE PATRONES DE SEGURIDAD IBM RPG/CL/PF v2.1.0")
    print("      (Con salida en consola y archivo de reporte)")
    print("=" * 70)
    
    todos_hallazgos = []
    
    if args.archivo:
        if not os.path.exists(args.archivo):
            print(f"❌ Error: El archivo '{args.archivo}' no existe.")
            return
        if not es_archivo_codigo_valido(os.path.basename(args.archivo)):
            print(f"⚠️  El archivo '{os.path.basename(args.archivo)}' no es un reporte de código válido.")
            return
        
        print(f"\n🔍 Analizando archivo: {os.path.basename(args.archivo)}")
        hallazgos = analizar_archivo_seguridad(args.archivo)
        todos_hallazgos.extend(hallazgos)
        print(f"📋 Hallazgos detectados: {len(hallazgos)}")
        
    elif args.carpeta:
        if not os.path.exists(args.carpeta):
            print(f"❌ Error: La carpeta '{args.carpeta}' no existe.")
            return

        print(f"\n🔍 Analizando carpeta: {args.carpeta}")
        
        archivos_a_analizar = []
        if args.recursivo:
            for root, _, files in os.walk(args.carpeta):
                for file in files:
                    if es_archivo_codigo_valido(file) and file.endswith('.txt'):
                        archivos_a_analizar.append(os.path.join(root, file))
        else:
            for file in os.listdir(args.carpeta):
                full_path = os.path.join(args.carpeta, file)
                if os.path.isfile(full_path) and es_archivo_codigo_valido(file) and file.endswith('.txt'):
                    archivos_a_analizar.append(full_path)
        
        if not archivos_a_analizar:
            print(f"❌ No se encontraron archivos de reporte de código válidos en '{args.carpeta}'")
            return
            
        print(f"📂 Archivos de código encontrados: {len(archivos_a_analizar)}")
        
        for archivo in archivos_a_analizar:
            print(f"  - Analizando: {os.path.basename(archivo)}")
            hallazgos = analizar_archivo_seguridad(archivo)
            todos_hallazgos.extend(hallazgos)
    
    # Nuevo comportamiento: imprimir los hallazgos en la consola
    if todos_hallazgos:
        print("\n" + "=" * 70)
        print("    HALLAZGOS DETALLADOS ENCONTRADOS")
        print("=" * 70)
        
        for i, hallazgo in enumerate(todos_hallazgos, 1):
            print(f"\n--- HALLAZGO #{i} ---")
            print(f"Archivo Original: {hallazgo['archivo_original']} ({hallazgo['tipo_archivo']})")
            print(f"Archivo de Reporte: {hallazgo['archivo_reporte']}")
            print(f"Línea: {hallazgo['linea']}")
            print(f"Patrón: {hallazgo['patron']}")
            print(f"Descripción: {hallazgo['descripcion']}")
            print(f"Código detectado: `{hallazgo['match']}`")
            print(f"Contenido de línea: `{hallazgo['contenido']}`")
        
        print("\n" + "=" * 70)
        print("    FIN DEL REPORTE DE CONSOLA")
        print("=" * 70)

        # Generar el reporte en archivo
        archivo_reporte = generar_reporte_seguridad(todos_hallazgos, DIRECTORIO_SALIDA)
        if archivo_reporte:
            print(f"\n✅ Reporte generado: {archivo_reporte}")
    else:
        print("\n✅ No se detectaron patrones de seguridad en el código analizado.")

if __name__ == "__main__":
    main()