#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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

#
# analisys.py
#
# Herramienta de línea de comandos para analizar archivos JRXML y .jasper.
# Extrae metadatos, texto, expresiones e imágenes embebidas.
# Genera hash SHA-256 para archivos .jrxml y .jasper.
# Integra auditoría de seguridad OWASP para detección de vulnerabilidades.
# NOTA: Para la descompilación de archivos .jasper, utilizar el script complementario v3.
#
# Uso:
# python analisys.py -a archivo.jrxml      # Analiza un JRXML
# python analisys.py -f carpeta/           # Analiza una carpeta
# python analisys.py -f carpeta/ -o salida.json # Salida JSON
# ==============================================================================
# --- HISTORIAL DE VERSIONES ---
# ==============================================================================
# v5.0.0 (2026-05-20) - [SEGURIDAD Y ANÁLISIS]
#   ✅ Integrado: Motor de auditoría OWASP (SQLi, LFI, RCE, XXE, XSS).
#   ✅ Estabilidad: Manejo correcto de archivos binarios (.jasper) sin decodificación.
#   ✅ Referencia: Indicación de uso de script v3 para procesos de descompilación.
#
# v1.2.0 (2025-09-15) - [ESTABLE FINAL]
#   ✅ Corregido: Función get_script_version() duplicada eliminada.
#   ✅ Corregido: Hash SHA-256 correcto para archivos JRXML.
#
# v1.1.0 (2025-09-15) - [ESTABLE]
#   ✅ Añadido: Detección recursiva de archivos .jrxml y .jasper.
#
# v1.0.0 (2025-09-14) - [LANZAMIENTO]
#   ✅ Primera versión funcional completa del analizador JRXML.
# ==============================================================================

import argparse
import os
import sys
import json
import re
import base64
import hashlib
import zipfile


def get_script_version():
    return "5.0.0"


def format_size(size_bytes):
    if size_bytes == 0:
        return "0 B"
    size_name = ("B", "KB", "MB", "GB", "TB")
    i = 0
    while size_bytes >= 1024 and i < len(size_name) - 1:
        size_bytes /= 1024
        i += 1
    return f"{size_bytes:.2f} {size_name[i]}"


def clean_content(content):
    if not content:
        return ""
    cleaned = re.sub(r'<[^>]+>', '', content)
    cleaned = re.sub(r'<!\[CDATA\[', '', cleaned)
    cleaned = re.sub(r'\]\]>', '', cleaned)
    return cleaned.strip()


def find_line_number(content, start_pos):
    return content[:start_pos].count('\n') + 1


def get_file_hash(file_path):
    h = hashlib.sha256()
    try:
        with open(file_path, "rb") as file:
            while True:
                chunk = file.read(4096)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        return f"Error al calcular hash: {e}"


def scan_folder(path):
    jrxml_files = []
    jasper_files = []
    if not os.path.isdir(path):
        return jrxml_files, jasper_files
    for root, _, files in os.walk(path):
        for filename in files:
            file_path = os.path.join(root, filename)
            if filename.lower().endswith('.jrxml'):
                jrxml_files.append(file_path)
            elif filename.lower().endswith('.jasper'):
                jasper_files.append(file_path)
    return jrxml_files, jasper_files


def motor_analisis_evidencias(content):
    """
    Motor de auditoría de seguridad para detectar vulnerabilidades en JRXML.
    - Cubre: SQLi, RCE, LFI/RFI, XXE, XSS, Exposición de datos y Deuda técnica.
    """
    evidencias = []
    lineas = content.splitlines()

    # 1. Análisis de Parámetros (Obsolescencia y Tipado)
    params = re.findall(r'parameter name="([^"]+)" class="([^"]+)"', content)
    for p, p_class in params:
        tipo_limpio = p_class.split('.')[-1]
        # Detección de parámetros obsoletos (deuda técnica)
        if p.startswith("PV60_"):
            evidencias.append({"tipo": "Obsolescencia", "detalle": f"Param '{p}' (Tipo: {tipo_limpio})"})
        # Detección de malas prácticas de tipado
        if "java.lang.Object" in p_class:
            evidencias.append({"tipo": "Debilidad de Tipado", "detalle": f"Param '{p}' usa tipo Object. Se recomienda tipo específico."})

    # 2. Análisis línea a línea (Inyección y Riesgos de Código)
    for i, linea in enumerate(lineas):
        # SQL Injection mediante parámetros dinámicos
        if "$P!{" in linea:
            evidencias.append({"tipo": "SQL Injection", "detalle": f"Query dinámico inseguro detectado en línea {i+1}"})
        
        # Riesgo LFI/RFI mediante carga de imágenes
        if "imageExpression" in linea and "$P{" in linea:
            evidencias.append({"tipo": "Riesgo LFI/RFI", "detalle": f"Imagen dinámica cargada por variable en línea {i+1}"})

    # 3. Análisis de Riesgos Globales (Regex de alto nivel)
    
    # RCE (Ejecución remota de comandos)
    if re.search(r'(Runtime\.getRuntime|java\.io\.File|ProcessBuilder)', content):
        evidencias.append({"tipo": "RCE CRÍTICO", "detalle": "Clases de sistema detectadas (Riesgo de ejecución de comandos)"})
    
    # XXE (Inyección de entidades externas)
    if re.search(r'<!ENTITY', content, re.IGNORECASE):
        evidencias.append({"tipo": "XXE POTENCIAL", "detalle": "Declaración <!ENTITY detectada en el XML"})
    
    # Exposición de datos sensibles
    sensible = re.search(r'(rut|clave|password|cuenta_bancaria|secret|token)', content, re.IGNORECASE)
    if sensible:
        evidencias.append({"tipo": "Exposición de Datos", "detalle": f"Campo sensible detectado: '{sensible.group(0)}'"})
    
    # XSS (Cross-Site Scripting)
    if 'markup="html"' in content:
        evidencias.append({"tipo": "XSS", "detalle": "Markup HTML habilitado (posible inyección de scripts en reportes web)"})

    return evidencias


def parse_jrxml(file_path, images_output_dir="./imagenes_extraidas"):
    try:
        if not os.path.exists(file_path):
            print(f"Error: El archivo no se encontró en la ruta: '{file_path}'")
            return None
        if os.path.getsize(file_path) == 0:
            print(f"Advertencia: El archivo '{file_path}' está vacío.")
            return None
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        size_bytes = os.path.getsize(file_path)
        formatted_size = format_size(size_bytes)
        security_findings = motor_analisis_evidencias(content)
        report_data = {
            "file_name": os.path.basename(file_path),
            "file_size": formatted_size,
            "file_type": "jrxml",
            "file_hash": get_file_hash(file_path),
            "encoding": None,
            "jasper_version": None,
            "name": None,
            "uuid": None,
            "language": None,
            "page_width": None,
            "page_height": None,
            "security_findings": security_findings,
            "properties": {},
            "query_string": None,
            "parameters": {},
            "fields": {},
            "variables": {},
            "groups": {},
            "static_texts": [],
            "field_expressions": [],
            "images": []
        }
        m = re.search(r'<\?xml[^>]*encoding="([^"]+)"', content)
        if m: report_data["encoding"] = m.group(1)
        m = re.search(r'<jasperReport\s+[^>]*version="([^"]+)"', content)
        if m: report_data["jasper_version"] = m.group(1).strip()
        m = re.search(r'name="([^"]+)"', content)
        if m: report_data["name"] = m.group(1)
        m = re.search(r'uuid="([^"]+)"', content)
        if m: report_data["uuid"] = m.group(1)
        m = re.search(r'language="([^"]+)"', content)
        if m: report_data["language"] = m.group(1)
        m = re.search(r'pageWidth="(\d+)"', content)
        if m: report_data["page_width"] = m.group(1)
        m = re.search(r'pageHeight="(\d+)"', content)
        if m: report_data["page_height"] = m.group(1)
        m = re.search(r'<queryString[^>]*>(.*?)</queryString>', content, re.DOTALL)
        if m: report_data["query_string"] = clean_content(m.group(1))
        report_data["parameters"] = dict(re.findall(r'<parameter name="([^"]+)" class="([^"]+)"', content))
        report_data["fields"] = dict(re.findall(r'<field name="([^"]+)" class="([^"]+)"', content))
        report_data["variables"] = dict(re.findall(r'<variable name="([^"]+)" class="([^"]+)"', content))
        report_data["groups"] = {name: {} for name in re.findall(r'<group name="([^"]+)"', content)}
        static_texts = re.finditer(r'<staticText.*?<text><!\[CDATA\[(.*?)\]\]></text>.*?</staticText>', content, re.DOTALL)
        for i, match in enumerate(static_texts, 1):
            report_data["static_texts"].append(match.group(1).strip())
        text_expr = re.finditer(r'<textFieldExpression><!\[CDATA\[(.*?)\]\]></textFieldExpression>', content, re.DOTALL)
        for i, match in enumerate(text_expr, 1):
            report_data["field_expressions"].append(match.group(1).strip())
        image_matches = re.finditer(r'<image[^>]*>.*?<imageExpression[^>]*><!\[CDATA\[(.*?)\]\]></imageExpression>.*?</image>', content, re.DOTALL)
        os.makedirs(images_output_dir, exist_ok=True)
        for idx, match in enumerate(image_matches, 1):
            expr = match.group(1).strip()
            img_data = {"id": f"img_{idx}", "expression": expr, "is_base64": False, "saved_path": None}
            b64_match = re.search(r'data:image/[a-zA-Z]+;base64,([^"\']+)', expr)
            if b64_match:
                img_data["is_base64"] = True
                try:
                    decoded = base64.b64decode(b64_match.group(1), validate=False)
                    out_name = f"{os.path.splitext(report_data['file_name'])[0]}_{img_data['id']}.png"
                    out_path = os.path.join(images_output_dir, out_name)
                    with open(out_path, 'wb') as imgf:
                        imgf.write(decoded)
                    img_data["saved_path"] = out_path
                except Exception as e:
                    img_data["saved_path"] = f"Error al decodificar: {e}"
            report_data["images"].append(img_data)
        return report_data
    except Exception as e:
        print(f"Error procesando {file_path}: {e}")
        return None
def print_audit_report(results):
    for r in results:
        print("\n=======================================================")
        print(f"--- {r.get('file_name', 'archivo_desconocido')} ---")
        print("\n[!] ALERTA DE SEGURIDAD - HALLAZGOS DETECTADOS:")
        
        # Filtramos o accedemos a los hallazgos de seguridad generados por el motor
        findings = r.get('security_findings', [])
        
        if not findings:
            print("  -> ✅ No se detectaron riesgos de seguridad.")
        else:
            for h in findings:
                # Ajustamos el formato según lo que muestra tu poc2.txt
                print(f"  -> [{h['tipo']}] {h['detalle']}")
                
 
def parse_jasper_report(file_path, images_dir):
    """
    Parsea un reporte JASPER compilado o JRXML, genera hash 
    y ejecuta el motor de auditoría si es posible.
    """
    try:
        # 1. Si es archivo .jasper, omitir lectura de contenido (binario)
        if file_path.lower().endswith('.jasper'):
            return {
                "file_name": os.path.basename(file_path),
                "file_hash": get_file_hash(file_path),
                "security_findings": [],
                "version": "BINARIO",
                "static_texts": [],
                "fields": [],
                "queries": [],
                "images": []
            }

        # 2. Si es .jrxml, leer como texto
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            
        # Ejecutar análisis de seguridad
        evidencias = motor_analisis_evidencias(content)
        
        # Construir reporte
        report_data = {
            "file_name": os.path.basename(file_path),
            "file_hash": get_file_hash(file_path),
            "security_findings": evidencias,
            "version": re.search(r'jasperReport.*?name="([^"]+)"', content).group(1) if re.search(r'name="([^"]+)"', content) else "N/A",
            "static_texts": re.findall(r'<text><!\[CDATA\[(.*?)\]\]></text>', content),
            "fields": re.findall(r'<field name="([^"]+)"', content),
            "queries": re.findall(r'<queryString><!\[CDATA\[(.*?)\]\]>', content, re.DOTALL),
            "images": []
        }
        return report_data

    except Exception as e:
        print(f"[-] Error crítico procesando {file_path}: {e}")
        return None


def process_file_or_folder(path, is_folder, images_output_dir):
    """
    Procesa archivos JRXML (con parse_jrxml) y JASPER (con parse_jasper_report)
    manteniendo la compatibilidad con tu lógica original.
    """
    results = []
    
    # Asegurar que el directorio de imágenes existe
    if not os.path.exists(images_output_dir):
        os.makedirs(images_output_dir)

    if is_folder:
        if not os.path.isdir(path):
            print(f"Error: La ruta '{path}' no es una carpeta válida.")
            return results
            
        # Asumiendo que 'scan_folder' es la función que escanea tu directorio
        # Si no existe, reemplázalo por la lógica de listado de archivos
        jrxml_files, jasper_files = scan_folder(path) 
        
        # Procesar JRXML
        for fp in jrxml_files:
            r = parse_jrxml(fp, images_output_dir)
            if r: results.append(r)
            
        # Procesar JASPER
        for fp in jasper_files:
            # Aquí es donde se soluciona el error, pasando los dos argumentos requeridos
            r = parse_jasper_report(fp, images_output_dir) 
            if r: results.append(r)
            
    else:
        # Procesamiento de archivo único
        if path.lower().endswith('.jrxml'):
            r = parse_jrxml(path, images_output_dir)
            if r: results.append(r)
        elif path.lower().endswith('.jasper'):
            r = parse_jasper_report(path, images_output_dir)
            if r: results.append(r)
        else:
            print('Error: El archivo debe ser .jrxml o .jasper')
            
    return results


def save_output(data, output_path):
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4, ensure_ascii=False)


def severity_counts(results):
    sev = {"CRÍTICO": 0, "MEDIO": 0, "INFORMATIVO": 0}
    mapping = {
        "SQL Injection": "CRÍTICO",
        "RCE CRÍTICO": "CRÍTICO",
        "XXE POTENCIAL": "CRÍTICO",
        "Riesgo LFI/RFI": "CRÍTICO",
        "Debilidad de Tipado": "MEDIO",
        "Exposición de Datos": "MEDIO",
        "XSS": "MEDIO",
        "Obsolescencia": "INFORMATIVO"
    }
    for item in results:
        for h in item.get('security_findings', []):
            sev[mapping.get(h['tipo'], 'INFORMATIVO')] += 1
    return sev


def print_results(results, summary_mode=False):
    for item in results:
        print("\n=======================================================")
        print(f"--- {item['file_name']} ---")
        if item.get('security_findings'):
            print("\n[!] ALERTA DE SEGURIDAD - HALLAZGOS DETECTADOS:")
            for h in item['security_findings']:
                print(f"  -> [{h['tipo']}] {h['detalle']}")
        elif item.get('file_type') == 'jrxml':
            print("\n[ok] Análisis limpio. No se detectaron problemas evidentes de seguridad.")
        print(f"\nTipo:           {item.get('file_type', 'N/A').upper()}")
        print(f"Tamaño:         {item.get('file_size', 'N/A')}")
        print(f"Hash SHA-256:   {item.get('file_hash', 'N/A')}")
        if item.get('file_type') == 'jrxml' and not summary_mode:
            print(f"Jasper Version: {item.get('jasper_version')}")
            print(f"Report Name:    {item.get('name')}")
            print(f"Parámetros:     {len(item.get('parameters', {}))}")
            print(f"Campos:         {len(item.get('fields', {}))}")
            if item.get('images'):
                print(f"\n--- Imágenes Extraídas ({len(item['images'])}) ---")
                for img in item['images']:
                    if img.get('is_base64'):
                        print(f"  - {img['id']} (Base64) -> Guardada en: {img['saved_path']}")
                    else:
                        expr = img['expression'].replace('\n', ' ')
                        print(f"  - {img['id']} -> Expresión: {expr[:60]}...")
    print("\n=====================================================================================")
    print("INFORME EJECUTIVO DE AUDITORÍA: JASPER REPORTS")
    print(f"Distribución de Riesgos: {severity_counts(results)}")
    print("=====================================================================================")
    all_types = set()
    for item in results:
        if item.get('security_findings'):
            print(f"\n[!] {item['file_name']}:")
            for h in item['security_findings']:
                all_types.add(h['tipo'])
                print(f" - [{h['tipo'].upper()}]: {h['detalle']}")
    print("\n=====================================================================================")
    print("GUÍA DE REMEDIACIÓN Y BUENAS PRÁCTICAS (OWASP)")
    if any(t in all_types for t in ('Riesgo LFI/RFI', 'SQL Injection', 'RCE CRÍTICO', 'XXE POTENCIAL')):
        print("\n[!] ALERTA CRÍTICA: Revisar inyección, inclusión de archivos y deserialización/XML.")
    if 'Debilidad de Tipado' in all_types:
        print("\n[!] MEJORA: Tipado estricto para parámetros sensibles.")
    if 'Obsolescencia' in all_types:
        print("\n[!] DEUDA TÉCNICA: Refactorizar nombres PV60_XX.")
    print("=====================================================================================")


def main():
    parser = argparse.ArgumentParser(description="Analizador de archivos JRXML y .jasper")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-a", "--analyze-file", help="Ruta archivo")
    group.add_argument("-f", "--analyze-folder", help="Ruta carpeta")
    parser.add_argument("-o", "--output", help="Guardar JSON")
    parser.add_argument("-i", "--summary", action="store_true", help="Salida resumida")
    args = parser.parse_args()
    results = process_file_or_folder(args.analyze_file or args.analyze_folder, args.analyze_folder is not None, "./imagenes_extraidas")
    if args.output:
        save_output(results, args.output)
    else:
        print_results(results, summary_mode=args.summary)



print("\n[!] AVISO LEGAL: Use solo con autorizacion. / LEGAL NOTICE: Authorized use only.\n")
if __name__ == "__main__":
    main()
