# jasper_jrxml.py
#
# Herramienta de línea de comandos para analizar archivos JRXML y .jasper.
# Extrae metadatos, texto, expresiones, imágenes embebidas de JRXML.
# Genera hash SHA-256 para archivos .jrxml y .jasper.
# Guarda imágenes automáticamente en ./imagenes_extraidas/
#
# Uso:
# python jasper_jrxml.py -a archivo.jrxml      # Analiza un JRXML
# python jasper_jrxml.py -f carpeta/          # Analiza una carpeta
# python jasper_jrxml.py -a archivo.jrxml -i  # Salida resumida
# python jasper_jrxml.py -f carpeta/ -o salida.json # Salida JSON
# ==============================================================================
# --- HISTORIAL DE VERSIONES ---
# ==============================================================================
# v1.2.0 (2025-09-15) - [ESTABLE FINAL]
#    ✅ Corregido: Función get_script_version() duplicada eliminada.
#    ✅ Corregido: Hash SHA-256 ahora se genera correctamente para archivos JRXML.
#    ✅ Corregido: Campo file_type añadido para consistencia en tabla resumen.
#    ✅ Mejorado: Función parse_jasper_report() integrada en el flujo principal.
#
# v1.1.0 (2025-09-15) - [ESTABLE]
#    ✅ Añadido: Detección y listado de archivos .jrxml y .jasper.
#    ✅ Añadido: Generación de hash SHA-256 para todos los archivos.
#    ✅ Mejorado: Salida en consola con una tabla resumen final.
#    ✅ Añadido: Detección y muestra automática de la versión del script.
#
# v1.0.0 (2025-09-14) - [LANZAMIENTO]
#    ✅ Primera versión funcional completa del analizador JRXML.
#    ✅ Extracción de metadatos, textos, expresiones e imágenes.
#    ✅ Manejo de argumentos para archivos y carpetas.
#    ✅ Opción de salida resumida y JSON.
#
# v0.1.0 (2025-09-13) - [INICIO]
#    ✅ Creación del script.
#    ✅ Estructura básica.
# ==============================================================================

import argparse
import os
import sys
import json
import re
import base64
import hashlib
import zipfile
VERSION = "1.2.0"
# ==============================================================================
# --- FUNCIONES DE UTILIDAD Y AYUDA ---
# ==============================================================================

def get_script_version():
    """
    Extrae la versión más reciente del historial de versiones en el script.
    """
    script_path = os.path.abspath(__file__)
    try:
        with open(script_path, 'r', encoding='utf-8') as f:
            content = f.read()
            # Busca la primera línea que contenga "vX.Y.Z"
            version_match = re.search(r'^#\s*v(\d+\.\d+\.\d+)', content, re.MULTILINE)
            if version_match:
                return version_match.group(1)
    except Exception as e:
        return f"Error al obtener versión: {e}"
    return "Desconocida"

def format_size(size_bytes):
    """Formatea tamaño del archivo en B, KB, MB, GB, TB."""
    if size_bytes == 0:
        return "0 B"
    size_name = ("B", "KB", "MB", "GB", "TB")
    i = 0
    while size_bytes >= 1024 and i < len(size_name) - 1:
        size_bytes /= 1024
        i += 1
    return f"{size_bytes:.2f} {size_name[i]}"

def get_file_hash(file_path):
    """Calcula el hash SHA-256 de un archivo."""
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

def clean_content(content):
    """Limpia etiquetas XML/HTML y CDATA, dejando solo texto plano."""
    if not content:
        return ""
    cleaned = re.sub(r'<[^>]+>', '', content)
    cleaned = re.sub(r'<!\[CDATA\[|\]\]>', '', cleaned)
    return cleaned.strip()

def find_line_number(content, start_pos):
    """Devuelve el número de línea dado una posición."""
    return content[:start_pos].count('\n') + 1

# ==============================================================================
# --- FUNCIONES DE ESCANEO DE ARCHIVOS ---
# ==============================================================================

def scan_folder(path):
    """Escanea una carpeta en busca de archivos .jrxml y .jasper."""
    jrxml_files = []
    jasper_files = []
    if not os.path.isdir(path):
        return jrxml_files, jasper_files
    for filename in os.listdir(path):
        file_path = os.path.join(path, filename)
        if os.path.isfile(file_path):
            if filename.lower().endswith(".jrxml"):
                jrxml_files.append(file_path)
            elif filename.lower().endswith(".jasper"):
                jasper_files.append(file_path)
    return jrxml_files, jasper_files

# ==============================================================================
# --- FUNCIONES CENTRALES DE ANÁLISIS (CORE) ---
# ==============================================================================

def parse_jrxml(file_path, images_output_dir="./imagenes_extraidas"):
    """Analiza un archivo JRXML y extrae todos los elementos relevantes."""
    try:
        if not os.path.exists(file_path):
            print(f"Error: El archivo no se encontró en la ruta: '{file_path}'")
            return None
        if os.path.getsize(file_path) == 0:
            print(f"Advertencia: El archivo '{file_path}' está vacío.")
            return None

        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        size_bytes = os.path.getsize(file_path)
        formatted_size = format_size(size_bytes)

        report_data = {
            "file_name": os.path.basename(file_path),
            "file_size": formatted_size,
            "file_type": "jrxml",  # ✅ Añadido para consistencia
            "encoding": None,
            "jasper_version": None,
            "jaspersoft_studio_version": None,
            "name": None,
            "uuid": None,
            "language": None,
            "page_width": None,
            "page_height": None,
            "report_title": None,
            "report_title_info": None,
            "page_header": None,
            "page_header_info": None,
            "page_footer": None,
            "page_footer_info": None,
            "summary_text": None,
            "summary_info": None,
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

        # === Metadatos principales ===
        encoding_match = re.search(r'<\?xml[^>]*encoding="([^"]+)"', content)
        if encoding_match:
            report_data["encoding"] = encoding_match.group(1)

        jasper_version_match = re.search(r'jasperReport\s+[^>]*version="([^"]+)"', content)
        if jasper_version_match:
            report_data["jasper_version"] = jasper_version_match.group(1).strip()

        name_match = re.search(r'name="([^"]+)"', content)
        if name_match:
            report_data["name"] = name_match.group(1)

        uuid_match = re.search(r'uuid="([^"]+)"', content)
        if uuid_match:
            report_data["uuid"] = uuid_match.group(1)

        lang_match = re.search(r'language="([^"]+)"', content)
        if lang_match:
            report_data["language"] = lang_match.group(1)

        page_width_match = re.search(r'pageWidth="(\d+)"', content)
        if page_width_match:
            report_data["page_width"] = page_width_match.group(1)

        page_height_match = re.search(r'pageHeight="(\d+)"', content)
        if page_height_match:
            report_data["page_height"] = page_height_match.group(1)

        # === Versión de Jaspersoft Studio ===
        studio_version_match = re.search(
            r'<!--\s*Created with Jaspersoft Studio version ([^\s]+)',
            content
        )
        if studio_version_match:
            raw_version = studio_version_match.group(1).strip()
            clean_match = re.search(r'^([\d\.\w-]+)', raw_version)
            report_data["jaspersoft_studio_version"] = clean_match.group(1) if clean_match else raw_version

        # === Propiedades ===
        properties = re.findall(r'<property name="([^"]+)" value="([^"]+)"', content)
        for name, value in properties:
            report_data["properties"][name] = value

        # === Query SQL ===
        query_match = re.search(r'<queryString>\s*<!\[CDATA\[(.*?)\]\]>\s*</queryString>', content, re.DOTALL)
        if query_match:
            report_data["query_string"] = query_match.group(1).strip()

        # === Parámetros, Campos, Variables, Grupos ===
        report_data["parameters"] = dict(re.findall(r'<parameter name="([^"]+)" class="([^"]+)"', content))
        report_data["fields"] = dict(re.findall(r'<field name="([^"]+)" class="([^"]+)"', content))
        report_data["variables"] = dict(re.findall(r'<variable name="([^"]+)" class="([^"]+)"', content))
        report_data["groups"] = {name: {} for name in re.findall(r'<group name="([^"]+)"', content)}

        # === Función auxiliar para extraer secciones con posición ===
        def extract_section(section_tag):
            section_match = re.search(rf'<{section_tag}[^>]*>.*?<\/{section_tag}>', content, re.DOTALL | re.IGNORECASE)
            if not section_match:
                return None

            field_match = re.search(
                r'<textField[^>]*>.*?<reportElement[^>]+x="(\d+)"[^>]*y="(\d+)"[^>]*width="(\d+)"[^>]*height="(\d+)"[^>]*>.*?<textFieldExpression>.*?<!\[CDATA\[(.*?)\]\]>.*?<\/textFieldExpression>.*?<\/textField>',
                section_match.group(0),
                re.DOTALL | re.IGNORECASE
            )
            if not field_match:
                return None

            x, y, width, height, raw_text = field_match.groups()
            start_pos = section_match.start() + field_match.start()
            line_number = find_line_number(content, start_pos)
            clean_text = clean_content(raw_text.strip())
            if not clean_text:
                return None

            return {
                "text": clean_text,
                "position": {"x": int(x), "y": int(y)},
                "size": {"width": int(width), "height": int(height)},
                "line_number": line_number
            }

        title_data = extract_section("title")
        if title_data:
            report_data["report_title"] = title_data["text"]
            report_data["report_title_info"] = {
                "position": title_data["position"],
                "size": title_data["size"],
                "line_number": title_data["line_number"]
            }

        header_data = extract_section("pageHeader")
        if header_data:
            report_data["page_header"] = header_data["text"]
            report_data["page_header_info"] = {
                "position": header_data["position"],
                "size": header_data["size"],
                "line_number": header_data["line_number"]
            }

        footer_data = extract_section("pageFooter")
        if footer_data:
            report_data["page_footer"] = footer_data["text"]
            report_data["page_footer_info"] = {
                "position": footer_data["position"],
                "size": footer_data["size"],
                "line_number": footer_data["line_number"]
            }

        summary_data = extract_section("summary")
        if summary_data:
            report_data["summary_text"] = summary_data["text"]
            report_data["summary_info"] = {
                "position": summary_data["position"],
                "size": summary_data["size"],
                "line_number": summary_data["line_number"]
            }

        # === Textos estáticos ===
        static_text_blocks = re.finditer(
            r'<staticText[^>]*>.*?<reportElement[^>]+x="(\d+)"[^>]*y="(\d+)"[^>]*width="(\d+)"[^>]*height="(\d+)"[^>]*(uuid="([^"]+)")?.*?>.*?<!\[CDATA\[(.*?)\]\]>.*?<\/staticText>',
            content,
            re.DOTALL
        )
        for match in static_text_blocks:
            x, y, width, height, uuid_group, uuid_value, raw_content = match.groups()
            line_number = find_line_number(content, match.start())
            clean_text = clean_content(raw_content.strip())
            if clean_text:
                report_data["static_texts"].append({
                    "line_number": line_number,
                    "content": clean_text,
                    "position": {"x": int(x), "y": int(y)},
                    "size": {"width": int(width), "height": int(height)},
                    "uuid": uuid_value
                })

        # === Expresiones de campo ===
        text_field_blocks = re.finditer(
            r'<textField[^>]*>.*?<reportElement[^>]+x="(\d+)"[^>]*y="(\d+)"[^>]*width="(\d+)"[^>]*height="(\d+)"[^>]*(uuid="([^"]+)")?.*?>.*?<textFieldExpression>.*?<!\[CDATA\[(.*?)\]\]>.*?<\/textFieldExpression>.*?<\/textField>',
            content,
            re.DOTALL
        )
        for match in text_field_blocks:
            x, y, width, height, uuid_group, uuid_value, raw_content = match.groups()
            line_number = find_line_number(content, match.start())
            clean_text = clean_content(raw_content.strip())
            if clean_text:
                report_data["field_expressions"].append({
                    "line_number": line_number,
                    "content": clean_text,
                    "position": {"x": int(x), "y": int(y)},
                    "size": {"width": int(width), "height": int(height)},
                    "uuid": uuid_value
                })

        # === Detección y extracción de imágenes embebidas ===
        image_var_pattern = re.compile(
            r'<variable\s+name="([^"]+)"[^>]*class="java\.lang\.String"[^>]*>.*?'
            r'<variableExpression>.*?<!\[CDATA\[(["\']?)([^"\']+)["\']?\]\]>.*?<\/variableExpression>.*?<\/variable>',
            re.DOTALL
        )
        for match in image_var_pattern.finditer(content):
            var_name, quote, base64_str = match.groups()
            base64_str = base64_str.strip()
            line_number = find_line_number(content, match.start())

            image_info = None
            if base64_str.startswith('iVBORw0KGgo'):
                image_info = {"type": "png", "magic": "PNG"}
            elif base64_str.startswith('/9j/4AAQSkZJRg'):
                image_info = {"type": "jpeg", "magic": "JPEG"}
            elif base64_str.startswith('R0lGODlh'):
                image_info = {"type": "gif", "magic": "GIF"}
            elif base64_str.startswith('Qk3'):
                image_info = {"type": "bmp", "magic": "BMP"}

            if image_info:
                # Crear carpeta si no existe
                if not os.path.exists(images_output_dir):
                    os.makedirs(images_output_dir)

                # Intentar decodificar y guardar
                try:
                    img_data = base64.b64decode(base64_str, validate=True)
                    img_path = os.path.join(images_output_dir, f"{var_name}.{image_info['type']}")
                    with open(img_path, 'wb') as img_file:
                        img_file.write(img_data)
                    print(f"✅ Imagen guardada: {img_path}")
                except Exception as e:
                    print(f"❌ No se pudo guardar {var_name}: {e}")

                approx_size_kb = round(len(base64_str) * 3 / 4 / 1024, 2)
                report_data["images"].append({
                    "variable": var_name,
                    "format": image_info["magic"],
                    "approx_size_kb": approx_size_kb,
                    "line_number": line_number
                })

        # ✅ Hash SHA-256 movido fuera del bucle de imágenes
        report_data["file_hash"] = get_file_hash(file_path)

        return report_data

    except Exception as e:
        print(f"Error al procesar el archivo '{file_path}': {e}")
        return None

def parse_jasper_report(file_path):
    """
    Registra un archivo .jasper (objeto Java serializado) - solo metadatos básicos.
    """
    return {
        "file_name": os.path.basename(file_path),
        "file_size": format_size(os.path.getsize(file_path)),
        "file_type": "jasper",
        "file_hash": get_file_hash(file_path)
    }

# ==============================================================================
# --- FUNCIONES DE FLUJO Y GESTIÓN DE SALIDA ---
# ==============================================================================

def process_file_or_folder(path, is_folder, images_output_dir):
    """Procesa un archivo o carpeta y devuelve una lista de resultados."""
    results = []
    if is_folder:
        if not os.path.isdir(path):
            print(f"Error: La ruta '{path}' no es una carpeta válida.")
            return []

        print(f"\n🔍 Analizando carpeta: {path}")
        jrxml_files, jasper_files = scan_folder(path)

        for file_path in jrxml_files:
            print(f"\n📄 Procesando archivo JRXML: {file_path}")
            analysis = parse_jrxml(file_path, images_output_dir)
            if analysis:
                results.append(analysis)

        for file_path in jasper_files:
            print(f"\n📦 Procesando archivo JASPER: {file_path}")
            # ✅ Ahora usa la función completa de análisis
            jasper_analysis = parse_jasper_report(file_path)
            results.append(jasper_analysis)

    else:
        print(f"\n📄 Procesando archivo: {path}")
        if path.lower().endswith(".jrxml"):
            analysis = parse_jrxml(path, images_output_dir)
            if analysis:
                results.append(analysis)
        elif path.lower().endswith(".jasper"):
            # ✅ Ahora usa la función completa de análisis
            jasper_analysis = parse_jasper_report(path)
            results.append(jasper_analysis)
        else:
            print("Error: El archivo debe ser .jrxml o .jasper")

    return results

def save_output(data, output_path):
    """Guarda los resultados en JSON."""
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        print(f"\n✅ Resultados guardados en '{output_path}'")
    except Exception as e:
        print(f"❌ Error al guardar: {e}")

def print_results(results, summary_mode=False):
    """Imprime resultados de forma completa o resumida."""
    script_version = get_script_version()
    print("\n" + "="*60)
    print("      📊 ANALIZADOR DE REPORTES JASPER JRXML")
    print(f"      v{script_version}")
    print("="*60)

    for item in results:
        print()
        print("─" * 50)
        # === Encabezado principal (siempre) ===
        print(f"**Archivo:** {item.get('file_name', 'N/A')}")
        print(f"**Tamaño:** {item.get('file_size', 'N/A')}")
        print(f"**Encoding:** {item.get('encoding', 'N/A')}")
        print(f"**Versión de Jaspersoft Studio:** {item.get('jaspersoft_studio_version', 'N/A')}")

        # === Modo resumido ===
        if summary_mode:
            if item.get("report_title"):
                info = item.get("report_title_info")
                coords = f"(x={info['position']['x']}, y={info['position']['y']})" if info else ""
                print(f"**Título:** {item['report_title']} {coords}")
            
            if item.get("images"):
                for img in item["images"]:
                    print(f"🖼️  **Imagen:** {img['variable']} → {img['format']} ({img['approx_size_kb']} KB)")
            
            static_count = len(item.get("static_texts", []))
            expr_count = len(item.get("field_expressions", []))
            print(f"📊 Textos: {static_count}, Expresiones: {expr_count}")
            continue  # Salta el resto

        # === Modo completo ===
        if item.get("report_title") and item.get("report_title_info"):
            info = item["report_title_info"]
            coords = f"(x={info['position']['x']}, y={info['position']['y']}, w={info['size']['width']}, h={info['size']['height']})"
            print(f"**Título del Reporte:** {item['report_title']} {coords} (Línea {info['line_number']})")

        if item.get("page_header") and item.get("page_header_info"):
            info = item["page_header_info"]
            coords = f"(x={info['position']['x']}, y={info['position']['y']}, w={info['size']['width']}, h={info['size']['height']})"
            print(f"**Encabezado de Página:** {item['page_header']} {coords} (Línea {info['line_number']})")

        if item.get("page_footer") and item.get("page_footer_info"):
            info = item["page_footer_info"]
            coords = f"(x={info['position']['x']}, y={info['position']['y']}, w={info['size']['width']}, h={info['size']['height']})"
            print(f"**Pie de Página:** {item['page_footer']} {coords} (Línea {info['line_number']})")

        if item.get("summary_text") and item.get("summary_info"):
            info = item["summary_info"]
            coords = f"(x={info['position']['x']}, y={info['position']['y']}, w={info['size']['width']}, h={info['size']['height']})"
            print(f"**Sección de Resumen:** {item['summary_text']} {coords} (Línea {info['line_number']})")

        if item.get("images"):
            print("\n🖼️  **Imágenes Embebidas:**")
            for img in item["images"]:
                print(f"  • {img['variable']} → {img['format']} ({img['approx_size_kb']} KB) en Línea {img['line_number']}")

        print("\n**Metadatos:**")
        for key in ["name", "uuid", "language", "page_width", "page_height"]:
            value = item.get(key)
            if value:
                label = key.replace('_', ' ').title()
                print(f"  • {label}: {value}")

        if item.get("properties"):
            print("\n**Propiedades:**")
            for name, value in item["properties"].items():
                print(f"  • {name}: {value}")

        if item.get("query_string"):
            print("\n**Consulta SQL:**")
            for line in item["query_string"].strip().split('\n'):
                stripped = line.strip()
                if stripped:
                    print(f"    {stripped}")

        sections = [("Parámetros", "parameters"), ("Campos", "fields"), ("Variables", "variables"), ("Grupos", "groups")]
        for label, key in sections:
            if item.get(key):
                print(f"\n**{label}:**")
                data = item[key]
                if isinstance(data, dict):
                    for sub_key, sub_value in data.items():
                        print(f"  • {sub_key} ({sub_value})" if key != "groups" else f"  • {sub_key}")

        if item.get("static_texts"):
            print("\n**Textos Estáticos:**")
            for t in sorted(item["static_texts"], key=lambda x: x['line_number']):
                pos, size = t['position'], t['size']
                coords = f"(x={pos['x']}, y={pos['y']}, w={size['width']}, h={size['height']})"
                print(f"  Línea {t['line_number']}: \"{t['content']}\" {coords}")

        if item.get("field_expressions"):
            print("\n**Expresiones de Campo:**")
            for e in sorted(item["field_expressions"], key=lambda x: x['line_number']):
                pos, size = e['position'], e['size']
                coords = f"(x={pos['x']}, y={pos['y']}, w={size['width']}, h={size['height']})"
                print(f"  Línea {e['line_number']}: {e['content']} {coords}")

        static_count = len(item.get("static_texts", []))
        expr_count = len(item.get("field_expressions", []))
        print(f"\n📊 Resumen: {static_count} texto(s) estático(s), {expr_count} expresión(es) de campo.")
    #fix
    if not results:
        print("\nNo se encontraron archivos.")
        return  
    # ✅ Calcular anchos dinámicos
    max_filename = max(len(item.get('file_name', 'N/A')) for item in results)
    max_filename = max(max_filename, len('Archivo'))  # Mínimo ancho del header

    max_type = max(len(item.get('file_type', 'N/A').upper()) for item in results)
    max_type = max(max_type, len('Tipo'))

    max_size = max(len(item.get('file_size', 'N/A')) for item in results)
    max_size = max(max_size, len('Tamaño'))

    hash_width = 64  # SHA-256 siempre 64 caracteres

    # Añadir padding
    filename_width = max_filename + 2
    type_width = max_type + 2
    size_width = max_size + 2

    # ✅ Encabezado con ancho dinámico
    total_width = filename_width + type_width + size_width + hash_width
    print("\n" + "=" * total_width)
    print("      📄 RESUMEN DE ARCHIVOS DETECTADOS")
    print("=" * total_width)
    
    # ✅ Headers alineados
    header = f"{'Archivo':<{filename_width}} {'Tipo':<{type_width}} {'Tamaño':<{size_width}} {'Hash SHA-256':<{hash_width}}"
    print(header)
    print("-" * total_width)
    
    # ✅ Datos perfectamente alineados
    for item in results:
        file_name = item.get('file_name', 'N/A')
        file_type = item.get('file_type', 'N/A').upper()
        file_size = item.get('file_size', 'N/A')
        file_hash = item.get('file_hash', 'N/A')
        
        print(f"{file_name:<{filename_width}} {file_type:<{type_width}} {file_size:<{size_width}} {file_hash:<{hash_width}}")
      
        
        
def main():
    parser = argparse.ArgumentParser(
        description="Analizador de archivos JRXML. Extrae metadatos, texto, expresiones, imágenes embebidas, y más.",
        epilog="""
Ejemplos:
  python jasper_jrxml.py -a reporte.jrxml       # completo
  python jasper_jrxml.py -f ./reportes/         # completo
  python jasper_jrxml.py -a reporte.jrxml -i    # resumido
  python jasper_jrxml.py -f ./reportes/ -o analisis.json
        """,
        formatter_class=argparse.RawTextHelpFormatter
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-a", "--analyze-file", help="Ruta al archivo JRXML.")
    group.add_argument("-f", "--analyze-folder", help="Ruta a la carpeta con archivos JRXML.")
    parser.add_argument("-o", "--output", help="Archivo JSON de salida (opcional).")
    parser.add_argument("-i", "--summary", action="store_true", help="Modo resumido: solo títulos e imágenes.")

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()
    images_dir = "./imagenes_extraidas"

    results = process_file_or_folder(
        args.analyze_file if args.analyze_file else args.analyze_folder,
        args.analyze_folder is not None,
        images_output_dir=images_dir
    )

    if not results:
        print("\n❌ No se procesó ningún archivo .jrxml/.jasper.")
        sys.exit(1)

    if args.output:
        save_output(results, args.output)
    else:
        print_results(results, summary_mode=args.summary)

if __name__ == "__main__":
    main()
