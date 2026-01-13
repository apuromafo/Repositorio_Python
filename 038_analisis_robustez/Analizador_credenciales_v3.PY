import re
import math
import os
import argparse
from pathlib import Path

# === FUNCIONES DE ENTROPIA Y CLASIFICACION === #
def detectar_complejidad(password):
    """Detecta qué tipos de caracteres contiene la contraseña."""
    return {
        'digitos': any(c.isdigit() for c in password),
        'mayusculas': any(c.isupper() for c in password),
        'minusculas': any(c.islower() for c in password),
        'especiales': any(not c.isalnum() and not c.isspace() for c in password)
    }

def calcular_entropia(longitud, complejidad):
    """Calcula la entropía en bits de una contraseña."""
    num_caracteres = sum([
        10 if complejidad['digitos'] else 0,
        26 if complejidad['mayusculas'] else 0,
        26 if complejidad['minusculas'] else 0,
        32 if complejidad['especiales'] else 0
    ])
    if num_caracteres == 0:
        return 0
    return longitud * math.log2(num_caracteres)

def clasificar_entropia(entropia):
    """Clasifica la entropía de la contraseña."""
    if entropia < 41:
        return "Muy Debil"
    elif entropia < 61:
        return "Debil"
    elif entropia < 81:
        return "Moderada"
    elif entropia < 101:
        return "Fuerte"
    else:
        return "Muy Fuerte"


# === FUNCIONES DE BUSQUEDA DE ARCHIVOS === #
def find_files_in_folder(folder_path):
    """Busca archivos de texto comunes dentro de una carpeta."""
    allowed_extensions = ['.txt', '.log', '.csv', '.sql', '.dat']
    files = []
    try:
        for root, _, filenames in os.walk(folder_path):
            for filename in filenames:
                if any(filename.endswith(ext) for ext in allowed_extensions):
                    files.append(os.path.join(root, filename))
    except FileNotFoundError:
        print(f"[ERROR] Carpeta no encontrada: {folder_path}")
        return []
    return files


# === FUNCION PRINCIPAL DE PARSEO === #
def parse_line(line):
    line = line.strip()
    line = re.sub(r'\s+', ' ', line).strip()
    if ';' in line:
        line = line.replace(';', ':')

    # === PATRON SQL INSERT MEJORADO ===
    sql_match = re.search(
        r"INSERT\s+INTO\s+leaked_credentials\s*$email,password$\s*VALUES\s*$\s*'([^']+)'\s*,\s*'(?:[^']*?)</?b>[\s\d\W]*([^']+)'\s*$;",
        line,
        re.IGNORECASE | re.DOTALL
    )
    if sql_match:
        usuario = sql_match.group(1).strip()
        clave = sql_match.group(2).strip()
        clave = re.sub(r'</?(b|code|strong|i)>', '', clave)
        clave = re.sub(r'[\x00-\x1F\x7F-\xFF]+', '', clave)
        clave = re.sub(r'^\s*\d+\s*', '', clave)
        clave = clave.strip()
        complejidad = detectar_complejidad(clave)
        entropia = calcular_entropia(len(clave), complejidad)
        return {
            "Sitio": "[Sin sitio]",
            "Usuario": usuario,
            "Clave": clave,
            "Patron": "SQL-Insert",
            "Entropia": round(entropia, 2),
            "Fuerza": clasificar_entropia(entropia)
        }

    # === PATRON CLASICO email:clave ===
    email_pass_match = re.match(
        r"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\:([\S]+)",
        line
    )
    if email_pass_match:
        clave = email_pass_match.group(2).strip('[] ')
        clave = re.sub(r'[\x00-\x1F\x7F-\xFF]+', '', clave)
        complejidad = detectar_complejidad(clave)
        entropia = calcular_entropia(len(clave), complejidad)
        return {
            "Sitio": "[Sin sitio]",
            "Usuario": email_pass_match.group(1),
            "Clave": clave,
            "Patron": "Email:Clave",
            "Entropia": round(entropia, 2),
            "Fuerza": clasificar_entropia(entropia)
        }

    # === PATRON ('contenido1', 'contenido2') ===
    dual_single_quote_match = re.match(
        r"$\s*'([^']+)'\s*,\s*'([^']+)'\s*$",
        line
    )
    if dual_single_quote_match:
        contenido1 = dual_single_quote_match.group(1).strip()
        contenido2 = dual_single_quote_match.group(2).strip()

        if re.match(r"[^@]+@[^@]+\.[^@]+", contenido1):
            clave = contenido2
        else:
            contenido1 = re.sub(r'[\x00-\x1F\x7F-\xFF]+', '', contenido1)
            contenido2 = re.sub(r'[\x00-\x1F\x7F-\xFF]+', '', contenido2)
            clave = contenido2
            contenido1 = contenido1[:50]

        clave = re.sub(r'</?b>|</?code>', '', clave).strip()
        clave = re.sub(r'[\x00-\x1F\x7F-\xFF]+', '', clave)

        complejidad = detectar_complejidad(clave)
        entropia = calcular_entropia(len(clave), complejidad)
        return {
            "Sitio": "[Sin sitio]",
            "Usuario": contenido1,
            "Clave": clave,
            "Patron": "('contenido1', 'contenido2')",
            "Entropia": round(entropia, 2),
            "Fuerza": clasificar_entropia(entropia)
        }

    # === PATRON URL:EMAIL:CLAVE ===
    url_email_pass_match = re.match(
        r"(https?://[^\s:]+|www\..+)\:([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\:([\S]+)",
        line
    )
    if url_email_pass_match:
        clave = url_email_pass_match.group(3).strip('[] ')
        clave = re.sub(r'[\x00-\x1F\x7F-\xFF]+', '', clave)
        complejidad = detectar_complejidad(clave)
        entropia = calcular_entropia(len(clave), complejidad)
        return {
            "Sitio": url_email_pass_match.group(1),
            "Usuario": url_email_pass_match.group(2),
            "Clave": clave,
            "Patron": "URL:Correo:Clave",
            "Entropia": round(entropia, 2),
            "Fuerza": clasificar_entropia(entropia)
        }

    # === PATRON URL::CLAVE (sin usuario) ===
    empty_user_match = re.match(
        r"(https?://[^\s:]+)::([\S]+)",
        line
    )
    if empty_user_match:
        clave = empty_user_match.group(2).strip('[] ')
        clave = re.sub(r'[\x00-\x1F\x7F-\xFF]+', '', clave)
        complejidad = detectar_complejidad(clave)
        entropia = calcular_entropia(len(clave), complejidad)
        return {
            "Sitio": empty_user_match.group(1),
            "Usuario": "[Sin usuario]",
            "Clave": clave,
            "Patron": "URL::Password",
            "Entropia": round(entropia, 2),
            "Fuerza": clasificar_entropia(entropia)
        }

    # === PATRON URL:USER:PASS ===
    standard_match = re.match(
        r"(https?://[^\s:]+|www\..+):([\w\-.@]+):([\S]+)",
        line
    )
    if standard_match:
        user = standard_match.group(2)
        if user == "$":
            return None
        clave = standard_match.group(3).strip('[] ')
        clave = re.sub(r'[\x00-\x1F\x7F-\xFF]+', '', clave)
        complejidad = detectar_complejidad(clave)
        entropia = calcular_entropia(len(clave), complejidad)
        return {
            "Sitio": standard_match.group(1),
            "Usuario": user,
            "Clave": clave,
            "Patron": "URL:Usuario:Clave",
            "Entropia": round(entropia, 2),
            "Fuerza": clasificar_entropia(entropia)
        }

    # === Cualquier linea con 'clave' entre comillas simples ===
    single_quote_pass_match = re.match(
        r".*['\"](.{6,})['\"].*",
        line
    )
    if single_quote_pass_match:
        clave = single_quote_pass_match.group(1).strip()
        clave = re.sub(r'[\x00-\x1F\x7F-\xFF]+', '', clave)
        if len(clave) > 5 and not re.match(r'^\d+$', clave):
            complejidad = detectar_complejidad(clave)
            entropia = calcular_entropia(len(clave), complejidad)
            return {
                "Sitio": "[Desconocido]",
                "Usuario": "[Sin usuario]",
                "Clave": clave,
                "Patron": "Comilla Simple - Clave",
                "Entropia": round(entropia, 2),
                "Fuerza": clasificar_entropia(entropia)
            }

    return None


# === FUNCIONES PARA BLOQUES MULTI-LINEA === #
def parse_multiline_block(lines):
    data = {
        "Usuario": None,
        "Clave": None,
        "Telefono": None,
        "Sitio": "[Desconocido]",
        "Patron": "Datos Multi-Línea",
    }

    email_regex = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"

    for line in lines:
        line = line.strip()
        if not line:
            continue

        if "Correo" in line or "Email" in line or re.search(email_regex, line):
            match = re.search(email_regex, line)
            if match:
                data["Usuario"] = match.group(0)

        elif "🔑Contraseña" in line or "Clave" in line or "Password" in line:
            match = re.search(r":\s*([^\s]+)", line)
            if match:
                data["Clave"] = match.group(1).strip()

        elif "📞Teléfono" in line or "Telefono" in line or "Phone" in line:
            match = re.search(r"\b\d{7,12}\b", line)
            if match:
                data["Telefono"] = match.group(0)

        elif "🔗Enlace" in line or "Sitio" in line or "URL" in line or "Link" in line:
            match = re.search(r"(https?://[^\s]+|www\.[^\s]+)", line)
            if match:
                data["Sitio"] = match.group(0)

    if data["Clave"]:
        complejidad = detectar_complejidad(data["Clave"])
        entropia = calcular_entropia(len(data["Clave"]), complejidad)
        return {
            "Sitio": data["Sitio"],
            "Usuario": data["Usuario"] or "[Sin usuario]",
            "Clave": data["Clave"],
            "Telefono": data["Telefono"],
            "Patron": "Datos Multi-Línea",
            "Entropia": round(entropia, 2),
            "Fuerza": clasificar_entropia(entropia)
        }
    return None


# === PROCESAMIENTO DEL ARCHIVO === #
def process_file(filepath):
    parsed_entries = []
    unparsed_lines = []

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except Exception as e:
        print(f"[ERROR] No se pudo leer el archivo {filepath}: {e}")
        return [], []

    i = 0
    while i < len(lines):
        line = lines[i].strip()
        if not line:
            i += 1
            continue

        # === PROCESAR BLOQUES MULTI-LINEA ===
        if any(tag in line for tag in ["🔑Contraseña", "📞Teléfono", "🔗Enlace", "Correo", "Email"]):
            block = []
            while i < len(lines) and len(block) < 10:
                l = lines[i].strip()
                if l:
                    block.append(l)
                i += 1
                if l == "":
                    break
            result = parse_multiline_block(block)
            if result:
                result["Archivo"] = filepath
                result["Linea"] = i - len(block) + 1
                parsed_entries.append(result)
            else:
                for l in block:
                    unparsed_lines.append({
                        "Archivo": filepath,
                        "Linea": i - len(block) + block.index(l) + 1,
                        "Contenido": l
                    })
            continue

        # === PROCESAR LINEA NORMAL ===
        result = parse_line(line)
        if result:
            result["Archivo"] = filepath
            result["Linea"] = i + 1
            parsed_entries.append(result)
        else:
            unparsed_lines.append({
                "Archivo": filepath,
                "Linea": i + 1,
                "Contenido": line
            })
        i += 1

    return parsed_entries, unparsed_lines


# === ESTADISTICAS Y SALIDA === #
def contar_por_categoria(entries):
    categorias = {
        "Muy Debil": 0,
        "Debil": 0,
        "Moderada": 0,
        "Fuerte": 0,
        "Muy Fuerte": 0
    }
    for entry in entries:
        categoria = entry.get("Fuerza", "Desconocido")
        if categoria in categorias:
            categorias[categoria] += 1
    return categorias

def grafico_ascii(categorias):
    max_bar_length = 40
    total = sum(categorias.values())
    print("\n---")
    print("Gráfico de fuerza de contraseñas:")
    print("---")
    for cat, count in categorias.items():
        percent = count / total if total else 0
        bar_len = int(max_bar_length * percent)
        bar = '#' * bar_len + '-' * (max_bar_length - bar_len)
        print(f"{cat.rjust(10)} | {bar} {count} ({percent:.1%})")
 
def tabla_longitud_contrasenas(entries):
    """Genera una tabla de contraseñas agrupadas por longitud."""
    longitudes = {}
    for entry in entries:
        clave = entry.get("Clave", "")
        largo = len(clave)
        if largo not in longitudes:
            longitudes[largo] = []
        longitudes[largo].append(entry)

    print("\n---")
    print("Tabla de contraseñas por longitud:")
    print("---")
    for largo in sorted(longitudes.keys()):
        count = len(longitudes[largo])
        print(f"- Contraseñas de {largo} caracteres: {count}")


def save_results(entries, errors, txt_output="salida.txt"):
    for idx, entry in enumerate(entries):
        entry["ID"] = idx + 1

    with open(txt_output, "w", encoding="utf-8") as f:
        f.write("=== REPORTE DE ANÁLISIS DE CREDENCIALES ===\n")
        f.write("-" * 60 + "\n")
        f.write("### RESUMEN DE ESTADÍSTICAS ###\n")
        f.write("-" * 60 + "\n")
        f.write(f"Total de credenciales analizadas: {len(entries)}\n")
        f.write(f"Líneas que no se pudieron procesar: {len(errors)}\n")

        categorias = contar_por_categoria(entries)
        f.write("Resumen por nivel de fuerza:\n")
        for categoria, cantidad in categorias.items():
            f.write(f"- {categoria.ljust(12)}: {cantidad} credenciales\n")
        f.write("\n")

        f.write("### LISTADO DETALLADO DE CREDENCIALES ###\n")
        f.write("-" * 60 + "\n")
        if entries:
            for entry in entries:
                f.write(f"ID: {entry['ID']}\n")
                f.write(f"  Archivo: {entry['Archivo']} (Línea {entry['Linea']})\n")
                f.write(f"  Sitio  : {entry['Sitio']}\n")
                f.write(f"  Usuario: {entry['Usuario']}\n")
                f.write(f"  Clave  : {entry['Clave']}\n")
                f.write(f"  Entropia: {entry['Entropia']} bits\n")
                f.write(f"  Fuerza  : {entry['Fuerza']}\n")
                f.write(f"  Patrón : {entry['Patron']}\n")
                f.write("-" * 40 + "\n")
        else:
            f.write("No se encontraron credenciales válidas.\n")

        f.write("\n### LÍNEAS NO PROCESADAS ###\n")
        f.write("-" * 60 + "\n")
        if errors:
            errors_by_file = {}
            for error in errors:
                archivo = error["Archivo"]
                if archivo not in errors_by_file:
                    errors_by_file[archivo] = []
                errors_by_file[archivo].append(error)

            for archivo, errs in errors_by_file.items():
                f.write(f"\nArchivo: {archivo}\n")
                f.write("=" * 40 + "\n")
                for err in errs:
                    f.write(f"Línea {err['Linea']}: {err['Contenido']}\n")
        else:
            f.write("Todas las líneas fueron procesadas con éxito.\n")

    print(f"\nSe han procesado {len(entries)} credenciales.")
    print(f"No se pudieron procesar {len(errors)} líneas.")
    grafico_ascii(categorias)
    tabla_longitud_contrasenas(entries)

    print("\nResumen por nivel de seguridad:")
    for categoria, cantidad in categorias.items():
        print(f"{categoria}: {cantidad}")

# === FUNCION PRINCIPAL === #
def main():
    
    parser = argparse.ArgumentParser(description="Analiza archivos o carpetas en busca de credenciales filtradas.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-a', '--archivo', type=str, help='Ruta al archivo .txt, .log, .sql, etc.')
    group.add_argument('-f', '--folder', type=str, help='Ruta a la carpeta con archivos potencialmente sensibles')
    args = parser.parse_args()

    all_parsed_entries = []
    all_unparsed_lines = []

    if args.archivo:
        print(f"\nProcesando archivo: {args.archivo}")
        entries, errors = process_file(args.archivo)
        all_parsed_entries.extend(entries)
        all_unparsed_lines.extend(errors)
    elif args.folder:
        print(f"\nBuscando archivos en carpeta: {args.folder}")
        files = find_files_in_folder(args.folder)
        if not files:
            print("No se encontraron archivos válidos en esta carpeta.")
            return
        for file in files:
            print(f"Procesando archivo: {file}")
            entries, errors = process_file(file)
            all_parsed_entries.extend(entries)
            all_unparsed_lines.extend(errors)

    if not all_parsed_entries and not all_unparsed_lines:
        print("No se encontraron datos para procesar.")
        return

    save_results(all_parsed_entries, all_unparsed_lines)

    if all_unparsed_lines:
        print("\nLíneas que no se pudieron procesar:")
        for error in all_unparsed_lines:
            print(f"{error['Archivo']} - Línea {error['Linea']}: {error['Contenido']}")
    else:
        print("\nTodas las líneas fueron procesadas exitosamente!")

    print("\nFinalizado.")


if __name__ == "__main__":
    main()