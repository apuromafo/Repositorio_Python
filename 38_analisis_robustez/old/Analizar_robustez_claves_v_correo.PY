import os
import re
import math
import csv
import argparse
from pathlib import Path

# === FUNCIONES DE DETECCIÓN Y CLASIFICACIÓN === #

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
        32 if complejidad['especiales'] else 0  # Aproximado
    ])
    if num_caracteres == 0:
        return 0
    return longitud * math.log2(num_caracteres)

def clasificar_entropia(entropia):
    """Clasifica la entropía de la contraseña."""
    if entropia < 41:
        return "Muy Débil"
    elif entropia < 61:
        return "Débil"
    elif entropia < 81:
        return "Moderada"
    elif entropia < 101:
        return "Fuerte"
    else:
        return "Muy Fuerte"

# === PATRONES DE PARSEO === #

def parse_line(line):
    line = line.strip()
    line = re.sub(r'\s+', ' ', line).strip()
    if ';' in line:
        line = line.replace(';', ':')

    # Caso nuevo: correo:clave
    email_pass_match = re.match(
        r"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\:([\w\-\.!@#$%^&*()]+)",
        line
    )
    if email_pass_match:
        clave = email_pass_match.group(2)
        complejidad = detectar_complejidad(clave)
        entropia = calcular_entropia(len(clave), complejidad)
        return {
            "Sitio": "[Sin sitio]",
            "Usuario": email_pass_match.group(1),
            "Clave": clave,
            "Patrón": "Email:Clave",
            "Entropía": round(entropia, 2),
            "Fuerza": clasificar_entropia(entropia)
        }

    # Caso general: usuario:clave
    user_pass_match = re.match(
        r"^([\w\-.@]+)\:([\w\-\.!@#$%^&*()\[\]]+)$",
        line
    )
    if user_pass_match and ":" in line and line.count(":") == 1:
        clave = user_pass_match.group(2).strip('[]')
        complejidad = detectar_complejidad(clave)
        entropia = calcular_entropia(len(clave), complejidad)
        return {
            "Sitio": "[Desconocido]",
            "Usuario": user_pass_match.group(1),
            "Clave": clave,
            "Patrón": "Usuario:Clave",
            "Entropía": round(entropia, 2),
            "Fuerza": clasificar_entropia(entropia)
        }

    # Otros casos ya definidos...

    # Ignorar líneas vacías o con "$:$"
    if re.search(r".*\:\$\:.*", line) or re.search(r"::$", line):
        return None

    return None

# === PROCESAMIENTO DEL ARCHIVO === #

def process_file(filepath):
    parsed_entries = []
    unparsed_lines = []

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except Exception as e:
        print(f"[ERROR] No se pudo leer el archivo: {filepath} | Error: {e}")
        return [], []

    for i, line in enumerate(lines):
        line = line.strip()
        if not line:
            continue
        result = parse_line(line)
        if result:
            parsed_entries.append(result)
        else:
            unparsed_lines.append(f"Línea {i + 1}: {line}")

    return parsed_entries, unparsed_lines

# === BUSQUEDA RECURSIVA EN CARPETAS === #

def find_files_in_folder(folder_path, extensions=[".txt", ".log", ".sql", ".csv"]):
    files_to_process = []
    for root, _, files in os.walk(folder_path):
        for file in files:
            if any(file.endswith(ext) for ext in extensions):
                files_to_process.append(os.path.join(root, file))
    return files_to_process

# === GUARDADO DE RESULTADOS === #

def contar_por_categoria(entries):
    categorias = {
        "Muy Débil": 0,
        "Débil": 0,
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
    print("\n📊 Gráfico de barras de fuerza de contraseñas:")
    for cat, count in categorias.items():
        percent = count / total if total else 0
        bar_len = int(max_bar_length * percent)
        bar = '#' * bar_len + '-' * (max_bar_length - bar_len)
        print(f"{cat.rjust(10)} | {bar} {count} ({percent:.1%})")

def save_results(entries, errors, txt_output="salida.txt", csv_output="salida.csv"):
    # Añadir ID único a cada entrada
    for idx, entry in enumerate(entries):
        entry["ID"] = idx + 1

    with open(txt_output, "w", encoding="utf-8") as f:
        f.write("=== CREDENCIALES FILTRADAS ===\n\n")
        for entry in entries:
            f.write(f"ID: {entry['ID']}\n")
            f.write(f"Sitio: {entry['Sitio']}\n")
            f.write(f"Usuario: {entry['Usuario']}\n")
            f.write(f"Clave: {entry['Clave']}\n")
            f.write(f"Patrón: {entry['Patrón']}\n")
            f.write(f"Entropía: {entry['Entropía']} bits\n")
            f.write(f"Fuerza: {entry['Fuerza']}\n")
            f.write("-" * 60 + "\n")

        # Resumen por categoría
        categorias = contar_por_categoria(entries)
        f.write("\n=== RESUMEN DE CONTRASEÑAS POR NIVEL ===\n\n")
        for categoria, cantidad in categorias.items():
            f.write(f"{categoria}: {cantidad}\n")

        # Líneas no procesadas
        f.write("\n=== LÍNEAS NO PROCESADAS ===\n")
        for error in errors:
            f.write(f"{error}\n")

    print(f"\n✅ Se han procesado {len(entries)} credenciales.")
    print(f"❌ No se pudieron procesar {len(errors)} líneas.")

    grafico_ascii(categorias)

    print("\n📊 Resumen por nivel de seguridad:")
    for categoria, cantidad in categorias.items():
        print(f"{categoria}: {cantidad}")

    if csv_output:
        with open(csv_output, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["ID", "Sitio", "Usuario", "Clave", "Patrón", "Entropía", "Fuerza"])
            writer.writeheader()
            writer.writerows(entries)
        print(f"📄 Datos también guardados en: {csv_output}")

# === FUNCIÓN PRINCIPAL CON ARGPARSE === #

def main():
    parser = argparse.ArgumentParser(description="Analiza archivos o carpetas en busca de credenciales filtradas.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-a', '--archivo', type=str, help='Ruta al archivo .txt, .log, .sql, etc.')
    group.add_argument('-f', '--folder', type=str, help='Ruta a la carpeta con archivos potencialmente sensibles')
    args = parser.parse_args()

    all_parsed_entries = []
    all_unparsed_lines = []

    if args.archivo:
        print(f"\n🔍 Procesando archivo: {args.archivo}")
        entries, errors = process_file(args.archivo)
        all_parsed_entries.extend(entries)
        all_unparsed_lines.extend(errors)
    elif args.folder:
        print(f"\n📁 Buscando archivos en carpeta: {args.folder}")
        files = find_files_in_folder(args.folder)
        if not files:
            print("❌ No se encontraron archivos válidos en esta carpeta.")
            return
        for file in files:
            print(f"📄 Procesando archivo: {file}")
            entries, errors = process_file(file)
            all_parsed_entries.extend(entries)
            all_unparsed_lines.extend(errors)

    save_results(all_parsed_entries, all_unparsed_lines)

    if all_unparsed_lines:
        print("\n❌ Líneas que no se pudieron procesar:")
        for error in all_unparsed_lines:
            print(error)
    else:
        print("\n✅ ¡Todas las líneas fueron procesadas exitosamente!")

    print("\nFinalizado.")

if __name__ == "__main__":
    main()