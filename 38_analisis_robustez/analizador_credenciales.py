import re
import math
import csv
#para parametros de entrada
import os
import argparse
from pathlib import Path


# === FUNCIONES DE ENTROPÍA Y CLASIFICACIÓN === #

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

    # Nuevo caso: correo:clave
    email_pass_match = re.match(
        r"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\:([\w\-\.!@#$%^&*()\[\]]+)",
        line
    )
    if email_pass_match:
        clave = email_pass_match.group(2).strip('[]')
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

    # Nuevo caso: url:correo:clave
    url_email_pass_match = re.match(
        r"(https?://[^:\s]+|www\..+)\:([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\:([\w\-\.!@#$%^&*()\[\]]+)",
        line
    )
    if url_email_pass_match:
        clave = url_email_pass_match.group(3).strip('[]')
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

    # Caso especial: android://token@url:user:pass
    android_match = re.match(
        r"^android://([a-zA-Z0-9+\/=._%-]+)@([^/]+/?)\:([\d\.\-\w]+)\:([\w\-\.!@#$%^&*()\[\]]+)$",
        line
    )
    if android_match:
        clave = android_match.group(4).strip('[]')
        complejidad = detectar_complejidad(clave)
        entropia = calcular_entropia(len(clave), complejidad)
        return {
            "Sitio": f"Android - {android_match.group(2)}",
            "Usuario": android_match.group(3),
            "Clave": clave,
            "Patron": "Android App Pattern",
            "Entropia": round(entropia, 2),
            "Fuerza": clasificar_entropia(entropia)
        }

    # Caso especial: token@url:user:pass
    android_plain_match = re.match(
        r"^([a-zA-Z0-9+\/=._%-]+)@([^:]+):([\w\-.@]+):([\w\-\.!@#$%^&*()\[\]]+)$",
        line
    )
    if android_plain_match:
        clave = android_plain_match.group(4).strip('[]')
        complejidad = detectar_complejidad(clave)
        entropia = calcular_entropia(len(clave), complejidad)
        return {
            "Sitio": f"App - {android_plain_match.group(2)}",
            "Usuario": android_plain_match.group(3),
            "Clave": clave,
            "Patron": "Token@URL:User:Pass",
            "Entropia": round(entropia, 2),
            "Fuerza": clasificar_entropia(entropia)
        }

    # Caso especial: correo:clave:url
    email_url_match = re.match(
        r"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}):([\w\-\.!@#$%^&*()]+):(https?://[^:]+)", line
    )
    if email_url_match:
        clave = email_url_match.group(2)
        complejidad = detectar_complejidad(clave)
        entropia = calcular_entropia(len(clave), complejidad)
        return {
            "Sitio": email_url_match.group(3),
            "Usuario": email_url_match.group(1),
            "Clave": clave,
            "Patron": "Email:Pass:URL",
            "Entropia": round(entropia, 2),
            "Fuerza": clasificar_entropia(entropia)
        }

    # Caso especial: url::clave (sin usuario)
    empty_user_match = re.match(r"(https?://[^:]+)::([\w\-\.!@#$%^&*()\[\]]+)", line)
    if empty_user_match:
        clave = empty_user_match.group(2).strip('[]')
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

    # Caso general: URL:user:pass
    standard_match = re.match(
        r"(https?://[^:\s]+|www\..+):([\w\-.@]+):([\w\-\.!@#$%^&*()\[\]]+)",
        line
    )
    if standard_match:
        user = standard_match.group(2)
        if user == "$":
            return None
        clave = standard_match.group(3).strip('[]')
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

    # Dominio:rut:clave
    plain_domain_match = re.match(
        r"([^:/]+[/\w\-\.]*)\:([\d\.\-\w]+)\:([\w\-\.!@#$%^&*()\[\]]+)",
        line
    )
    if plain_domain_match:
        clave = plain_domain_match.group(3).strip('[]')
        complejidad = detectar_complejidad(clave)
        entropia = calcular_entropia(len(clave), complejidad)
        return {
            "Sitio": plain_domain_match.group(1),
            "Usuario": plain_domain_match.group(2),
            "Clave": clave,
            "Patron": "Dominio:RUT:Clave",
            "Entropia": round(entropia, 2),
            "Fuerza": clasificar_entropia(entropia)
        }

    # Rut:clave sin sitio
    simple_rut_match = re.match(r"^([\d\.\-]+):(.+)", line)
    if simple_rut_match and ":" in line and line.count(":") == 1:
        clave = simple_rut_match.group(2)
        complejidad = detectar_complejidad(clave)
        entropia = calcular_entropia(len(clave), complejidad)
        return {
            "Sitio": "[Desconocido]",
            "Usuario": simple_rut_match.group(1),
            "Clave": clave,
            "Patron": "RUT:Clave",
            "Entropia": round(entropia, 2),
            "Fuerza": clasificar_entropia(entropia)
        }

    # https://login...      rut:clave
    space_match = re.match(r"(https?://[^:\s]+)\s+([\d\.\-]+):(.+)", line)
    if space_match:
        clave = space_match.group(3)
        complejidad = detectar_complejidad(clave)
        entropia = calcular_entropia(len(clave), complejidad)
        return {
            "Sitio": space_match.group(1),
            "Usuario": space_match.group(2),
            "Clave": clave,
            "Patron": "URL[espacio]RUT:Clave",
            "Entropia": round(entropia, 2),
            "Fuerza": clasificar_entropia(entropia)
        }

    # Dominio:correo:clave
    email_site_match = re.match(
        r"([^:/]+[/\w\-\.]*)\:([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\:([\w\-\.!@#$%^&*()]+)",
        line
    )
    if email_site_match:
        clave = email_site_match.group(3)
        complejidad = detectar_complejidad(clave)
        entropia = calcular_entropia(len(clave), complejidad)
        return {
            "Sitio": email_site_match.group(1),
            "Usuario": email_site_match.group(2),
            "Clave": clave,
            "Patron": "Dominio:Correo:Clave",
            "Entropia": round(entropia, 2),
            "Fuerza": clasificar_entropia(entropia)
        }

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
    except FileNotFoundError:
        print(f"[ERROR] Archivo no encontrado: {filepath}")
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


# === ESTADÍSTICAS Y SALIDA === #

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
    print("\n📊 Gráfico de fuerza de contraseñas:")
    for cat, count in categorias.items():
        percent = count / total if total else 0
        bar_len = int(max_bar_length * percent)
        bar = '#' * bar_len + '-' * (max_bar_length - bar_len)
        print(f"{cat.rjust(10)} | {bar} {count} ({percent:.1%})")


def save_results(entries, errors, txt_output="salida.txt", csv_output="salida.csv"):
    # Añadimos ID único a cada entrada
    for idx, entry in enumerate(entries):
        entry["ID"] = idx + 1

    with open(txt_output, "w", encoding="utf-8") as f:
        f.write("=== CREDENCIALES FILTRADAS ===\n\n")
        for entry in entries:
            f.write(f"ID: {entry['ID']}\n")
            f.write(f"Sitio: {entry['Sitio']}\n")
            f.write(f"Usuario: {entry['Usuario']}\n")
            f.write(f"Clave: {entry['Clave']}\n")
            f.write(f"Patron: {entry['Patron']}\n")
            f.write(f"Entropia: {entry['Entropia']} bits\n")
            f.write(f"Fuerza: {entry['Fuerza']}\n")
            f.write("-" * 60 + "\n")

        # Resumen por categoría
        categorias = contar_por_categoria(entries)
        f.write("\n=== RESUMEN POR NIVEL DE FUERZA ===\n\n")
        for categoria, cantidad in categorias.items():
            f.write(f"{categoria}: {cantidad}\n")

        # Líneas no procesadas
        f.write("\n=== LINEAS NO PROCESADAS ===\n")
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
            writer = csv.DictWriter(f, fieldnames=["ID", "Sitio", "Usuario", "Clave", "Patron", "Entropia", "Fuerza"])
            writer.writeheader()
            writer.writerows(entries)
        print(f"📄 Datos también guardados en: {csv_output}")


# === FUNCIÓN PRINCIPAL === #

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