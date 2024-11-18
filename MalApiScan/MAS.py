import lief
import sys
import json
import os
import glob

MALAPI_JSON_PATH = r"malapi.json"  # Cambia esto a tu ruta específica

def load_malapi_observations():
    try:
        with open(MALAPI_JSON_PATH, 'r') as f:
            data = json.load(f)
        return data['Categories']
    except FileNotFoundError:
        print(f"Error: No se encontró el archivo en la ruta: {MALAPI_JSON_PATH}")
        sys.exit(1)
    except json.JSONDecodeError:
        print("Error: El archivo JSON no está bien formado.")
        sys.exit(1)

def print_table(headers, rows):
    col_widths = [max(len(str(item)) for item in col) for col in zip(*rows, headers)]
    header_row = " | ".join(f"{header:<{col_widths[i]}}" for i, header in enumerate(headers))
    separator = "-+-".join('-' * width for width in col_widths)

    print(header_row)
    print(separator)
    for row in rows:
        print(" | ".join(f"{str(item):<{col_widths[i]}}" for i, item in enumerate(row)))

def list_imports(file_path, observations):
    try:
        binary = lief.PE.parse(file_path)
    except lief.exception as e:
        print(f"Error: No se pudo procesar el archivo: {file_path}. Detalle: {str(e)}")
        return
    except Exception as e:
        print(f"Error inesperado al procesar el archivo: {file_path}. Detalle: {str(e)}")
        return

    if not binary:
        print(f"No se pudo parsear el archivo: {file_path}")
        return

    print(f"Importaciones de {file_path}:\n")
    print(f"{'TAGS':<28} | {'ADDR':<20} | {'NAME':<30} | {'DLL'}")
    print('-' * 80)

    category_count = {category: 0 for category in observations.keys()}
    total_imports = 0

    for imp in binary.imports:
        dll_name = imp.name
        for entry in imp.entries:
            func_name = entry.name
            function_address = hex(entry.iat_address + binary.imagebase) if entry.iat_address != 0 else "N/A"
            observation_tags = []
            for category, functions in observations.items():
                if func_name in functions:
                    observation_tags.append(category)
                    category_count[category] += 1
            if observation_tags:
                tags = ', '.join(observation_tags)
                print(f"{tags:<28} | {function_address:<20} | {func_name:<30} | {dll_name}")
                total_imports += 1

    print("\nResumen por categorías:\n")
    summary_rows = [[category, count] for category, count in category_count.items()]
    print_table(["Categoría", "Total"], summary_rows)

    print(f"\nTotal de funciones importadas encontradas: {total_imports}")

def print_usage():
    print("Uso: python scan.py -a <ruta_al_archivo_PE>")
    print("   o: python scan.py -f <ruta_a_la_carpeta>")
    print("Opciones:")
    print("  -h, --help   Muestra este mensaje de ayuda y sale.")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        if len(sys.argv) == 1 or (len(sys.argv) == 2 and sys.argv[1] in ["-h", "--help"]):
            print_usage()
            sys.exit(0)  # Salir normalmente cuando se muestra ayuda
        else:
            print("Error: Argumento no válido. Usa -h para ayuda.")
            sys.exit(1)

    mode = sys.argv[1]
    path = sys.argv[2]

    observations = load_malapi_observations()

    if mode == "-a":
        # Procesar un archivo específico
        if not os.path.isfile(path):
            print(f"Error: No se encontró el archivo: {path}")
            sys.exit(1)
        list_imports(path, observations)

    elif mode == "-f":
        # Si se pasa un archivo, extraer la carpeta
        if os.path.isfile(path):
            path = os.path.dirname(path)  # Extraer la carpeta del archivo

        # Verificar si la ruta es una carpeta
        if not os.path.isdir(path):
            print(f"Error: No se encontró la carpeta: {path}")
            sys.exit(1)

        # Buscar todos los archivos en la carpeta
        files = glob.glob(os.path.join(path, "*"))  # Cambiar para buscar todos los archivos
        if not files:
            print(f"No se encontraron archivos en la carpeta: {path}")
            sys.exit(1)

        for file in files:
            if os.path.isfile(file):  # Asegurarse de que sea un archivo
                list_imports(file, observations)

    else:
        print("Error: Opción no válida. Usa -h para ayuda.")
        sys.exit(1)