import lief
import sys
import json
import os
import glob
from datetime import datetime

#malapi.json es obtenido desde github (010_malapi_json) que a su vez proviene de malapi.io
MALAPI_JSON_PATH = r"malapi.json"  # Cambia esto a tu ruta específica

def load_malapi_observations():
    try:
        with open(MALAPI_JSON_PATH, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return data['Categories']
    except FileNotFoundError:
        print(f"Error: No se encontró el archivo en la ruta: {MALAPI_JSON_PATH}")
        sys.exit(1)
    except json.JSONDecodeError:
        print("Error: El archivo JSON no está bien formado.")
        sys.exit(1)

def print_table(headers, rows, log_file=None):
    if not rows:  # Si no hay filas, no hacemos nada
        return

    col_widths = [max(len(str(item)) for item in col) for col in zip(*rows, headers)]
    header_row = " | ".join(f"{header:<{col_widths[i]}}" for i, header in enumerate(headers))
    separator = "-+-".join('-' * width for width in col_widths)

    output = [header_row, separator]
    for row in rows:
        if len(row) != len(headers):
            print("Error: La fila no coincide con el número de encabezados.")
            continue  # O manejar el error como desees
        output.append(" | ".join(f"{str(item):<{col_widths[i]}}" for i, item in enumerate(row)))

    # Imprimir y escribir en el log si se especifica
    final_output = "\n".join(output)
    print(final_output)
    if log_file:
        log_file.write(final_output + "\n")

def list_imports(file_path, observations, log_file=None):
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
    output_headers = ['TAGS', 'ADDR', 'NAME', 'DLL']
    print_table(output_headers, [], log_file)  # Imprimir solo los encabezados

    category_count = {category: 0 for category in observations.keys()}
    total_imports = 0
    rows = []  # Lista para almacenar las filas a imprimir

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
                rows.append([tags, function_address, func_name, dll_name])  # Agregar fila
                total_imports += 1

    # Imprimir filas recopiladas
    if rows:
        print_table(output_headers, rows, log_file)  # Llamar con encabezados

    print("\nResumen por categorías:\n")
    summary_rows = [[category, count] for category, count in category_count.items()]
    print_table(["Categoría", "Total"], summary_rows, log_file)

    print(f"\nTotal de funciones importadas encontradas: {total_imports}")
    if log_file:
        log_file.write(f"\nTotal de funciones importadas encontradas: {total_imports}\n")

def print_usage():
    print("Uso: python scan.py -a <ruta_al_archivo_PE> [-o salida.txt]")
    print("   o: python scan.py -f <ruta_a_la_carpeta> [-o salida.txt]")
    print("Opciones:")
    print("  -h, --help   Muestra este mensaje de ayuda y sale.")

if __name__ == "__main__":
    output_file = None
    if len(sys.argv) < 3:
        if len(sys.argv) == 1 or (len(sys.argv) == 2 and sys.argv[1] in ["-h", "--help"]):
            print_usage()
            sys.exit(0)
        else:
            print("Error: Argumento no válido. Usa -h para ayuda.")
            sys.exit(1)

    mode = sys.argv[1]
    path = sys.argv[2]

    # Manejo del archivo de salida
    if len(sys.argv) == 5 and sys.argv[3] == "-o":
        output_file = sys.argv[4]

    observations = load_malapi_observations()

    if mode == "-a":
        if not os.path.isfile(path):
            print(f"Error: No se encontró el archivo: {path}")
            sys.exit(1)

        # Definir el nombre del archivo de log si no se especifica
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"{os.path.splitext(path)[0]}_{timestamp}_info.log"

        with open(output_file, 'w', encoding='utf-8') as log_file:
            list_imports(path, observations, log_file)

    elif mode == "-f":
        if os.path.isfile(path):
            path = os.path.dirname(path)

        if not os.path.isdir(path):
            print(f"Error: No se encontró la carpeta: {path}")
            sys.exit(1)

        files = glob.glob(os.path.join(path, "*"))
        if not files:
            print(f"No se encontraron archivos en la carpeta: {path}")
            sys.exit(1)

        for file in files:
            if os.path.isfile(file):
                # Definir el nombre del archivo de log para cada archivo analizado
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                log_file_name = f"{os.path.splitext(file)[0]}_{timestamp}_info.log"
                with open(log_file_name, 'w', encoding='utf-8') as log_file:
                    list_imports(file, observations, log_file)

    else:
        print("Error: Opción no válida. Usa -h para ayuda.")
        sys.exit(1)