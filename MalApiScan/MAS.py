import lief
import sys
import json

# Ruta fija para el archivo JSON de malapi
MALAPI_JSON_PATH = r"malapi.json"  # Cambia esto a tu ruta específica

# Cargar las observaciones desde el archivo JSON de malapi
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
    """Imprime una tabla simple en consola."""
    # Calcular el ancho de cada columna
    col_widths = [max(len(str(item)) for item in col) for col in zip(*rows, headers)]
    header_row = " | ".join(f"{header:<{col_widths[i]}}" for i, header in enumerate(headers))
    separator = "-+-".join('-' * width for width in col_widths)

    print(header_row)
    print(separator)
    for row in rows:
        print(" | ".join(f"{str(item):<{col_widths[i]}}" for i, item in enumerate(row)))

def list_imports(file_path, observations):
    # Cargar el archivo PE
    binary = lief.PE.parse(file_path)

    if not binary:
        print(f"No se pudo parsear el archivo: {file_path}")
        return

    # Obtener la dirección base de la imagen
    image_base = hex(binary.imagebase)
    
    print(f"Importaciones de {file_path}:\n")
    print(f"{'TAGS':<28} | {'ADDR':<20} | {'NAME':<30} | {'DLL'}")
    print('-' * 80)

    # Inicializar contador por categoría
    category_count = {category: 0 for category in observations.keys()}
    total_imports = 0

    for imp in binary.imports:
        dll_name = imp.name  # Nombre de la DLL
        for entry in imp.entries:
            func_name = entry.name
            # Obtener la dirección de la función importada
            function_address = hex(entry.iat_address + binary.imagebase) if entry.iat_address != 0 else "N/A"
            # Buscar en todas las categorías
            observation_tags = []
            for category, functions in observations.items():
                if func_name in functions:
                    observation_tags.append(category)
                    category_count[category] += 1  # Incrementar el contador para la categoría
            if observation_tags:
                tags = ', '.join(observation_tags)
                print(f"{tags:<28} | {function_address:<20} | {func_name:<30} | {dll_name}")
                total_imports += 1

    # Resumen por categorías
    print("\nResumen por categorías:\n")
    summary_rows = [[category, count] for category, count in category_count.items()]
    print_table(["Categoría", "Total"], summary_rows)

    print(f"\nTotal de funciones importadas encontradas: {total_imports}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: python scan.py <ruta_al_archivo_PE>")
        sys.exit(1)

    input_file = sys.argv[1]

    # Cargar las observaciones de malapi
    observations = load_malapi_observations()

    # Listar las importaciones del archivo PE
    list_imports(input_file, observations)