import sys
import argparse

def encode_message_to_binary(message):
    """
    Codifica un mensaje de texto a una lista de cadenas binarias de 8 bits
    y devuelve los datos en un formato listo para imprimir en tabla.
    """
    table_data = []
    for char in message:
        decimal_value = ord(char)
        binary_string = f"{decimal_value:08b}"
        table_data.append({
            "character": char,
            "decimal": decimal_value,
            "binary": binary_string
        })
    return table_data

def decode_binary_to_message(binary_strings_list):
    """
    Decodifica una lista de cadenas binarias (base 2) a un mensaje de texto.
    """
    decoded_message = ""
    table_data = []
    
    # Asegurarse de que la entrada es una lista de strings binarios
    if isinstance(binary_strings_list, str):
        # Si es un solo string largo de binarios (ej. "0100001101111001...")
        # lo dividimos en bloques de 8 bits
        if len(binary_strings_list) % 8 != 0:
            raise ValueError("La cadena binaria de entrada tiene una longitud inválida para bloques de 8 bits.")
        chunks = [binary_strings_list[i:i+8] for i in range(0, len(binary_strings_list), 8)]
    else: # Esperamos que sea una lista
        chunks = binary_strings_list

    for binary_string in chunks:
        try:
            decimal_value = int(binary_string, 2)
            character = chr(decimal_value)
            decoded_message += character
            table_data.append({
                "binary": binary_string,
                "decimal": decimal_value,
                "character": character
            })
        except ValueError:
            raise ValueError(f"'{binary_string}' no es una cadena binaria válida (contiene caracteres distintos de 0 o 1).")
        except OverflowError:
            raise ValueError(f"'{binary_string}' es demasiado grande para ser un carácter ASCII/UTF-8 válido.")
    return decoded_message, table_data

def print_table(data, mode="encode"):
    """
    Imprime los datos en un formato de tabla ordenado.
    'mode' puede ser 'encode' o 'decode' para ajustar los encabezados.
    """
    if not data:
        print("No hay datos para mostrar.")
        return

    # Ajustar anchos de columna dinámicamente o mantener fijos para consistencia
    if mode == "encode":
        char_width = max(len("Caracter"), max(len(row["character"]) for row in data))
        decimal_width = max(len("Decimal"), max(len(str(row["decimal"])) for row in data))
        binary_width = max(len("Binario"), max(len(row["binary"]) for row in data))
        
        header = f"| {'Caracter'.ljust(char_width)} | {'Decimal'.ljust(decimal_width)} | {'Binario'.ljust(binary_width)} |"
        separator_length = len(header)
        
        print("-" * separator_length)
        print(header)
        print("-" * separator_length)
        for row in data:
            print(f"| {row['character'].ljust(char_width)} | {str(row['decimal']).ljust(decimal_width)} | {row['binary'].ljust(binary_width)} |")
        print("-" * separator_length)
    
    elif mode == "decode":
        binary_width = max(len("Binario"), max(len(row["binary"]) for row in data))
        decimal_width = max(len("Decimal"), max(len(str(row["decimal"])) for row in data))
        char_width = max(len("Caracter"), max(len(row["character"]) for row in data))
        
        header = f"| {'Binario'.ljust(binary_width)} | {'Decimal'.ljust(decimal_width)} | {'Caracter'.ljust(char_width)} |"
        separator_length = len(header)
        
        print("-" * separator_length)
        print(header)
        print("-" * separator_length)
        for row in data:
            print(f"| {row['binary'].ljust(binary_width)} | {str(row['decimal']).ljust(decimal_width)} | {row['character'].ljust(char_width)} |")
        print("-" * separator_length)

def write_output_to_file(filename, content):
    """
    Escribe el contenido dado en un archivo.
    """
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"\nResultados guardados en '{filename}'.")
    except IOError as e:
        print(f"\nError al escribir en el archivo '{filename}': {e}")

def read_binary_from_file(filename):
    """
    Lee contenido binario de un archivo de texto.
    Elimina espacios en blanco y saltos de línea para obtener solo la secuencia binaria.
    """
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            content = f.read()
            # Limpiar el contenido para asegurar que solo sean '0' y '1'
            cleaned_content = ''.join(c for c in content if c in '01')
            return cleaned_content
    except FileNotFoundError:
        print(f"Error: El archivo '{filename}' no fue encontrado.")
        sys.exit(1)
    except IOError as e:
        print(f"Error al leer el archivo '{filename}': {e}")
        sys.exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Herramienta para codificar texto a binario y decodificar binario a texto.",
        epilog="Ejemplos:\n  python bin_converter.py -s \"Hola Mundo\" -o output_binary.txt\n  python bin_converter.py -d \"01001000011011110110110001100001\" -o output_text.txt\n  python bin_converter.py --decode_file input_binary.txt\n  python bin_converter.py  (para modo interactivo)",
        formatter_class=argparse.RawTextHelpFormatter # Permite saltos de línea en epilog
    )

    # Argumentos para codificación
    parser.add_argument("-s", "--string_encode", type=str,
                        help="Mensaje de texto a codificar a binario.")
    
    # Argumentos para decodificación
    parser.add_argument("-d", "--string_decode", type=str,
                        help="Cadena(s) binaria(s) a decodificar a texto. Puede ser una sola cadena larga o múltiples separadas por espacio (ej. '01000011 01111001').")
    
    parser.add_argument("--decode_file", type=str,
                        help="Ruta a un archivo que contiene datos binarios para decodificar.")

    # Argumento para la salida a archivo
    parser.add_argument("-o", "--output_file", type=str,
                        help="Ruta del archivo donde se guardará la salida.")

    args = parser.parse_args()

    # --- Lógica principal del script ---
    
    if args.string_encode:
        print(f"\n--- INICIANDO CODIFICACIÓN ---")
        encoded_data = encode_message_to_binary(args.string_encode)
        print_table(encoded_data, mode="encode")
        
        # Preparar la salida final para el archivo
        output_content = ""
        for row in encoded_data:
            output_content += f"{row['binary']}\n" # Cada binario en una nueva línea para el archivo

        if args.output_file:
            write_output_to_file(args.output_file, output_content)

    elif args.string_decode or args.decode_file:
        print(f"\n--- INICIANDO DECODIFICACIÓN ---")
        binary_input = None

        if args.string_decode:
            # Si el usuario ingresa binarios separados por espacio, los convertimos a una lista
            # Si es un solo string largo, lo pasamos tal cual para que decode_binary_to_message lo maneje
            if ' ' in args.string_decode:
                binary_input = args.string_decode.split()
            else:
                binary_input = args.string_decode

        elif args.decode_file:
            binary_input = read_binary_from_file(args.decode_file)
            print(f"Leyendo binarios de '{args.decode_file}'.")
            # Si el archivo tiene muchos binarios, podría ser útil mostrar una vista previa.
            # print(f"Contenido binario leído (parcial): {binary_input[:100]}...")


        if binary_input:
            try:
                decoded_message, decoded_table_data = decode_binary_to_message(binary_input)
                print_table(decoded_table_data, mode="decode")
                print(f"\n--- MENSAJE DECODIFICADO ---")
                print(decoded_message)
                print("--------------------------")

                if args.output_file:
                    write_output_to_file(args.output_file, decoded_message)
            except ValueError as e:
                print(f"Error al decodificar: {e}")
        else:
            print("No se proporcionaron datos binarios para decodificar.")

    else:
        # Modo interactivo si no se proporcionan argumentos
        print("\n--- MODO INTERACTIVO ---")
        print("Selecciona una opción:")
        print("1. Codificar texto a binario")
        print("2. Decodificar binario a texto")
        print("3. Salir")

        while True:
            choice = input("Ingresa tu elección (1/2/3): ")

            if choice == '1':
                message = input("Ingresa el texto a codificar: ")
                if message:
                    encoded_data = encode_message_to_binary(message)
                    print_table(encoded_data, mode="encode")
                    output_choice = input("¿Guardar la salida binaria en un archivo? (s/n): ")
                    if output_choice.lower() == 's':
                        filename = input("Ingresa el nombre del archivo de salida (ej. binario.txt): ")
                        if filename:
                            output_content = ""
                            for row in encoded_data:
                                output_content += f"{row['binary']}\n"
                            write_output_to_file(filename, output_content)
                else:
                    print("No se ingresó texto para codificar.")
            
            elif choice == '2':
                decode_type = input("¿Decodificar desde un string (s) o desde un archivo (a)? (s/a): ")
                if decode_type.lower() == 's':
                    binary_str_input = input("Ingresa la cadena binaria (ej. '0100001101111001' o '01000011 01111001'): ")
                    if binary_str_input:
                        binary_to_decode = binary_str_input.split() if ' ' in binary_str_input else binary_str_input
                        try:
                            decoded_message, decoded_table_data = decode_binary_to_message(binary_to_decode)
                            print_table(decoded_table_data, mode="decode")
                            print(f"\n--- MENSAJE DECODIFICADO ---")
                            print(decoded_message)
                            print("--------------------------")
                            output_choice = input("¿Guardar el mensaje decodificado en un archivo? (s/n): ")
                            if output_choice.lower() == 's':
                                filename = input("Ingresa el nombre del archivo de salida (ej. mensaje.txt): ")
                                if filename:
                                    write_output_to_file(filename, decoded_message)
                        except ValueError as e:
                            print(f"Error al decodificar: {e}")
                    else:
                        print("No se ingresó cadena binaria para decodificar.")
                elif decode_type.lower() == 'a':
                    filename = input("Ingresa el nombre del archivo con binarios (ej. binario_input.txt): ")
                    if filename:
                        binary_from_file = read_binary_from_file(filename)
                        if binary_from_file:
                            try:
                                decoded_message, decoded_table_data = decode_binary_to_message(binary_from_file)
                                print_table(decoded_table_data, mode="decode")
                                print(f"\n--- MENSAJE DECODIFICADO ---")
                                print(decoded_message)
                                print("--------------------------")
                                output_choice = input("¿Guardar el mensaje decodificado en un archivo? (s/n): ")
                                if output_choice.lower() == 's':
                                    output_filename = input("Ingresa el nombre del archivo de salida (ej. mensaje.txt): ")
                                    if output_filename:
                                        write_output_to_file(output_filename, decoded_message)
                            except ValueError as e:
                                print(f"Error al decodificar: {e}")
                        else:
                            print("El archivo no contiene binarios válidos.")
                else:
                    print("Opción no válida.")
            
            elif choice == '3':
                print("Saliendo del programa.")
                break
            else:
                print("Opción no válida. Por favor, elige 1, 2 o 3.")