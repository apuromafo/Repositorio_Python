# -*- coding: utf-8 -*-
import sys
import json
import re
import os
import urllib.parse
import textwrap
from datetime import datetime

def parse_curl_command(curl_command_str):
    """
    Analiza una cadena de comando curl individual y extrae sus componentes.
    """
    cleaned_command = re.sub(r'[\^\\\\]\s*\n', ' ', curl_command_str).strip()
    cleaned_command = cleaned_command.replace('^^', '__CARET_ESCAPED_PLACEHOLDER__')
    
    def replace_cmd_escape(match):
        escaped_char = match.group(1)
        if escaped_char in '"%&|<>() ':
            return escaped_char
        return escaped_char

    cleaned_command = re.sub(r'\^(.)', replace_cmd_escape, cleaned_command)
    cleaned_command = cleaned_command.replace('__CARET_ESCAPED_PLACEHOLDER__', '^')

    method = "GET"
    method_match = re.search(r"-X\s+['\"]?(\S+)['\"]?", cleaned_command)
    if method_match:
        method = method_match.group(1).upper()

    url = None
    url_pattern = r"curl\s+(?:-X\s+['\"]?\S+['\"]?\s+)?(?:'([^']+)'|\"([^\"]+)\"|(\S+))"
    url_match = re.search(url_pattern, cleaned_command)
    if url_match:
        url = url_match.group(1) or url_match.group(2) or url_match.group(3)
        if url:
            url = url.replace('\\"', '"').replace("\\'", "'")
            try:
                decoded_url = urllib.parse.unquote(url)
                url = urllib.parse.quote(decoded_url, safe='/:?&=')
            except Exception as e:
                print(f"Advertencia: Error al normalizar la URL '{url}': {e}. Se usará la URL original.")

    headers = {}
    header_matches = re.findall(r"-H\s+'((?:[^'\\]|\\.)*)'|-H\s+\"((?:[^\"\\]|\\.)*)\"", cleaned_command, re.DOTALL)
    for match_tuple in header_matches:
        header_str = match_tuple[0] if match_tuple[0] is not None else match_tuple[1]
        header_str = header_str.replace('\\"', '"').replace("\\'", "'")
        parts = header_str.split(':', 1)
        if len(parts) == 2:
            key = parts[0].strip()
            value = parts[1].strip()
            headers[key] = value

    cookies = {}
    cookie_match = re.search(r"-b\s+(?:'((?:[^'\\]|\\.)*)'|\"((?:[^\"\\]|\\.)*)\")", cleaned_command, re.DOTALL)
    if cookie_match:
        cookie_string = cookie_match.group(1) if cookie_match.group(1) is not None else cookie_match.group(2)
        cookie_string = cookie_string.replace('\\"', '"').replace("\\'", "'")
        for cookie_pair in cookie_string.split(';'):
            if '=' in cookie_pair:
                key, value = cookie_pair.split('=', 1)
                cookies[key.strip()] = value.strip()

    data = None
    data_match = re.search(r"-d\s+(?:'((?:[^'\\]|\\.)*)'|\"((?:[^\"\\]|\\.)*)\")", cleaned_command, re.DOTALL)
    if data_match:
        data_str = data_match.group(1) if data_match.group(1) is not None else data_match.group(2)
        data_str = data_str.replace('\\"', '"').replace("\\'", "'")
        try:
            data = json.loads(data_str)
        except json.JSONDecodeError:
            data = data_str

    if method == "POST" and "content-length" in headers and headers["content-length"] == "0" and data is None:
        data = ""

    return {
        "method": method,
        "url": url,
        "headers": headers,
        "cookies": cookies,
        "data": data
    }

def generate_python_request(parsed_command):
    """Genera el código Python de requests con el formato mejorado y manejo de archivos."""
    method = parsed_command["method"].lower()
    url = parsed_command["url"]
    headers = parsed_command["headers"]
    cookies = parsed_command["cookies"]
    data = parsed_command["data"]

    if not url:
        return "# Error: URL no encontrada para este comando curl.\n"

    args_list = []
    args_list.append(f"'{url}'")

    if cookies:
        cookies_str = json.dumps(cookies, indent=4)
        indented_cookies = textwrap.indent(cookies_str, ' ' * 4)
        args_list.append(f"cookies={indented_cookies}")

    if headers:
        headers_str = json.dumps(headers, indent=4)
        indented_headers = textwrap.indent(headers_str, ' ' * 4)
        args_list.append(f"headers={indented_headers}")

    if data is not None:
        if isinstance(data, dict):
            data_str = json.dumps(data, indent=4)
            indented_data = textwrap.indent(data_str, ' ' * 4)
            args_list.append(f"json={indented_data}")
        else:
            args_list.append(f"data={repr(data)}")

    request_args_str = ",\n".join(args_list)
    request_args_str = textwrap.indent(request_args_str, ' ' * 4)

    script_snippet = f"""
# --- Solicitud {parsed_command["method"]} a: {url} ---
try:
    response = requests.{method}(
{request_args_str}
    )
    response.raise_for_status()

    content_type = response.headers.get('Content-Type', 'unknown')
    print(f"Tipo de contenido: {{content_type}}")

    if 'application/json' in content_type:
        try:
            data = response.json()
            print(json.dumps(data, indent=4))
        except json.JSONDecodeError as e:
            print(f"Advertencia: No se pudo parsear como JSON. Imprimiendo texto sin procesar. Error: {{e}}")
            print(response.text)
    elif 'text/html' in content_type:
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"content_{{timestamp}}.html"
        print(f"Contenido es HTML. Guardando en: {{filename}}")
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(response.text)
    elif 'text/' in content_type:
        print("Contenido es texto. Imprimiendo texto:")
        print(response.text)
    elif 'application/octet-stream' in content_type:
        filename = 'response_content'
        with open(filename, 'wb') as f:
            f.write(response.content)
        print(f"Archivo binario descargado: {{filename}}")
    else:
        print("Tipo de contenido no reconocido. Imprimiendo texto sin procesar:")
        print(response.text)

except requests.exceptions.RequestException as e:
    print(f"Error en la solicitud: {{e}}")

print("\\n" + "="*80 + "\\n")
"""
    return script_snippet

def file_exists_validation(filepath):
    """Valida si un archivo existe."""
    return os.path.exists(filepath)

def not_empty_validation(s):
    """Valida si una cadena no está vacía."""
    return bool(s)

def generar_script_desde_curl():
    """Genera un script de Python 3 basándose en la entrada de curl."""
    curl_input = ""
    nombre_archivo_salida = None

    # 1. Parsear el argumento de salida si está presente en cualquier posición.
    if "-o" in sys.argv:
        try:
            o_index = sys.argv.index("-o")
            if o_index + 1 < len(sys.argv):
                nombre_archivo_salida = sys.argv[o_index + 1]
            else:
                print("Error: '-o' requiere un nombre de archivo de salida.")
                return
        except ValueError:
            pass

    # 2. Determinar la fuente de entrada: argumento o interactiva
    if len(sys.argv) > 1 and sys.argv[1] != "-o":
        input_arg = sys.argv[1]
        
        if file_exists_validation(input_arg):
            try:
                with open(input_arg, 'r', encoding='utf-8') as f:
                    curl_input = f.read()
                print(f"Leyendo comandos curl desde el archivo '{input_arg}'.")
            except Exception as e:
                print(f"Error al leer el archivo '{input_arg}': {e}")
                return
        elif input_arg.strip().startswith('curl '):
            curl_input = input_arg
            print(f"Leyendo el comando curl proporcionado como argumento.")
        else:
            print(f"Error: Argumento no reconocido: '{input_arg}'. Debe ser una ruta de archivo o un comando 'curl'.")
            return
    else:
        # Modo interactivo: se espera entrada por consola.
        print("Pegue aquí sus comandos curl o la ruta de un archivo.")
        print("Para finalizar, ingrese una línea en blanco y presione Enter dos veces.")
        
        # Lee la primera línea de la entrada para decidir si es una ruta o un comando.
        first_line = input()
        if not first_line.strip():
            print("No se proporcionó ninguna entrada. Saliendo.")
            return

        # Si la primera línea es una ruta de archivo válida, lee el archivo.
        if file_exists_validation(first_line.strip()):
            try:
                with open(first_line.strip(), 'r', encoding='utf-8') as f:
                    curl_input = f.read()
                print(f"Detectada ruta de archivo. Leyendo contenido de '{first_line.strip()}'.")
            except Exception as e:
                print(f"Error al leer el archivo '{first_line.strip()}': {e}")
                return
        else:
            # Si no es una ruta de archivo, asume que es el inicio de un comando curl.
            # Acumula la primera línea y lee el resto.
            lines = [first_line]
            while True:
                try:
                    line = input()
                    if not line.strip():
                        break
                    lines.append(line)
                except EOFError:
                    break
            curl_input = "\n".join(lines)
            print("Detectado comando(s) curl pegado(s). Procesando entrada.")
        
    if not curl_input:
        print("No se proporcionó ninguna entrada de curl. Saliendo.")
        return

    # 3. Procesar los comandos curl.
    normalized_input = re.sub(r'[\^\\\\]\s*\n', ' ', curl_input)
    raw_commands = re.split(r'(?<![a-zA-Z0-9])(curl\s+)', normalized_input)
    individual_curl_commands = []
    current_command_parts = []
    for part in raw_commands:
        if part.strip().startswith('curl '):
            if current_command_parts:
                full_cmd = "".join(current_command_parts).strip()
                if full_cmd.endswith(';') or full_cmd.endswith('&'):
                    full_cmd = full_cmd[:-1].strip()
                individual_curl_commands.append(full_cmd)
            current_command_parts = [part]
        else:
            current_command_parts.append(part)
    
    if current_command_parts:
        full_cmd = "".join(current_command_parts).strip()
        if full_cmd.endswith(';') or full_cmd.endswith('&'):
            full_cmd = full_cmd[:-1].strip()
        individual_curl_commands.append(full_cmd)

    individual_curl_commands = [cmd for cmd in individual_curl_commands if cmd.strip().startswith('curl ')]

    if not individual_curl_commands:
        print("Error: No se encontraron comandos 'curl' válidos en la entrada.")
        return

    all_script_snippets = []
    for cmd_str in individual_curl_commands:
        parsed_cmd = parse_curl_command(cmd_str)
        if parsed_cmd["url"]:
            all_script_snippets.append(generate_python_request(parsed_cmd))
        else:
            print(f"Advertencia: Se omitió un comando curl debido a un error de análisis de URL: '{cmd_str[:100]}...'")

    final_script_content = "# -*- coding: utf-8 -*-\nimport requests\nimport json\nimport urllib.parse\nfrom datetime import datetime\n\n" + "".join(all_script_snippets)

    # NUEVA LÓGICA: Preguntar al usuario dónde guardar la salida
    if not nombre_archivo_salida:
        respuesta = input("Presione ENTER para mostrar en pantalla o escriba un nombre de archivo para guardar (ej: mi_script.py): ").strip()
        if respuesta:
            nombre_archivo_salida = respuesta
        else:
            nombre_archivo_salida = None

    if nombre_archivo_salida:
        try:
            # Si no se especificó la extensión, se añade .py
            if not nombre_archivo_salida.lower().endswith('.py'):
                nombre_archivo_salida += '.py'
            
            with open(nombre_archivo_salida, 'w', encoding='utf-8') as f:
                f.write(final_script_content)
            print(f"\nScript generado y guardado en '{nombre_archivo_salida}' con {len(all_script_snippets)} solicitudes.")
        except Exception as e:
            print(f"Error al escribir en el archivo '{nombre_archivo_salida}': {e}")
    else:
        print("\n--- Script Python Generado (imprimiendo en la consola) ---")
        print(final_script_content)
        print("--- Fin del Script Generado ---")

if __name__ == "__main__":
    generar_script_desde_curl()