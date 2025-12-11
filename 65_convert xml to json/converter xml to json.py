#python .\conv.py -a .\demo.txt -o demo.json
import xml.etree.ElementTree as ET
import json
import argparse
import sys
from collections import defaultdict

# --- CONFIGURACIÓN DE VERSIÓN Y CONSTANTES ---
__version__ = "1.2.0" # Versión actualizada con el fix de simplificación de texto
TEXT_KEY = '#text'
ATTRIB_PREFIX = '@'
SOAP_NS = "http://schemas.xmlsoap.org/soap/envelope/"

# --- FUNCIONES NÚCLEO DE CONVERSIÓN ---

def parse_tag_name(tag):
    """Limpia el nombre de la etiqueta eliminando el namespace entre {}."""
    return tag.split('}')[-1]

def xml_to_dict_recursive(element):
    """
    Convierte un elemento XML (y sus hijos) en un diccionario de forma recursiva.
    Maneja atributos (@) y texto (#text) y aplica la simplificación de texto.
    """
    result = {}

    # 1. Manejar atributos
    for key, value in element.attrib.items():
        result[ATTRIB_PREFIX + key] = value

    # 2. Manejar texto
    text = (element.text or '').strip()
    
    # 3. Manejar hijos (recursión)
    children_map = defaultdict(list)
    for child in element:
        child_tag = parse_tag_name(child.tag)
        children_map[child_tag].append(xml_to_dict_recursive(child))

    for tag, items in children_map.items():
        if len(items) == 1:
            result[tag] = items[0]
        else:
            result[tag] = items

    # --- FIX DE SIMPLIFICACIÓN DE TEXTO ---
    
    # Si el elemento tiene texto y NO tiene atributos y NO tiene hijos,
    # el valor del nodo es solo el texto.
    if text and not result:
        return text
    
    # Si el elemento tiene texto Y tiene atributos o hijos,
    # el texto debe ir bajo la clave #text (comportamiento estándar).
    if text and result:
        result[TEXT_KEY] = text
        
    # --------------------------------------

    return result

def get_root_or_body(root):
    """
    Determina si el XML es un mensaje SOAP y devuelve el nodo 'Body' simplificado,
    o devuelve el nodo raíz normal si no es SOAP.
    """
    root_tag = parse_tag_name(root.tag)
    
    # 1. Verificar si es un Envelope SOAP
    if root_tag == 'Envelope' and SOAP_NS in root.tag:
        print("INFO: Detectado formato SOAP. Extrayendo contenido del Body.")
        body = root.find(f'{{{SOAP_NS}}}Body')
        if body is None:
            print("ADVERTENCIA: SOAP Envelope sin nodo Body encontrado.")
            return root
        
        # Simplificar: Si el Body tiene un solo hijo, devolver solo ese hijo.
        body_children = list(body)
        if len(body_children) == 1:
             return body_children[0]
        
        return body

    # 2. Si no es SOAP, devolver la raíz normal
    return root

def convertir_xml_a_json(archivo_entrada, archivo_salida=None):
    """
    Función principal que orquesta la conversión de XML a JSON,
    incluyendo la detección y simplificación de SOAP.
    """
    try:
        # 1. Parsear el archivo XML
        tree = ET.parse(archivo_entrada)
        root = tree.getroot()
        
        # 2. Obtener la raíz (o el contenido del Body si es SOAP)
        data_node = get_root_or_body(root)
        
        # 3. Convertir a diccionario
        resultado_dict = xml_to_dict_recursive(data_node)
        
        # Usamos el nombre del nodo extraído como la clave principal del JSON
        root_tag = parse_tag_name(data_node.tag)
        json_output = json.dumps({root_tag: resultado_dict}, indent=4, ensure_ascii=False)
        
        # 4. Escribir o imprimir el resultado
        if archivo_salida:
            with open(archivo_salida, 'w', encoding='utf-8') as f:
                f.write(json_output)
            print(f"\nÉXITO: Conversión finalizada. JSON escrito en '{archivo_salida}'")
        else:
            print("\n--- JSON Resultado ---")
            print(json_output)
        
        return True

    except FileNotFoundError:
        print(f"ERROR: Archivo de entrada no encontrado: '{archivo_entrada}'", file=sys.stderr)
        return False
    except ET.ParseError as e:
        print(f"ERROR: Error al analizar el XML en el archivo: {e}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"ERROR: Ocurrió un error inesperado: {e}", file=sys.stderr)
        return False

# --- LÓGICA PRINCIPAL Y ARGUMENTOS ---

def main():
    """Manejo de argumentos de línea de comandos."""
    parser = argparse.ArgumentParser(
        description="Convierte archivos XML (incluyendo SOAP) a formato JSON.",
        epilog=f"Versión: {__version__}. Desarrollado con xml.etree y json."
    )
    
    # Argumento obligatorio: Archivo de entrada (-a)
    parser.add_argument(
        '-a', '--archivo',
        required=True,
        help="Ruta al archivo XML de entrada (e.g., input.txt)."
    )
    
    # Argumento opcional: Archivo de salida (-o)
    parser.add_argument(
        '-o', '--output',
        help="Ruta al archivo donde se guardará el JSON resultante (opcional)."
    )
    
    # Argumento para mostrar la versión
    parser.add_argument(
        '-v', '--version',
        action='version',
        version=f'%(prog)s {__version__}',
        help="Muestra la versión del script."
    )

    args = parser.parse_args()

    # Ejecutar la conversión
    success = convertir_xml_a_json(args.archivo, args.output)
    
    if not success:
        sys.exit(1)

if __name__ == "__main__":
    main()