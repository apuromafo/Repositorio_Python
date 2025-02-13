import os
import re
import argparse
#forma de uso  python .\extract_emails.py .\demo.correo.txt -o output.txt -d  
#
def is_valid_email(email):
    """Valida si una cadena es un correo electrónico utilizando una expresión regular."""
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(email_regex, email) is not None

def extract_emails(file_path, remove_duplicates):
    """Extrae correos electrónicos de un archivo, asumiendo que están en el formato 'email: valor'."""
    emails = set() if remove_duplicates else []
    invalid_emails = 0
    
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            for line in file:
                line = line.strip()
                if ':' in line:
                    email = line.split(':')[0].strip()
                    if is_valid_email(email):
                        if remove_duplicates:
                            emails.add(email)
                        else:
                            emails.append(email)
                    else:
                        invalid_emails += 1
    except Exception as e:
        print(f"Error al procesar el archivo: {e}")
        return [], invalid_emails
    
    return list(emails), invalid_emails

def main():
    # Configuración de argumentos de línea de comandos
    parser = argparse.ArgumentParser(description='Extrae correos electrónicos de un archivo de texto.')
    parser.add_argument('file_path', type=str, help='Ruta del archivo de texto a procesar.')
    parser.add_argument('-o', '--output', type=str, default='Resultado.txt',
                        help='Ruta del archivo de salida (por defecto: Resultado.txt).')
    parser.add_argument('-d', '--duplicates', action='store_true',
                        help='Eliminar correos electrónicos duplicados del resultado.')
    
    args = parser.parse_args()
    
    # Validar la existencia del archivo
    if not os.path.exists(args.file_path):
        print('Error: El archivo no existe. Verifique la ruta e intente de nuevo.')
        return
    
    print('Procesando el archivo...')
    emails, invalid_emails = extract_emails(args.file_path, args.duplicates)
    
    if not emails:
        print("No se encontraron correos válidos en el archivo.")
        return
    
    try:
        # Escribir resultados en el archivo de salida
        with open(args.output, 'w', encoding='utf-8') as result_file:
            for email in sorted(emails):  # Opcional: ordenar los emails
                result_file.write(email + '\n')
        
        print(f'Estado: OK, proceso listo. Revisa {args.output}')
        print(f"Correos válidos extraídos: {len(emails)}")
        if invalid_emails > 0:
            print(f"Correos inválidos ignorados: {invalid_emails}")
    except Exception as e:
        print(f"Error al escribir en el archivo de salida: {e}")

if __name__ == '__main__':
    main()