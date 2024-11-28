import os
import argparse

def extract_emails(file_path, remove_duplicates):
    """Extrae correos electrónicos de un archivo, asumiendo que están en el formato 'email: valor'."""
    emails = set() if remove_duplicates else []  # Usar un conjunto si se deben eliminar duplicados
    with open(file_path, 'r') as file:
        for line in file:
            line = line.strip()
            if ':' in line:
                email = line.split(':')[0]
                if remove_duplicates:
                    emails.add(email)  # Añadir al conjunto
                else:
                    emails.append(email)  # Añadir a la lista
    return emails

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
    if os.path.exists(args.file_path):
        print('Procesando el archivo...')
        emails = extract_emails(args.file_path, args.duplicates)
        
        # Escribir resultados en el archivo de salida
        with open(args.output, 'w') as result_file:
            for email in sorted(emails):  # Opcional: ordenar los emails
                result_file.write(email + '\n')
        
        print(f'Estado: OK, proceso listo. Revisa {args.output}')
    else:
        print('Error: El archivo no existe. Verifique la ruta e intente de nuevo.')

if __name__ == '__main__':
    main()