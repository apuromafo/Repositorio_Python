import os

def get_file_names(path):
    file_names = []
    for file_name in os.listdir(path):
        if os.path.isfile(os.path.join(path, file_name)):
            file_names.append(os.path.join(path, file_name))
    return file_names

def extract_emails(file_path):
    emails = []
    with open(file_path, 'r') as file:
        for line in file:
            line = line.strip()
            if ':' in line:
                email = line.split(':')[0]
                emails.append(email)
    return emails

def main():
    print('Buscando el Archivo')
    file_path = input('Ingrese la ruta del archivo: ')
    if os.path.exists(file_path):
        print('Procesando el Archivo')
        emails = extract_emails(file_path)
        result_file_path = 'Resultado.txt'
        with open(result_file_path, 'w') as result_file:
            for email in emails:
                result_file.write(email + '\n')
        print('Estado: OK, Proceso listo. Revisa Resultado.txt')
    else:
        print('El archivo no existe.')

if __name__ == '__main__':
    main()