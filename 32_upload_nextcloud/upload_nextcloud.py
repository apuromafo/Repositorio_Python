import os
import argparse
import requests
from requests.auth import HTTPBasicAuth

# Configuración de Nextcloud
NEXTCLOUD_URL = "https://tu-servidor-nextcloud.com "
USERNAME = "tu_usuario"
PASSWORD = "tu_contraseña"

def upload_file_to_nextcloud(local_file_path, nextcloud_file_path):
    """Sube un archivo a Nextcloud."""
    try:
        with open(local_file_path, 'rb') as f:
            response = requests.put(
                f"{NEXTCLOUD_URL}/remote.php/dav/files/{USERNAME}/{nextcloud_file_path}",
                data=f,
                auth=HTTPBasicAuth(USERNAME, PASSWORD)
            )

        if response.status_code in [200, 201, 204]:
            print(f"✅ Archivo subido exitosamente: {local_file_path} -> /{nextcloud_file_path}")
            return True
        else:
            print(f"❌ Error al subir '{local_file_path}': {response.status_code} - {response.text}")
            return False
    except Exception as e:
        print(f"❌ Error al procesar '{local_file_path}': {e}")
        return False

def share_file(nextcloud_file_path):
    """Comparte un archivo en Nextcloud generando un enlace público."""
    share_endpoint = f"{NEXTCLOUD_URL}/ocs/v1.php/apps/files_sharing/api/v1/shares"
    payload = {
        'path': nextcloud_file_path,
        'shareType': 3,   # Compartir por enlace
        'permissions': 1  # Solo lectura
    }

    headers = {
        'OCS-APIRequest': 'true',
        'Accept': 'application/json'  # <-- Añadimos esto
    }

    try:
        response = requests.post(
            share_endpoint,
            auth=HTTPBasicAuth(USERNAME, PASSWORD),
            data=payload,
            headers=headers
        )

        print(f"Estado HTTP: {response.status_code}")
        print("Respuesta del servidor:")
        print(response.text)

        if response.status_code == 200:
            try:
                share_info = response.json()
                print("🔗 Enlace compartido:")
                print(f"   {share_info['ocs']['data']['url']}")
            except requests.exceptions.JSONDecodeError:
                print("❌ No se pudo decodificar la respuesta como JSON.")
        else:
            print(f"⚠️ No se pudo generar el enlace para '{nextcloud_file_path}': {response.status_code} - {response.text}")

    except Exception as e:
        print(f"⚠️ Error al compartir '{nextcloud_file_path}': {e}")
        
               
        
def upload_folder(local_folder, nextcloud_base_path):
    """Sube recursivamente todos los archivos de una carpeta local a Nextcloud."""
    for root, _, files in os.walk(local_folder):
        relative_path = os.path.relpath(root, local_folder)
        nc_folder_path = os.path.join(nextcloud_base_path, relative_path).replace("\\", "/")

        for file in files:
            local_file_path = os.path.join(root, file)
            nc_file_path = f"{nc_folder_path}/{file}"
            upload_file_to_nextcloud(local_file_path, nc_file_path)


def main():
    parser = argparse.ArgumentParser(description="Subir archivos o carpetas a Nextcloud.")
    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument('-a', '--archivo', type=str, help='Ruta al archivo que deseas subir.')
    group.add_argument('-f', '--carpeta', type=str, help='Ruta a la carpeta que deseas subir (se suben todos los archivos de forma recursiva).')

    args = parser.parse_args()

    # Subir un solo archivo
    if args.archivo:
        if not os.path.isfile(args.archivo):
            print(f"❌ El archivo '{args.archivo}' no existe.")
            return

        filename = os.path.basename(args.archivo)
        remote_path = filename  # Puedes cambiar esto si quieres una ruta específica
        if upload_file_to_nextcloud(args.archivo, remote_path):
            share_file(remote_path)

    # Subir una carpeta completa
    elif args.carpeta:
        if not os.path.isdir(args.carpeta):
            print(f"❌ La carpeta '{args.carpeta}' no existe.")
            return

        folder_name = os.path.basename(os.path.normpath(args.carpeta))
        upload_folder(args.carpeta, folder_name)

if __name__ == "__main__":
    main()