#!/usr/bin/env python3
# coding: utf-8
"""
Herramienta de apoyo para encontrar patrones en archivos (originalmente dsx).
"""
__description__ = 'Herramienta de apoyo a ejecutar adb'
__author__ = 'Michel Faúndez'
__version__ = '0.0.1'  # Incrementada la versión para reflejar cambios
__date__ = '2025-04-24'

import os
import requests
import zipfile
import sys
import winreg  # Para modificar el Registro de Windows
# # Ruta por defecto en     default_path 

def download_adb_tools(download_url, extract_path):
    """
    Descarga el archivo ZIP desde la URL proporcionada y lo guarda en la ruta especificada.
    """
    try:
        print(f"Descargando ADB Tools desde: {download_url}")
        response = requests.get(download_url, stream=True)
        response.raise_for_status()  # Lanza una excepción si hay un error HTTP
        
        zip_file_path = os.path.join(extract_path, "platform-tools-latest.zip")
        
        with open(zip_file_path, 'wb') as file:
            for chunk in response.iter_content(chunk_size=8192):
                file.write(chunk)
        
        print(f"Archivo descargado correctamente: {zip_file_path}")
        return zip_file_path
    except requests.RequestException as e:
        print(f"Error al descargar el archivo: {e}")
        sys.exit(1)

def extract_zip(zip_file_path, extract_path):
    """
    Descomprime el archivo ZIP en la ruta especificada.
    """
    try:
        print(f"Descomprimiendo archivo ZIP en: {extract_path}")
        with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
            zip_ref.extractall(extract_path)
        print("Archivo descomprimido correctamente.")
        
        # Eliminar el archivo ZIP después de la extracción
        os.remove(zip_file_path)
        print(f"Archivo ZIP eliminado: {zip_file_path}")
    except zipfile.BadZipFile as e:
        print(f"Error al descomprimir el archivo: {e}")
        sys.exit(1)

def is_adb_installed(adb_path):
    """
    Verifica si adb.exe está disponible en la ruta especificada.
    """
    adb_exe_path = os.path.join(adb_path, "adb.exe")
    return os.path.isfile(adb_exe_path)

def set_adb_environment_variable(extract_path):
    """
    Configura la variable de entorno PATH para incluir la ruta de ADB Tools de forma permanente en Windows.
    """
    adb_path = os.path.join(extract_path, "platform-tools")
    
    # Verificar si la ruta ya existe en PATH
    current_path = os.environ.get("PATH", "")
    if adb_path in current_path.split(os.pathsep):
        print("La ruta de ADB ya está configurada en la variable PATH.")
        return
    
    # Modificar el Registro de Windows para agregar la ruta de ADB permanentemente
    try:
        # Abrir la clave del Registro correspondiente a las variables de entorno del sistema
        reg_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Environment", 0, winreg.KEY_ALL_ACCESS)
        
        # Leer el valor actual de PATH
        path_value, _ = winreg.QueryValueEx(reg_key, "Path")
        path_list = path_value.split(os.pathsep)
        
        # Agregar la nueva ruta si no está presente
        if adb_path not in path_list:
            path_list.append(adb_path)
            new_path = os.pathsep.join(path_list)
            winreg.SetValueEx(reg_key, "Path", 0, winreg.REG_EXPAND_SZ, new_path)
            print(f"Ruta de ADB añadida permanentemente a la variable PATH: {adb_path}")
        else:
            print("La ruta de ADB ya está configurada en la variable PATH del sistema.")
        
        # Cerrar la clave del Registro
        winreg.CloseKey(reg_key)
        
        # Notificar al usuario que debe reiniciar la terminal o el sistema
        print("\nIMPORTANTE: Debes reiniciar tu terminal o sistema para que los cambios surtan efecto.")
        print("Para verificar la instalación, ejecuta 'adb version' en una nueva terminal.")
    except Exception as e:
        print(f"Error al configurar la variable PATH en el Registro de Windows: {e}")
        sys.exit(1)

def validate_user_path(user_path):
    """
    Valida si la ruta ingresada por el usuario es válida y escribible.
    """
    if not user_path:
        return False
    if not os.path.exists(user_path):
        try:
            os.makedirs(user_path, exist_ok=True)
        except Exception as e:
            print(f"Error al crear la ruta: {e}")
            return False
    return True

if __name__ == "__main__":
    # URL del archivo ZIP
    adb_url = "https://dl.google.com/android/repository/platform-tools-latest-windows.zip"
    
    # Ruta por defecto
    default_path = r"C:\Users\pente\Documents\Movil\herramientas\adb" 
    
    # Preguntar al usuario si desea cambiar la ruta
    user_path = input(f"Introduce la ruta donde deseas extraer ADB Tools (por defecto: {default_path}): ").strip()
    extract_path = user_path if user_path else default_path
    
    # Validar la ruta ingresada
    if not validate_user_path(extract_path):
        print("La ruta ingresada no es válida o no se puede escribir. Usando la ruta por defecto.")
        extract_path = default_path
    
    # Crear la ruta si no existe
    os.makedirs(extract_path, exist_ok=True)
    
    # Verificar si adb.exe ya está instalado
    adb_path = os.path.join(extract_path, "platform-tools")
    if is_adb_installed(adb_path):
        print("ADB ya está instalado en la ruta especificada.")
    else:
        # Descargar y descomprimir
        zip_file_path = download_adb_tools(adb_url, extract_path)
        extract_zip(zip_file_path, extract_path)
    
    # Configurar la variable de entorno
    set_adb_environment_variable(extract_path)