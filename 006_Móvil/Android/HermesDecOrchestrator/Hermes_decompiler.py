# ==============================================================================
# --- HISTORIAL DE VERSIONES ---
# ==============================================================================
# v1.3.1 (2025-09-23) - [ESTABLE]
#   ✅ Corregido: Error de 'FileNotFound' causado por comillas dobles y espacios en la ruta de entrada.
#   ✅ Mejorado: La función de entrada de archivo ahora limpia automáticamente la cadena.
#
# v1.3.0 (2025-09-23)
#   ✅ Añadido: Argumento de línea de comandos para especificar el archivo de entrada.
#   ✅ Añadido: Opción interactiva para procesar un archivo de entrada o ingresar una ruta personalizada.
#   ✅ Añadido: Soporte para rutas de archivos relativas o absolutas.
#
# v1.2.0 (2025-09-23) - [ESTABLE]
#   ✅ Añadido: Control de versiones detallado en la cabecera.
#   ✅ Corregido: Error "fatal: not a git repository" al gestionar el repo. El script ahora clona si no existe y actualiza si ya existe.
#
# v1.1.0 (2025-09-23)
#   ✅ Añadido: Menú interactivo con opciones para entorno virtual o host.
#   ✅ Añadido: Opción para personalizar el nombre del entorno virtual.
#   ✅ Ajustado: Lógica de instalación para trabajar en Windows (sin sudo) y con pip.
#
# v1.0.0 (2025-09-23) - [LANZAMIENTO]
#   ✅ Funcionalidad completa para Windows 11.
#   ✅ Automatizado: clonación del repositorio, instalación de dependencias, y descompilación.
#   ✅ Configuración: usa un nombre de archivo de entrada y salida personalizado.
#
# v0.5.0 (2025-09-23)
#   ✅ Prototipo inicial de descompilación.
#   ✅ Lógica de ejecución del descompilador de Hermes a través de Python.
#   ❌ No maneja control de versiones.
#
# v0.1.0 (2025-09-23) - [INICIO]
#   ✅ Creación del script inicial.
#   ✅ Estructura básica de funciones.
# ==============================================================================

import os
import sys
import subprocess
import shutil
import time

# --- CONFIGURACIÓN Y VARIABLES GLOBALES ---
REPO_URL = "https://github.com/P1sec/hermes-dec.git"
REPO_DIR = "hermes-dec"
DEFAULT_BUNDLE_FILE = 'index.android.bundle_extracted_20250923_123506.js'
DECOMPILED_FILE = 'decompiled_output.js'

# --- UTILIDADES ---
def log(message, level="INFO"):
    """Función de registro para un output claro."""
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    print(f"[{timestamp}] [{level.upper()}] {message}")

def run_command(command, message_success, message_error):
    """Ejecuta un comando de la terminal y maneja los errores."""
    try:
        is_windows = sys.platform == "win32"
        subprocess.run(command, check=True, text=True, shell=is_windows, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        log(message_success, "SUCCESS")
        return True
    except subprocess.CalledProcessError as e:
        log(f"{message_error}: {e.stderr.strip()}", "ERROR")
        return False
    except Exception as e:
        log(f"Ocurrió un error inesperado al ejecutar el comando: {e}", "ERROR")
        return False

def check_dependencies(is_host):
    """Verifica si las dependencias iniciales están instaladas."""
    required_commands = ['git']
    if is_host:
        required_commands.extend(['python', 'pip'])
    else:
        required_commands.extend(['python', 'pip'])
    
    for cmd in required_commands:
        if shutil.which(cmd) is None:
            log(f"Error: '{cmd}' no está instalado o no se encuentra en el PATH. Por favor, instálalo e inténtalo de nuevo.", "ERROR")
            return False
    return True

# --- PASOS DEL PROCESO ---
def setup_virtual_env():
    """Configura y activa un entorno virtual."""
    print("\n--- Configuración de Entorno Virtual ---")
    default_venv_dir = "hermes_venv"
    user_input = input(f"¿Desea usar el nombre de entorno por defecto '{default_venv_dir}'? (s/n, Enter para si): ")
    if user_input.strip().lower() in ['n', 'no']:
        venv_dir = input("Ingrese el nombre para el entorno virtual: ").strip()
        if not venv_dir:
            venv_dir = default_venv_dir
            log(f"Nombre no válido. Usando el nombre por defecto: {default_venv_dir}", "WARNING")
    else:
        venv_dir = default_venv_dir
    
    if os.path.exists(venv_dir):
        log(f"El entorno virtual '{venv_dir}' ya existe. Saltando la creación.", "INFO")
    else:
        log(f"Creando entorno virtual en: ./{venv_dir}", "INFO")
        try:
            subprocess.run([sys.executable, '-m', 'venv', venv_dir], check=True)
            log("Entorno virtual creado con éxito.", "SUCCESS")
        except subprocess.CalledProcessError:
            log("Error: No se pudo crear el entorno virtual. Asegúrate de tener el módulo 'venv'.", "ERROR")
            return None
    
    return venv_dir

def install_hermes_dec(use_venv, venv_dir=None):
    """Instala la herramienta hermes-dec."""
    log("Instalando hermes-dec y sus dependencias...", "INFO")
    
    if use_venv and venv_dir:
        python_exec = os.path.join(venv_dir, "Scripts" if sys.platform == "win32" else "bin", "python")
        if not run_command([python_exec, '-m', 'pip', 'install', '--upgrade', f'git+{REPO_URL}'],
                           "hermes-dec instalado en el entorno virtual.",
                           "Error al instalar en el entorno virtual"):
            return False
    else: # Modo host
        pip_command = 'pip' if sys.platform == "win32" else 'pip3'
        if not run_command([pip_command, 'install', '--upgrade', f'git+{REPO_URL}'],
                           "hermes-dec instalado en el host.",
                           "Error al instalar en el host. Revisa tus permisos."):
            return False
    
    return True

def get_bundle_file():
    """Obtiene la ruta del archivo de entrada del usuario."""
    # 1. Verificar si se proporcionó un argumento en la línea de comandos
    if len(sys.argv) > 1:
        file_path = sys.argv[1].strip().strip('"').strip("'")
        log(f"Usando el archivo de entrada proporcionado: {file_path}", "INFO")
        if os.path.exists(file_path):
            return file_path
        else:
            log(f"Error: El archivo '{file_path}' no se encontró. Por favor, verifica la ruta.", "ERROR")
            sys.exit(1)

    # 2. Si no hay argumento, preguntar al usuario
    print("\n--- Seleccionar Archivo de Entrada ---")
    user_input = input(f"¿Desea procesar el archivo por defecto '{DEFAULT_BUNDLE_FILE}'? (s/n, Enter para si): ")
    if user_input.strip().lower() in ['n', 'no']:
        file_path = input("Ingrese la ruta completa o relativa al archivo .bundle: ").strip().strip('"').strip("'")
        if not os.path.exists(file_path):
            log(f"Error: El archivo '{file_path}' no se encontró. Saliendo...", "ERROR")
            sys.exit(1)
        return file_path
    else:
        if not os.path.exists(DEFAULT_BUNDLE_FILE):
            log(f"Error: El archivo por defecto '{DEFAULT_BUNDLE_FILE}' no se encontró. Saliendo...", "ERROR")
            sys.exit(1)
        return DEFAULT_BUNDLE_FILE

def decompile_file(bundle_path):
    """Ejecuta el descompilador en el archivo bundle."""
    log(f"Iniciando la descompilación de '{bundle_path}'...", "INFO")
    
    # Aseguramos que la ruta se pase sin comillas al comando `hbc-decompiler`
    return run_command(
        ['hbc-decompiler', bundle_path, DECOMPILED_FILE],
        f"Descompilación completada. El archivo se guardó como '{DECOMPILED_FILE}'.",
        "Error durante la descompilación. El archivo podría no ser un bytecode de Hermes válido o la herramienta no está en el PATH."
    )

# --- MENÚ Y LÓGICA PRINCIPAL ---
def show_menu():
    """Muestra el menú de opciones al usuario."""
    print("\n" + "="*40)
    print("Herramienta de Descompilación de Hermes")
    print("="*40)
    print("1. Descompilar con Entorno Virtual (Recomendado)")
    print("2. Descompilar directamente en el Host (No recomendado)")
    print("3. Salir")
    
    while True:
        try:
            choice = int(input("\nSeleccione una opción: "))
            if choice in [1, 2, 3]:
                return choice
            else:
                print("Opción no válida. Por favor, intente de nuevo.")
        except ValueError:
            print("Entrada no válida. Por favor, ingrese un número.")

def main():
    """Función principal para orquestar el proceso."""
    choice = show_menu()
    
    if choice == 3:
        log("Saliendo del programa.", "INFO")
        return

    use_venv = choice == 1
    
    if not check_dependencies(not use_venv):
        return

    bundle_path = get_bundle_file()

    # 1. Gestión del repositorio: clonar si no existe, actualizar si ya existe
    if not os.path.exists(REPO_DIR):
        log("El repositorio no existe. Clonando...", "INFO")
        if not run_command(['git', 'clone', REPO_URL], "Repositorio clonado con éxito.", "Error al clonar el repositorio"):
            return
    else:
        log("El repositorio ya existe. Actualizando...", "INFO")
        os.chdir(REPO_DIR)
        if not run_command(['git', 'pull'], "Repositorio actualizado con éxito.", "Error al actualizar el repositorio"):
            os.chdir('..')
            return
        os.chdir('..')
        
    # 2. Configuración e instalación
    venv_dir = None
    if use_venv:
        venv_dir = setup_virtual_env()
        if not venv_dir:
            return
        if not install_hermes_dec(True, venv_dir):
            return
    else:
        if not install_hermes_dec(False):
            return

    # 3. Ejecutar la descompilación
    decompile_file(bundle_path)

    log("🎉 Proceso de descompilación finalizado.", "INFO")

if __name__ == "__main__":
    main()