import subprocess
import sys
import json
import os
import time

# ==============================================================================
# VARIABLES GLOBALES Y CONFIGURACIÓN
# ==============================================================================
VERSION = "1.0.0"
CONFIG_FILE = "config.json"
LOG_FILE = "launcher_actions.log"
# Archivo 1 análisis (analisys.py)
FILE1 = "analisys.py"
# Archivo 2 conversión (convertir.py)
FILE2 = "convertir.py"

# Variable de estado global para el logging, se inicializa al cargar la config
global ENABLE_LOGS
ENABLE_LOGS = False

# ==============================================================================
# FUNCIONES DE CONFIGURACIÓN Y LOGGING
# ==============================================================================

def save_config(config):
    """
    Guarda la configuración actual en el archivo JSON.
    """
    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump(config, f, indent=4)
    except Exception as e:
        print(f"[-] Error guardando configuración: {e}")

def load_config():
    """
    Carga la configuración desde un archivo JSON. Si no existe, crea uno por defecto.
    """
    global ENABLE_LOGS
    try:
        if not os.path.exists(CONFIG_FILE):
            config = {"enable_logs": True}
            save_config(config)

        with open(CONFIG_FILE, "r") as f:
            config = json.load(f)
            ENABLE_LOGS = config.get("enable_logs", True)
            return config
    except (json.JSONDecodeError, IOError):
        print("[-] Error cargando el archivo de configuración. Se usará la configuración por defecto.")
        config = {"enable_logs": True}
        save_config(config)
        ENABLE_LOGS = True
        return config

def log(message, level="INFO"):
    """
    Registra un evento con timestamp y nivel.
    Formato: 2025-09-15T12:38:07 [LEVEL] Descripción del evento
    """
    # Si el usuario desactiva el logging no escribimos nada
    if not ENABLE_LOGS:
        return

    # ISO-8601 local (año-mes-díaThh:mm:ss)
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%S")
    line = f"{timestamp} [{level}] {message}"

    # Intenta escribir; ignora errores que no comprometen la ejecución
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except (IOError, OSError):
        # Último recurso: imprime el fallo para que no pase desapercibido
        print(f"[!] No se pudo escribir en {LOG_FILE}")

# ==============================================================================
# FUNCIONES DE MENÚ Y EJECUCIÓN
# ==============================================================================

def show_main_menu():
    """
    Muestra en pantalla el menú principal.
    """
    print("\n=======================================")
    print(f"      Jasper CLI v{VERSION}")
    print("=======================================")
    print("[+] Menú principal:")
    print("1. Analizar archivos Jasper/XML")
    print("2. Convertir archivos Jasper a PDF")
    print(f"3. Toggle Logging (Actual: {'Activado' if ENABLE_LOGS else 'Desactivado'})")
    print("4. Salir")

def handle_main_menu_choice(choice):
    """
    Procesa la opción seleccionada.
    Retorna True si el programa debe salir.
    """
    global ENABLE_LOGS
    
    if choice == "1":
        log("[+] Opción 1 seleccionada: Analizar archivos Jasper/XML")
        
        # Pide al usuario la ruta y crea el comando
        analyze_choice = input("Analizar (a)rchivo o (f)carpeta? (a/f): ").strip().lower()
        command = [sys.executable, FILE1]
        
        if analyze_choice == 'a':
            file_path = input("Ruta del archivo a analizar: ")
            command.extend(["-a", file_path])
        elif analyze_choice == 'f':
            folder_path = input("Ruta de la carpeta a analizar: ")
            command.extend(["-f", folder_path])
        else:
            print("[-] Opción de análisis no válida. Volviendo al menú principal.")
            log("[-] Opción de análisis no válida.")
            return False

        try:
            print("\n[+] Ejecutando:", " ".join(command))
            subprocess.run(command, check=True)
        except subprocess.CalledProcessError as e:
            print(f"[-] El script de análisis falló con el código de salida: {e.returncode}")
            log(f"[-] El script de análisis falló: {e}")
        except FileNotFoundError:
            print(f"[-] Error: El script '{FILE1}' no se encuentra.")
            log(f"[-] Archivo no encontrado: {FILE1}")
    
    elif choice == "2":
        log("[+] Opción 2 seleccionada: Convertir archivos Jasper a PDF")
        
        # Pide al usuario las rutas y crea el comando
        convert_choice = input("Convertir (a)rchivo o (f)carpeta? (a/f): ").strip().lower()
        command = [sys.executable, FILE2]

        if convert_choice == 'a':
            file_path = input("Ruta del archivo .jasper: ")
            output_path = input("Ruta de salida (opcional, Enter para la misma carpeta): ")
            command.extend(["-a", file_path])
            if output_path:
                command.extend(["-o", output_path])
        elif convert_choice == 'f':
            folder_path = input("Ruta de la carpeta: ")
            output_path = input("Ruta de salida (opcional, Enter para la misma carpeta): ")
            command.extend(["-f", folder_path])
            if output_path:
                command.extend(["-o", output_path])
        else:
            print("[-] Opción de conversión no válida. Volviendo al menú principal.")
            log("[-] Opción de conversión no válida.")
            return False
        
        try:
            print("\n[+] Ejecutando:", " ".join(command))
            subprocess.run(command, check=True)
        except subprocess.CalledProcessError as e:
            print(f"[-] El script de conversión falló con el código de salida: {e.returncode}")
            log(f"[-] El script de conversión falló: {e}")
        except FileNotFoundError:
            print(f"[-] Error: El script '{FILE2}' no se encuentra.")
            log(f"[-] Archivo no encontrado: {FILE2}")

    elif choice == "3":
        # Toggle Logging
        config = load_config()
        config["enable_logs"] = not config["enable_logs"]
        save_config(config)
        ENABLE_LOGS = config["enable_logs"]
        print(f"[+] Logging ahora está: {'Activado' if ENABLE_LOGS else 'Desactivado'}")
        log(f"[+] Logging cambiado a: {'Activado' if ENABLE_LOGS else 'Desactivado'}")

    elif choice == "4":
        # Exit
        log("[+] Saliendo del programa.")
        print("Saliendo...")
        return True
    
    else:
        print("[-] Opción no válida. Intenta nuevamente.")
        log(f"[-] Opción no válida seleccionada: {choice}")
    return False

# ==============================================================================
# FUNCIÓN PRINCIPAL
# ==============================================================================

def main():
    """
    Función principal que carga la configuración y muestra el menú repetidamente.
    """
    load_config()
    log("[+] Programa iniciado.")
    while True:
        try:
            show_main_menu()
            choice = input("[?] Selecciona una opción: ").strip()
            if handle_main_menu_choice(choice):
                break
        except (KeyboardInterrupt, EOFError):
            print("\n[!] Operación cancelada. Saliendo del programa...")
            log("[!] Programa interrumpido por el usuario.")
            break

if __name__ == "__main__":
    main()