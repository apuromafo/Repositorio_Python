import subprocess
import sys
import json
import os

VERSION = "1.1.2"
CONFIG_FILE = r"config\config_00main.json"
LOG_FILE = "main.log"
global ENABLE_LOGS

def load_config():
    # Asegura que la carpeta de configuración exista
    if not os.path.exists("config"):
        os.makedirs("config")
    
    """
    Carga la configuración desde un archivo JSON. 
    Si no existe o está corrupto, crea uno con configuración por defecto (logging activado).
    Actualiza la variable global ENABLE_LOGS con el valor leído o por defecto.
    """
    global ENABLE_LOGS
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                config = json.load(f)
                ENABLE_LOGS = config.get("enable_logs", False)
                return config
        except (json.JSONDecodeError, IOError):
            config = {"enable_logs": True}
            save_config(config)
            ENABLE_LOGS = True
            return config
    else:
        config = {"enable_logs": True}
        save_config(config)
        ENABLE_LOGS = True
        return config

def save_config(config):
    """
    Guarda la configuración actual en el archivo JSON CONFIG_FILE.
    Captura y muestra errores en caso de fallo al guardar.
    """
    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump(config, f, indent=4)
    except Exception as e:
        print(f"[-] Error guardando configuración: {e}")

def log(message):
    """
    Registra un mensaje en el archivo de log si el logging está activado.
    Protege la escritura para evitar interrupciones o errores que afecten la ejecución.
    """
    if ENABLE_LOGS:
        try:
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(message + "\n")
        except (KeyboardInterrupt, IOError):
            # Omite errores en logging para no interrumpir flujo
            pass

SCRIPTS = {
    "0": {"script": "adb_setup.py", "desc": "Validar instalación de ADB"},
    "1": {"script": "frida_tools.py", "desc": "Instala y configura frida-tools"},
    "2": {"script": "install_frida_server.py", "desc": "Instala y configura frida-server"},
    "3": {"script": "run_frida_scripts.py", "desc": "Valida entorno y ejecuta scripts de Frida"},
    "4": {"script": "restart_frida_server.py", "desc": "Reinicia frida-server"}
}

def show_main_menu():
    """
    Muestra en pantalla el menú principal con las opciones disponibles para el usuario.
    Incluye los scripts predefinidos, toggle de logging y opción para salir.
    """
    print("\n=======================================")
    print(f"     Frida Automation CLI v{VERSION}")
    print("=======================================")
    print("[+] Menú principal:")
    for k, v in sorted(SCRIPTS.items()):
        print(f"{k}. {v['desc']} ")
    print(f"{len(SCRIPTS)}. Toggle Logging (Actual: {'Activado' if ENABLE_LOGS else 'Desactivado'})")
    print(f"{len(SCRIPTS)+1}. Salir")

def help_option(num):
    """
    Muestra una breve descripción de la función del script asociado a la opción num.
    Incluye ayuda especial para la opción Toggle Logging.
    """
    if num in SCRIPTS:
        print(f"\nAyuda de '{SCRIPTS[num]['script']}':")
        print(SCRIPTS[num]['desc'])
    elif num == "toggle":
        print("\nAyuda de 'Toggle Logging':")
        print("Esta opción permite activar o desactivar el logging para personalizar el registro de acciones.")
        print(f"El archivo de log actual es: {LOG_FILE}")
    else:
        print("Opción inválida.")

def handle_main_menu_choice(choice):
    """
    Procesa la opción seleccionada en el menú principal.
    Ejecuta scripts, toggles de logging o termina el programa según elección.
    Devuelve True si la ejecución debe terminar, False para continuar en menú.
    """
    if choice in SCRIPTS:
        log(f"[+] Ejecutando {SCRIPTS[choice]['script']}")
        run_script(SCRIPTS[choice]["script"])
    elif choice == str(len(SCRIPTS)):
        config = load_config()
        config["enable_logs"] = not config["enable_logs"]
        save_config(config)
        global ENABLE_LOGS
        ENABLE_LOGS = config["enable_logs"]
        print(f"[+] Logging ahora está: {'Activado' if ENABLE_LOGS else 'Desactivado'}")
    elif choice == str(len(SCRIPTS)+1):
        print("[+] Saliendo del programa...")
        return True
    elif choice.endswith("?") and (choice[:-1] in SCRIPTS or choice[:-1] == str(len(SCRIPTS))):
        if choice[:-1] == str(len(SCRIPTS)):
            help_option("toggle")
        else:
            help_option(choice[:-1])
    else:
        print("[-] Opción no válida. Intenta nuevamente.")
    return False

def handle_exit_exception(exc_type):
    """
    Maneja de forma segura las excepciones KeyboardInterrupt y EOFError,
    mostrando mensajes claros y dejando registros en el log si está habilitado.
    
    :param exc_type: Tipo de excepción ('keyboard' o 'eof')
    """
    try:
        if exc_type == 'keyboard':
            print("\n[!] Interrupción (Ctrl+C) detectada. Saliendo del programa...")
        elif exc_type == 'eof':
            print("\n[!] Entrada final (EOF) detectada. Saliendo del programa...")
    except KeyboardInterrupt:
        pass  # Ignorar si ocurre otra interrupción mientras se imprime
    try:
        if exc_type == 'keyboard':
            log("[!] Programa interrumpido por usuario (Ctrl+C).")
        elif exc_type == 'eof':
            log("[!] Programa finalizado por EOF en entrada.")
    except Exception:
        pass  # Ignorar errores en logging

def run_script(script_name):
    """
    Ejecuta el script Python especificado, permitiendo una comunicación interactiva
    con el usuario a través de la terminal.
    """
    print(f"[+] Ejecutando {script_name}...")
    try:
        process = subprocess.Popen([sys.executable, script_name])
        process.wait()
    except KeyboardInterrupt:
        print(f"\n[!] El script {script_name} fue interrumpido. Volviendo al menú principal...")
        log(f"[!] {script_name} interrumpido por el usuario.")
    except FileNotFoundError:
        print(f"[-] Error: El script '{script_name}' no se encuentra.")
        log(f"[-] Archivo no encontrado: {script_name}")
    except Exception as e:
        print(f"[-] Error al ejecutar {script_name}: {e}")
        log(f"[-] Error en {script_name}: {e}")

def main():
    load_config()
    while True:
        show_main_menu()
        try:
            choice = input("[?] Selecciona una opción (o número seguido de ? para ver ayuda): ").strip()
        except KeyboardInterrupt:
            handle_exit_exception('keyboard')
            break
        except EOFError:
            handle_exit_exception('eof')
            break
        if handle_main_menu_choice(choice):
            break

if __name__ == "__main__":
    main()
