import os
import subprocess
import sys

# Ruta predeterminada al ejecutable del emulador
EMULATOR_PATH = r"C:\Users\pente\AppData\Local\Android\Sdk\emulator\emulator.exe"

def verificar_emulador():
    """
    Verifica si el emulador de Android existe en la ruta actual de EMULATOR_PATH.
    Si no se encuentra, intenta la ruta alternativa y, si falla, solicita la ruta manualmente al usuario,
    actualizando la variable global EMULATOR_PATH.

    Returns:
        bool: True si se encontró una ruta válida al emulador, False en caso contrario.
    """
    global EMULATOR_PATH
    if os.path.exists(EMULATOR_PATH):
        return True
    else:
        ruta_alternativa = os.path.join(os.path.expanduser('~'), 'AppData', 'Local', 'Android', 'Sdk', 'emulator', 'emulator.exe')
        if os.path.exists(ruta_alternativa):
            EMULATOR_PATH = ruta_alternativa
            return True
        else:
            print("No se encontró el emulador en las ubicaciones comunes.")
            nueva_ruta = solicitar_ruta_manual()
            if nueva_ruta:
                EMULATOR_PATH = nueva_ruta
                return True
            else:
                return False

def solicitar_ruta_manual():
    """
    Solicita al usuario que ingrese manualmente la ruta al emulador de Android.

    Returns:
        str or None: La ruta ingresada por el usuario si es válida, None en caso contrario.
    """
    while True:
        # Solución 1: Usar una cadena raw (r"...")
        ruta_manual = input(r"Por favor, ingresa la ruta correcta al emulador de Android: Ejemplo C:\Users\pente\AppData\Local\Android\Sdk\emulator\emulator.exe  ")
        # Solución 2: Escapar las barras invertidas
        # ruta_manual = input("Por favor, ingresa la ruta correcta al emulador de Android: Ejemplo C:\\Users\\pente\\AppData\\Local\\Android\\Sdk\\emulator\\emulator.exe  ")

        if os.path.exists(ruta_manual):
            return ruta_manual
        else:
            print("La ruta ingresada no es válida. Por favor, intenta nuevamente.")
            if input("¿Deseas intentar nuevamente? (s/n): ").lower() != 's':
                return None

# Verificar la existencia del emulador y actualizar EMULATOR_PATH
if verificar_emulador():
    print(f"Emulador encontrado en: {EMULATOR_PATH}")
    # Aquí puedes continuar con la lógica que utiliza EMULATOR_PATH
else:
    print("No se pudo encontrar una ruta válida al emulador de Android.")
    # Aquí podrías agregar un manejo adicional si no se encuentra la ruta ni manualmente

    

def list_avds():
    """Lista todas las máquinas virtuales disponibles."""
    try:
        print("[+] Listando máquinas virtuales disponibles...")
        result = subprocess.run(
            [EMULATOR_PATH, "-list-avds"],
            capture_output=True,
            text=True,
            check=True
        )
        avds = result.stdout.strip().split("\n")
        if not avds or avds == [""]:
            print("[-] No se encontraron máquinas virtuales disponibles.")
            return []
        print("[+] Máquinas virtuales disponibles:")
        for idx, avd in enumerate(avds, start=1):
            print(f"{idx}. {avd}")
        return avds
    except Exception as e:
        print(f"[-] Error al listar las máquinas virtuales: {e}")
        return []

def start_emulator(avd_name):
    """Inicia el emulador con la opción writable-system."""
    try:
        print(f"[+] Iniciando el emulador '{avd_name}' con writable-system...")
        subprocess.Popen(
            [EMULATOR_PATH, f"@{avd_name}", "-writable-system"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        print(f"[+] Emulador '{avd_name}' iniciado exitosamente.")
    except Exception as e:
        print(f"[-] Error al iniciar el emulador: {e}")

def main():
    # Paso 1: Listar las máquinas virtuales disponibles
    avds = list_avds()
    if not avds:
        print("[-] No hay máquinas virtuales disponibles para iniciar.")
        return

    # Paso 2: Permitir al usuario seleccionar una máquina virtual
    while True:
        choice = input("[?] Selecciona el número de la máquina virtual a iniciar (o 'q' para salir): ").strip()
        if choice.lower() == "q":
            print("[+] Saliendo del programa...")
            break
        if not choice.isdigit() or int(choice) < 1 or int(choice) > len(avds):
            print("[-] Selección inválida. Intenta nuevamente.")
            continue
        
        selected_avd = avds[int(choice) - 1]
        print(f"[+] Has seleccionado: {selected_avd}")

        # Paso 3: Iniciar el emulador con writable-system
        start_emulator(selected_avd)
        break

if __name__ == "__main__":
    main()