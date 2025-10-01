import subprocess
import sys

__version__ = '1.1.0'

def run_usbipd_command(args):
    try:
        result = subprocess.run(['usbipd'] + args, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"[Error] Al ejecutar 'usbipd {' '.join(args)}':\n{e.stderr.strip()}")
        return None
    except FileNotFoundError:
        print("[Error] Comando 'usbipd' no encontrado. Asegúrate de que esté instalado y en el PATH del sistema.")
        sys.exit(1)

def list_devices():
    print("\n[Info] Listando dispositivos USB conectados al sistema Windows...\n")
    output = run_usbipd_command(['list'])
    if output:
        print(output)
    else:
        print("[Aviso] No se pudo obtener la lista de dispositivos. Verifica el estado de usbipd.")

def detach_device(busid):
    print(f"\n[Info] Desconectando dispositivo USB con BusID '{busid}' de WSL...")
    run_usbipd_command(['detach', '--busid', busid])
    print("[Info] Operación completada.\n")

def attach_device(busid):
    print(f"\n[Info] Conectando dispositivo USB con BusID '{busid}' a WSL (opción --wsl)...")
    run_usbipd_command(['attach', '--wsl', '--busid', busid])
    print("[Info] Operación completada.\n")

def main_menu():
    print(f"=== Script de Gestión USB para WSL - Versión {__version__} ===\n")
    print("Nota: Ejecuta este script con permisos adecuados para usar usbipd.\n")

    while True:
        print("Opciones disponibles:")
        print(" 1) Listar dispositivos USB conectados")
        print(" 2) Desconectar dispositivo USB de WSL (detach)")
        print(" 3) Conectar dispositivo USB a WSL (attach)")
        print(" 4) Salir\n")

        choice = input("Elige una opción (1-4): ").strip()

        if choice == '1':
            list_devices()
        elif choice == '2':
            busid = input("Introduce BusID del dispositivo a desconectar (ejemplo: 2-4): ").strip()
            if busid:
                detach_device(busid)
            else:
                print("[Error] BusID inválido.\n")
        elif choice == '3':
            busid = input("Introduce BusID del dispositivo a conectar (ejemplo: 2-4): ").strip()
            if busid:
                attach_device(busid)
            else:
                print("[Error] BusID inválido.\n")
        elif choice == '4':
            print("Saliendo del script. ¡Hasta luego!")
            break
        else:
            print("[Error] Opción no válida. Por favor ingresa un número del 1 al 4.\n")

if __name__ == "__main__":
    main_menu()
