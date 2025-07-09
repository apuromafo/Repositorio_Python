import subprocess
import sys

def show_menu():
    """Muestra el menú principal."""
    print("\n[+] Menú principal:")
    print("1. Instalar y configurar frida-server")
    print("2. Validar entorno y ejecutar scripts de Frida")
    print("3. Reiniciar frida-server")
    print("4. Salir")

def run_script(script_name):
    """Ejecuta un script Python específico."""
    try:
        print(f"[+] Ejecutando {script_name}...")
        subprocess.run([sys.executable, script_name], check=True)
    except Exception as e:
        print(f"[-] Error al ejecutar {script_name}: {e}")

def main():
    while True:
        show_menu()
        choice = input("[?] Selecciona una opción (1-4): ").strip()
        
        if choice == "1":
            run_script("install_frida_server.py")  # Llama al script de instalación
        elif choice == "2":
            run_script("run_frida_scripts.py")  # Llama al script de validación y ejecución
        elif choice == "3":
            run_script("restart_frida_server.py")  # Llama al script de reinicio
        elif choice == "4":
            print("[+] Saliendo del programa...")
            break
        else:
            print("[-] Opción no válida. Intenta nuevamente.")

if __name__ == "__main__":
    main()