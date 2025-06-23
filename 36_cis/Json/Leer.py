import json
import os
import time

def clear_screen():
    """Limpia la pantalla de la consola."""
    os.system('cls' if os.name == 'nt' else 'clear')

def pause_and_continue(message="Presiona Enter para continuar...", sleep_time=0):
    """Pausa la ejecución y espera la entrada del usuario."""
    if sleep_time > 0:
        time.sleep(sleep_time)
    input(message)

def display_unified_controls(file_path):
    """
    Lee un archivo JSON unificado de controles y muestra su contenido de forma ordenada y paginada.

    Args:
        file_path (str): La ruta completa al archivo JSON unificado.
    """
    clear_screen()
    print(f"\n{'='*80}")
    print(f"--- Mostrando contenido de: {os.path.basename(file_path)} ---")
    print(f"{'='*80}")
    pause_and_continue()

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            unified_data = json.load(f)

        sorted_control_keys = sorted(
            unified_data.keys(),
            key=lambda k: int(k.split(' ')[1])
        )

        for control_key in sorted_control_keys:
            clear_screen() # Limpiar pantalla antes de cada control
            control_info = unified_data[control_key]

            print(f"\n{'#'*70}")
            print(f"CONTROL {control_info.get('number', 'N/A')}: {control_info.get('title', 'N/A')}")
            print(f"{'#'*70}")
            print(f"Resumen: {control_info.get('overview', 'N/A')}")

            safeguards = control_info.get('safeguards', [])
            if safeguards:
                print(f"\n--- Salvaguardas ({len(safeguards)}) ---")
                for s in safeguards:
                    print(f"  ID: {s.get('id', 'N/A')}")
                    print(f"  Descripción: {s.get('description', 'N/A')}")
                    print(f"  Tipo de Activo: {s.get('asset_type', 'N/A')}")
                    print(f"  Función de Seguridad: {s.get('security_function', 'N/A')}")
                    print(f"  IGs: {', '.join(s.get('igs', []))}")
                    print("-" * 60) # Separador para cada salvaguarda
            else:
                print("\nNo se encontraron salvaguardas para este control.")

            pause_and_continue(f"Presiona Enter para ver el siguiente control (CONTROL {control_info.get('number', 'N/A')})...")

    except FileNotFoundError:
        clear_screen()
        print(f"Error: El archivo '{file_path}' no se encontró.")
        print("Asegúrate de que esté en el mismo directorio que el script o proporciona la ruta completa.")
    except json.JSONDecodeError:
        clear_screen()
        print(f"Error: No se pudo decodificar el archivo JSON '{file_path}'.")
        print("Asegúrate de que sea un JSON válido y bien formado.")
    except Exception as e:
        clear_screen()
        print(f"Ocurrió un error inesperado al leer '{file_path}': {e}")
    
    print(f"\n{'='*80}")
    print("Fin de la visualización de controles.")
    print(f"{'='*80}\n")
    pause_and_continue("Presiona Enter para volver al menú principal...")


def main_menu():
    """Muestra el menú principal y maneja la selección del usuario."""
    while True:
        clear_screen()
        print("\n--- Menú de Controles CIS ---")
        print("1. Leer Controles en Español")
        print("2. Leer Controles en Inglés")
        print("3. Salir")
        print("----------------------------")

        choice = input("Elige una opción (1-3): ")

        if choice == '1':
            file_to_display = "all_cis_controls_es.json"
            display_unified_controls(file_to_display)
        elif choice == '2':
            file_to_display = "all_cis_controls_en.json"
            display_unified_controls(file_to_display)
        elif choice == '3':
            clear_screen()
            print("Saliendo del programa. ¡Hasta luego!")
            break
        else:
            print("Opción no válida. Por favor, elige 1, 2 o 3.")
            pause_and_continue("Presiona Enter para intentarlo de nuevo...")

if __name__ == "__main__":
    main_menu()