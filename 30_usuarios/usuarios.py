import argparse
import subprocess
import sys
import os
import getpass
import platform

# --- Constantes y configuración ---
SISTEMA = platform.system()
EXITO = 0
FALLO = 1

# --- Funciones de utilidad ---

def imprimir_mensaje(mensaje, tipo="info"):
    """
    Imprime un mensaje con un prefijo que indica el tipo.
    Tipos: "info" (+), "exito" (✓), "error" (✗), "advertencia" (!).
    """
    colores = {
        "info": "\033[94m",     # Azul
        "exito": "\033[92m",    # Verde
        "error": "\033[91m",    # Rojo
        "advertencia": "\033[93m", # Amarillo
        "reset": "\033[0m"      # Resetear color
    }
    prefijos = {
        "info": "[+]",
        "exito": "[✓]",
        "error": "[✗]",
        "advertencia": "[!]"
    }
    prefijo = prefijos.get(tipo, "[?]")
    color = colores.get(tipo, colores["reset"])
    print(f"{color}{prefijo} {mensaje}{colores['reset']}")

def ejecutar_comando(comando, verificar_root=False, suprimir_salida=False):
    """
    Ejecuta un comando del sistema y maneja errores.
    Args:
        comando (list): Lista de strings que representan el comando y sus argumentos.
        verificar_root (bool): Si es True, verifica si el usuario es root antes de ejecutar.
        suprimir_salida (bool): Si es True, no imprime la salida stdout del comando.
    Returns:
        str: La salida estándar del comando si fue exitoso, o una cadena vacía en caso de error.
    """
    if verificar_root and SISTEMA in ["Linux", "Darwin"] and getpass.getuser() != "root":
        imprimir_mensaje("Debes ejecutar este comando como root (sudo).", "advertencia")
        return ""
    try:
        resultado = result = subprocess.run(comando, capture_output=True, text=True, check=True, encoding='cp850', errors='replace')
        if not suprimir_salida:
            return resultado.stdout.strip()
        return ""
    except FileNotFoundError:
        imprimir_mensaje(f"Comando no encontrado: '{comando[0]}'. Asegúrate de que esté en tu PATH.", "error")
        return ""
    except subprocess.CalledProcessError as e:
        imprimir_mensaje(f"Error ejecutando el comando: {' '.join(comando)}. Salida de error: {e.stderr.strip()}", "error")
        return ""
    except Exception as e:
        imprimir_mensaje(f"Ocurrió un error inesperado: {e}", "error")
        return ""

def confirmar_accion(pregunta):
    """Solicita confirmación al usuario."""
    return input(f"{pregunta} [s/n]: ").strip().lower() == "s"

# --- Funciones específicas por sistema ---

def listar_usuarios():
    """Lista los usuarios del sistema."""
    imprimir_mensaje("Listando usuarios del sistema...")
    
    if SISTEMA == "Windows":
        salida = ejecutar_comando(["net", "user"])
        if salida:
            usuarios = []
            for linea in salida.splitlines():
                # Ignorar líneas descriptivas o vacías
                if not linea.strip() or "Cuentas de usuario" in linea or "---" in linea or "completado" in linea:
                    continue
                # Dividir por espacios múltiples y limpiar nombres
                nombres = [n for n in linea.strip().split() if n]
                usuarios.extend(nombres)
            
            if usuarios:
                print("[✓] Usuarios encontrados:")
                for usuario in usuarios:
                    print(f"  - {usuario}")
            else:
                imprimir_mensaje("No se encontraron usuarios válidos.", "advertencia")
        else:
            imprimir_mensaje("No se pudo obtener la lista de usuarios.", "advertencia")

    elif SISTEMA in ["Linux", "Darwin"]:
        if SISTEMA == "Linux":
            salida = ejecutar_comando(["getent", "passwd"])
            if salida:
                print("[✓] Usuarios del sistema (con /home/ o /usr/local/):")
                for linea in salida.splitlines():
                    partes = linea.split(":")
                    if len(partes) >= 6 and (partes[5].startswith("/home/") or partes[5].startswith("/usr/local/")) and partes[6] not in ["/bin/false", "/usr/sbin/nologin"]:
                        print(f"Usuario: {partes[0]}, Home: {partes[5]}, Shell: {partes[6]}")
            else:
                imprimir_mensaje("No se pudo obtener la lista de usuarios.", "advertencia")

        elif SISTEMA == "Darwin":  # macOS
            salida = ejecutar_comando(["dscl", ".", "-read", "/Users", "NFSHomeDirectory", "UserShell", "PrimaryGroupID"])
            if salida:
                usuarios = []
                usuario_actual = {}
                for linea in salida.splitlines():
                    if linea.startswith("RecordName:"):
                        if usuario_actual:
                            usuarios.append(usuario_actual)
                        usuario_actual = {"Nombre": linea.split(":")[1].strip()}
                    elif "NFSHomeDirectory:" in linea:
                        usuario_actual["Home"] = linea.split(":")[1].strip()
                    elif "UserShell:" in linea:
                        usuario_actual["Shell"] = linea.split(":")[1].strip()
                if usuario_actual:
                    usuarios.append(usuario_actual)

                print("[✓] Usuarios del sistema (/Users/ o /var/root):")
                for datos_usuario in usuarios:
                    if "Home" in datos_usuario and (datos_usuario["Home"].startswith("/Users/") or datos_usuario["Home"] == "/var/root"):
                        print(f"Usuario: {datos_usuario.get('Nombre', 'N/A')}, Home: {datos_usuario.get('Home', 'N/A')}, Shell: {datos_usuario.get('Shell', 'N/A')}")
            else:
                imprimir_mensaje("No se pudo obtener la lista de usuarios.", "advertencia")
    else:
        imprimir_mensaje(f"Sistema '{SISTEMA}' no compatible para listar usuarios.", "advertencia")

def crear_usuario(nombre):
    """Crea un nuevo usuario."""
    imprimir_mensaje(f"Creando usuario: {nombre}")
    if SISTEMA == "Windows":
        if ejecutar_comando(["net", "user", nombre, "/add"]):
            imprimir_mensaje(f"Usuario '{nombre}' creado correctamente.", "exito")
        else:
            imprimir_mensaje(f"Fallo al crear el usuario '{nombre}'.", "error")
    elif SISTEMA in ["Linux", "Darwin"]:
        if ejecutar_comando(["useradd", "-m", nombre], verificar_root=True):
            imprimir_mensaje(f"Usuario '{nombre}' creado correctamente.", "exito")
        else:
            imprimir_mensaje(f"Fallo al crear el usuario '{nombre}'.", "error")
    else:
        imprimir_mensaje(f"Sistema '{SISTEMA}' no compatible para crear usuarios.", "advertencia")

def eliminar_usuario(nombre):
    """Elimina un usuario."""
    imprimir_mensaje(f"Eliminando usuario: {nombre}")
    if SISTEMA == "Windows":
        if ejecutar_comando(["net", "user", nombre, "/delete"]):
            imprimir_mensaje(f"Usuario '{nombre}' eliminado correctamente.", "exito")
        else:
            imprimir_mensaje(f"Fallo al eliminar el usuario '{nombre}'.", "error")
    elif SISTEMA in ["Linux", "Darwin"]:
        if ejecutar_comando(["userdel", "-r", nombre], verificar_root=True):
            imprimir_mensaje(f"Usuario '{nombre}' eliminado correctamente.", "exito")
        else:
            imprimir_mensaje(f"Fallo al eliminar el usuario '{nombre}'.", "error")
    else:
        imprimir_mensaje(f"Sistema '{SISTEMA}' no compatible para eliminar usuarios.", "advertencia")

def mostrar_grupos(nombre=None):
    """Muestra información de grupos del sistema o de un usuario específico."""
    imprimir_mensaje("Mostrando información de grupos...")
    if SISTEMA == "Windows":
        if nombre:
            salida = ejecutar_comando(["net", "user", nombre])
            if salida:
                grupos_encontrados = False
                for linea in salida.splitlines():
                    if "Miembro de" in linea or "Local Group Memberships" in linea:
                        print(linea)
                        grupos_encontrados = True
                if not grupos_encontrados:
                    imprimir_mensaje(f"No se encontraron grupos para el usuario '{nombre}'.", "info")
            else:
                imprimir_mensaje(f"El usuario '{nombre}' no existe o no se pudo obtener su información.", "advertencia")
        else:
            salida = ejecutar_comando(["net", "localgroup"])
            if salida:
                print(salida)
            else:
                imprimir_mensaje("No se pudo obtener la lista de grupos.", "advertencia")
    elif SISTEMA in ["Linux", "Darwin"]:
        if nombre:
            salida = ejecutar_comando(["groups", nombre])
            if salida:
                print(salida)
            else:
                imprimir_mensaje(f"El usuario '{nombre}' no existe o no tiene grupos asignados.", "advertencia")
        else:
            salida = ejecutar_comando(["cat", "/etc/group"])
            if salida:
                print(salida)
            else:
                imprimir_mensaje("No se pudo obtener la lista de grupos.", "advertencia")
    else:
        imprimir_mensaje(f"Sistema '{SISTEMA}' no compatible para mostrar grupos.", "advertencia")

def info_usuario(nombre):
    """Muestra información detallada de un usuario."""
    imprimir_mensaje(f"Información del usuario '{nombre}':")
    if SISTEMA == "Windows":
        salida = ejecutar_comando(["net", "user", nombre])
        if salida:
            print(salida)
        else:
            imprimir_mensaje(f"No se encontró información para '{nombre}'.", "advertencia")
    elif SISTEMA in ["Linux", "Darwin"]:
        salida = ejecutar_comando(["id", nombre])
        if salida:
            print(salida)
        else:
            imprimir_mensaje(f"No se encontró información para '{nombre}'.", "advertencia")
    else:
        imprimir_mensaje(f"Sistema '{SISTEMA}' no compatible para mostrar información de usuario.", "advertencia")

# --- Menú Interactivo ---

def menu_interactivo():
    """Muestra un menú interactivo para la gestión de usuarios."""
    while True:
        print("\n--- Menú Interactivo - Gestión de Usuarios ---")
        print("1. Listar usuarios del sistema")
        print("2. Crear usuario")
        print("3. Eliminar usuario")
        print("4. Ver grupos del sistema")
        print("5. Ver grupos de un usuario")
        print("6. Ver información detallada de un usuario")
        print("7. Salir")
        eleccion = input("Seleccione una opción [1-7]: ").strip()

        if eleccion == "1":
            listar_usuarios()
        elif eleccion == "2":
            nombre = input("Ingrese el nombre del usuario a crear: ").strip()
            if nombre and confirmar_accion(f"¿Está seguro de crear el usuario '{nombre}'?"):
                crear_usuario(nombre)
            else:
                imprimir_mensaje("Operación cancelada o nombre de usuario inválido.", "info")
        elif eleccion == "3":
            nombre = input("Ingrese el nombre del usuario a eliminar: ").strip()
            if nombre and confirmar_accion(f"¿Está seguro de eliminar el usuario '{nombre}'?"):
                eliminar_usuario(nombre)
            else:
                imprimir_mensaje("Operación cancelada o nombre de usuario inválido.", "info")
        elif eleccion == "4":
            mostrar_grupos()
        elif eleccion == "5":
            nombre = input("Ingrese el nombre del usuario para ver sus grupos: ").strip()
            if nombre:
                mostrar_grupos(nombre)
            else:
                imprimir_mensaje("Nombre de usuario inválido.", "advertencia")
        elif eleccion == "6":
            nombre = input("Ingrese el nombre del usuario para ver su información: ").strip()
            if nombre:
                info_usuario(nombre)
            else:
                imprimir_mensaje("Nombre de usuario inválido.", "advertencia")
        elif eleccion == "7":
            imprimir_mensaje("Saliendo...", "info")
            sys.exit(EXITO)
        else:
            imprimir_mensaje("Opción no válida. Por favor, intente de nuevo.", "advertencia")

# --- Punto de entrada principal ---

def main():
    """Función principal que maneja los argumentos de línea de comandos."""
    descripcion = f"Herramienta CLI multiplataforma para gestión de usuarios ({SISTEMA})"
    epilogo = """
Si no se especifica ningún comando, se iniciará el menú interactivo.
Ejemplos de uso:
  python3 script.py listar
  python3 script.py crear mi_usuario
  python3 script.py grupos --usuario mi_usuario
"""

    parser = argparse.ArgumentParser(
        description=descripcion,
        epilog=epilogo,
        formatter_class=argparse.RawTextHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="comando", help="Comandos disponibles")

    # Subcomando 'listar'
    subparsers.add_parser("listar", help="Listar usuarios del sistema")

    # Subcomando 'crear'
    crear_parser = subparsers.add_parser("crear", help="Crear un nuevo usuario")
    crear_parser.add_argument("nombre", help="Nombre del usuario a crear")

    # Subcomando 'eliminar'
    eliminar_parser = subparsers.add_parser("eliminar", help="Eliminar un usuario")
    eliminar_parser.add_argument("nombre", help="Nombre del usuario a eliminar")

    # Subcomando 'grupos'
    grupos_parser = subparsers.add_parser("grupos", help="Mostrar grupos del sistema o de un usuario específico")
    grupos_parser.add_argument("--usuario", dest="nombre", help="Mostrar grupos de un usuario específico")

    # Subcomando 'info'
    info_parser = subparsers.add_parser("info", help="Mostrar información detallada de un usuario")
    info_parser.add_argument("nombre", help="Nombre del usuario a consultar")

    args = parser.parse_args()

    if args.comando == "listar":
        listar_usuarios()
    elif args.comando == "crear":
        crear_usuario(args.nombre)
    elif args.comando == "eliminar":
        eliminar_usuario(args.nombre)
    elif args.comando == "grupos":
        mostrar_grupos(args.nombre)
    elif args.comando == "info":
        info_usuario(args.nombre)
    else:
        menu_interactivo()

if __name__ == "__main__":
    main()