#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# =============================================================================
# AVISO LEGAL / LEGAL NOTICE
# -----------------------------------------------------------------------------
# Esta herramienta es unicamente para fines educativos y de auditoria de
# seguridad autorizada. El uso no autorizado contra sistemas sin el
# consentimiento explicito del propietario es ilegal.
# El usuario asume toda responsabilidad por el uso indebido.
#
# This tool is for educational and authorized security auditing purposes only.
# Unauthorized use against systems without the owner's explicit consent is
# illegal. The user assumes all responsibility for misuse.
# =============================================================================

"""
Script: Gestión de Usuarios Multiplataforma
Versión: 2.0
Fecha: 2025-10-01
Autor: Pentester
Descripción: Herramienta CLI para gestión de usuarios en Windows, Linux y macOS
Changelog:
  v2.0 (2025-10-01)
    - ✅ Detección avanzada de entorno (distro Linux, versión Windows/macOS)
    - ✅ Verificación robusta de privilegios multiplataforma
    - ✅ Mejoras en manejo de encoding UTF-8
    - ✅ Información detallada del sistema al inicio
    - ✅ Validación de comandos disponibles
  v1.0 (2025-09-30)
    - 🎯 Versión inicial con funciones básicas
"""

import argparse
import subprocess
import sys
import os
import getpass
import platform
import ctypes

# --- Constantes y configuración ---
VERSION = "2.0"
SISTEMA = platform.system()
EXITO = 0
FALLO = 1

# --- Funciones de detección de entorno ---

def obtener_info_detallada_sistema():
    """
    Obtiene información detallada del sistema operativo.
    Returns:
        dict: Diccionario con información del sistema.
    """
    info = {
        "sistema": SISTEMA,
        "release": platform.release(),
        "version": platform.version(),
        "arquitectura": platform.machine(),
        "procesador": platform.processor(),
        "python_version": platform.python_version(),
        "detalles": ""
    }
    
    if SISTEMA == "Linux":
        try:
            # Obtener información de la distribución Linux
            os_info = platform.freedesktop_os_release()
            info["distro_nombre"] = os_info.get("NAME", "Desconocido")
            info["distro_id"] = os_info.get("ID", "Desconocido")
            info["distro_version"] = os_info.get("VERSION_ID", "Desconocido")
            info["detalles"] = f"{info['distro_nombre']} {info['distro_version']}"
        except (OSError, KeyError):
            info["detalles"] = f"Linux {platform.release()}"
    
    elif SISTEMA == "Darwin":  # macOS
        mac_ver = platform.mac_ver()
        info["macos_version"] = mac_ver[0]
        info["detalles"] = f"macOS {mac_ver[0]}"
    
    elif SISTEMA == "Windows":
        win_ver = platform.win32_ver()
        info["windows_release"] = win_ver[0]
        info["windows_version"] = win_ver[1]
        try:
            info["windows_edition"] = platform.win32_edition()
            info["detalles"] = f"Windows {win_ver[0]} {info['windows_edition']}"
        except:
            info["detalles"] = f"Windows {win_ver[0]}"
    
    return info

def es_admin():
    """
    Verifica si el usuario actual tiene privilegios de administrador/root.
    Funciona en Windows, Linux y macOS.
    Returns:
        bool: True si tiene privilegios de administrador, False en caso contrario.
    """
    try:
        # Linux y macOS: verificar si UID es 0 (root)
        return os.getuid() == 0
    except AttributeError:
        # Windows: usar ctypes para verificar privilegios de administrador
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False

def verificar_comando_disponible(comando):
    """
    Verifica si un comando está disponible en el sistema.
    Args:
        comando (str): Nombre del comando a verificar.
    Returns:
        bool: True si el comando está disponible, False en caso contrario.
    """
    try:
        if SISTEMA == "Windows":
            subprocess.run(["where", comando], capture_output=True, check=True)
        else:
            subprocess.run(["which", comando], capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

def mostrar_info_entorno():
    """Muestra información detallada del entorno de ejecución."""
    info = obtener_info_detallada_sistema()
    es_root = es_admin()
    
    print("\n" + "="*60)
    print(f"  Gestión de Usuarios Multiplataforma v{VERSION}")
    print("="*60)
    print(f"Sistema Operativo: {info['detalles']}")
    print(f"Arquitectura: {info['arquitectura']}")
    print(f"Python: {info['python_version']}")
    print(f"Usuario actual: {getpass.getuser()}")
    print(f"Privilegios de administrador: {'✓ SÍ' if es_root else '✗ NO'}")
    print("="*60 + "\n")

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
    if verificar_root and not es_admin():
        if SISTEMA == "Windows":
            imprimir_mensaje("Debes ejecutar este script como Administrador.", "advertencia")
        else:
            imprimir_mensaje("Debes ejecutar este comando como root (sudo).", "advertencia")
        return ""
    
    # Determinar encoding según el sistema
    encoding = 'utf-8'
    if SISTEMA == "Windows":
        # Windows puede usar cp850, cp1252 u otros encodings según la región
        encoding = 'cp850'
    
    try:
        resultado = subprocess.run(
            comando, 
            capture_output=True, 
            text=True, 
            check=True, 
            encoding=encoding, 
            errors='replace'
        )
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
    respuesta = input(f"{pregunta} [s/n]: ").strip().lower()
    return respuesta in ['s', 'y', 'si', 'yes']

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
                if not linea.strip() or "Cuentas de usuario" in linea or "---" in linea or "completado" in linea or "comando" in linea.lower():
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

    elif SISTEMA == "Linux":
        if verificar_comando_disponible("getent"):
            salida = ejecutar_comando(["getent", "passwd"])
            if salida:
                print("[✓] Usuarios del sistema (con /home/ o /usr/local/):")
                for linea in salida.splitlines():
                    partes = linea.split(":")
                    if len(partes) >= 6:
                        # Filtrar usuarios del sistema y mostrar solo usuarios reales
                        if (partes[5].startswith("/home/") or partes[5].startswith("/usr/local/")) and \
                           partes[6] not in ["/bin/false", "/usr/sbin/nologin", "/sbin/nologin"]:
                            print(f"Usuario: {partes[0]}, Home: {partes[5]}, Shell: {partes[6]}")
            else:
                imprimir_mensaje("No se pudo obtener la lista de usuarios.", "advertencia")
        else:
            imprimir_mensaje("Comando 'getent' no disponible. Usando /etc/passwd...", "advertencia")
            salida = ejecutar_comando(["cat", "/etc/passwd"])
            if salida:
                print("[✓] Usuarios del sistema:")
                for linea in salida.splitlines():
                    partes = linea.split(":")
                    if len(partes) >= 6 and partes[5].startswith("/home/"):
                        print(f"Usuario: {partes[0]}, Home: {partes[5]}")

    elif SISTEMA == "Darwin":  # macOS
        if verificar_comando_disponible("dscl"):
            salida = ejecutar_comando(["dscl", ".", "list", "/Users"])
            if salida:
                print("[✓] Usuarios del sistema:")
                for linea in salida.splitlines():
                    usuario = linea.strip()
                    # Filtrar usuarios del sistema (comienzan con _ o son daemon/nobody)
                    if usuario and not usuario.startswith("_") and usuario not in ["daemon", "nobody"]:
                        print(f"  - {usuario}")
            else:
                imprimir_mensaje("No se pudo obtener la lista de usuarios.", "advertencia")
        else:
            imprimir_mensaje("Comando 'dscl' no disponible.", "error")
    else:
        imprimir_mensaje(f"Sistema '{SISTEMA}' no compatible para listar usuarios.", "advertencia")

def crear_usuario(nombre):
    """Crea un nuevo usuario."""
    imprimir_mensaje(f"Creando usuario: {nombre}")
    if SISTEMA == "Windows":
        resultado = ejecutar_comando(["net", "user", nombre, "/add"], verificar_root=True)
        if resultado is not None and resultado != "":
            imprimir_mensaje(f"Usuario '{nombre}' creado correctamente.", "exito")
        else:
            imprimir_mensaje(f"Fallo al crear el usuario '{nombre}'.", "error")
    elif SISTEMA in ["Linux", "Darwin"]:
        if verificar_comando_disponible("useradd"):
            resultado = ejecutar_comando(["useradd", "-m", nombre], verificar_root=True)
            if resultado is not None:
                imprimir_mensaje(f"Usuario '{nombre}' creado correctamente.", "exito")
                imprimir_mensaje(f"Recuerda establecer una contraseña con: passwd {nombre}", "info")
            else:
                imprimir_mensaje(f"Fallo al crear el usuario '{nombre}'.", "error")
        else:
            imprimir_mensaje("Comando 'useradd' no disponible.", "error")
    else:
        imprimir_mensaje(f"Sistema '{SISTEMA}' no compatible para crear usuarios.", "advertencia")

def eliminar_usuario(nombre):
    """Elimina un usuario."""
    imprimir_mensaje(f"Eliminando usuario: {nombre}")
    if SISTEMA == "Windows":
        resultado = ejecutar_comando(["net", "user", nombre, "/delete"], verificar_root=True)
        if resultado is not None:
            imprimir_mensaje(f"Usuario '{nombre}' eliminado correctamente.", "exito")
        else:
            imprimir_mensaje(f"Fallo al eliminar el usuario '{nombre}'.", "error")
    elif SISTEMA in ["Linux", "Darwin"]:
        if verificar_comando_disponible("userdel"):
            resultado = ejecutar_comando(["userdel", "-r", nombre], verificar_root=True)
            if resultado is not None:
                imprimir_mensaje(f"Usuario '{nombre}' eliminado correctamente.", "exito")
            else:
                imprimir_mensaje(f"Fallo al eliminar el usuario '{nombre}'.", "error")
        else:
            imprimir_mensaje("Comando 'userdel' no disponible.", "error")
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
                    if "Miembro de" in linea or "Local Group Memberships" in linea or "pertenencia" in linea.lower():
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
            if verificar_comando_disponible("groups"):
                salida = ejecutar_comando(["groups", nombre])
                if salida:
                    print(f"[✓] Grupos de {nombre}: {salida}")
                else:
                    imprimir_mensaje(f"El usuario '{nombre}' no existe o no tiene grupos asignados.", "advertencia")
            else:
                imprimir_mensaje("Comando 'groups' no disponible.", "error")
        else:
            salida = ejecutar_comando(["cat", "/etc/group"])
            if salida:
                print("[✓] Grupos del sistema:")
                for linea in salida.splitlines()[:20]:  # Mostrar solo los primeros 20
                    print(linea)
                print(f"\n... ({len(salida.splitlines())} grupos en total)")
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
        if verificar_comando_disponible("id"):
            salida = ejecutar_comando(["id", nombre])
            if salida:
                print(f"[✓] {salida}")
                # Información adicional del usuario
                salida_passwd = ejecutar_comando(["getent", "passwd", nombre]) if verificar_comando_disponible("getent") else ""
                if salida_passwd:
                    partes = salida_passwd.split(":")
                    if len(partes) >= 6:
                        print(f"[✓] Home: {partes[5]}, Shell: {partes[6]}")
            else:
                imprimir_mensaje(f"No se encontró información para '{nombre}'.", "advertencia")
        else:
            imprimir_mensaje("Comando 'id' no disponible.", "error")
    else:
        imprimir_mensaje(f"Sistema '{SISTEMA}' no compatible para mostrar información de usuario.", "advertencia")

# --- Menú Interactivo ---

def menu_interactivo():
    """Muestra un menú interactivo para la gestión de usuarios."""
    # Mostrar información del entorno al inicio
    mostrar_info_entorno()
    
    while True:
        print("\n--- Menú Interactivo - Gestión de Usuarios ---")
        print("1. Listar usuarios del sistema")
        print("2. Crear usuario")
        print("3. Eliminar usuario")
        print("4. Ver grupos del sistema")
        print("5. Ver grupos de un usuario")
        print("6. Ver información detallada de un usuario")
        print("7. Mostrar información del entorno")
        print("8. Salir")
        eleccion = input("\nSeleccione una opción [1-8]: ").strip()

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
            if nombre and confirmar_accion(f"¿Está seguro de eliminar el usuario '{nombre}'? Esta acción es IRREVERSIBLE."):
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
            mostrar_info_entorno()
        elif eleccion == "8":
            imprimir_mensaje("Saliendo...", "info")
            sys.exit(EXITO)
        else:
            imprimir_mensaje("Opción no válida. Por favor, intente de nuevo.", "advertencia")

# --- Punto de entrada principal ---

def main():
    """Función principal que maneja los argumentos de línea de comandos."""
    descripcion = f"Herramienta CLI multiplataforma para gestión de usuarios v{VERSION}"
    epilogo = """
Si no se especifica ningún comando, se iniciará el menú interactivo.

Ejemplos de uso:
  python3 script.py listar
  python3 script.py crear mi_usuario
  python3 script.py grupos --usuario mi_usuario
  python3 script.py info mi_usuario
  
Nota: Las operaciones de creación y eliminación requieren privilegios de administrador.
"""

    parser = argparse.ArgumentParser(
        description=descripcion,
        epilog=epilogo,
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    parser.add_argument("--info-sistema", action="store_true", help="Mostrar información detallada del sistema")
    
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

    if args.info_sistema:
        mostrar_info_entorno()
        sys.exit(EXITO)

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


print("\n[!] AVISO LEGAL: Use solo con autorizacion. / LEGAL NOTICE: Authorized use only.\n")
if __name__ == "__main__":
    main()
