
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

#--------------------------------------------------------------------------------------
# Nombre del Script: Frida Environment Setup Tool
# Versión: 1.2.3
# Descripción:
#   Este script facilita la instalación y verificación de Frida y Frida-tools.
#   Se ha añadido una lógica de AUTOREPARACIÓN de binarios en entornos virtuales
#   si la validación de funcionalidad inicial falla.
#--------------------------------------------------------------------------------------
# ==============================================================================
# --- HISTORIAL DE VERSIONES ---
# ==============================================================================
# v1.2.1 (2025-09-30) - [MEJORA DE USABILIDAD]
#   ✅ Añadido mensaje de ayuda con instrucciones de activación del VENV si la validación falla.
# v1.2.2 (2025-09-30) - [MEJORA DE MANTENIMIENTO]
#   ✅ Incluida opción para actualizar PIP antes de actualizar Frida/Frida-tools.
# v1.2.3 (2025-09-30) - [AUTOREPARACIÓN]
#   ✅ Implementada lógica para ejecutar reinstalación forzada (sin dependencias)
#      de frida-tools y frida si la prueba de funcionalidad falla en un VENV.
# ==============================================================================

import subprocess
import re
import sys
import os
import json
import signal
import time # Importar time para el pequeño retraso

VERSION = "1.2.3" # ¡Versión actualizada!
CONFIG_FILE = r"config\config_frida_tools.json"
LOG_FILE = "frida_tools.log"
global ENABLE_LOGS

def load_config():
    # Asegura que la carpeta de configuración exista
    if not os.path.exists("config"):
        os.makedirs("config")
    
    """
    Carga la configuración desde un archivo JSON o crea una por defecto.
    """
    global ENABLE_LOGS
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                config = json.load(f)
                ENABLE_LOGS = config.get("enable_logs", False)
                return config
        except json.JSONDecodeError:
            print("❌ Error: Archivo de configuración corrupto. Creando uno nuevo.")
            config = {"enable_logs": False}
            save_config(config)
            ENABLE_LOGS = False
            return config
    else:
        config = {"enable_logs": False}
        save_config(config)
        ENABLE_LOGS = False
        return config

def save_config(config):
    """
    Guarda la configuración en un archivo JSON.
    """
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=4)

def log(message):
    """
    Escribe un mensaje en el archivo de log si los logs están activados.
    """
    if ENABLE_LOGS:
        # Intentar obtener la hora de forma compatible
        try:
            if sys.platform == "win32":
                # Usar powershell para un formato más estándar en Windows
                current_time = subprocess.check_output(['powershell', '(Get-Date).ToString("yyyy-MM-dd HH:mm:ss")'], text=True).strip()
            else:
                # Usar el comando date estándar en Linux/macOS
                current_time = subprocess.check_output(['date', '+%Y-%m-%d %H:%M:%S'], text=True).strip()
        except Exception:
            current_time = "N/A" # En caso de error, usar N/A
            
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{current_time}] {message}\n")

def signal_handler(sig, frame):
    """
    Maneja interrupciones como Ctrl+C, registrándolas en el log si está activo.
    """
    print("\n\n👋 Proceso cancelado por el usuario (Ctrl+C). Saliendo del script.")
    log("Proceso cancelado por el usuario (Ctrl+C).")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# --- Funciones de Frida Environment Setup Tool ---

def get_frida_versions_from_pip(python_executable=sys.executable):
    """
    Obtiene las versiones de frida y frida-tools usando 'pip freeze'
    y un ejecutable de Python específico (para venv o host).
    """
    log(f"Iniciando la verificación de versiones con '{python_executable} -m pip freeze'.")
    versions = {'frida': None, 'frida-tools': None}
    try:
        # Usa el ejecutable de Python especificado para asegurar el entorno correcto
        result = subprocess.run([python_executable, '-m', 'pip', 'freeze'], capture_output=True, text=True, check=True, timeout=15)
        
        # Comprobar si 'frida' o 'frida-tools' están instalados de forma editable (e.g., -e git+...)
        for line in result.stdout.splitlines():
            if line.startswith('frida-tools=='):
                versions['frida-tools'] = line.split('==')[1].strip()
            elif line.startswith('frida=='):
                versions['frida'] = line.split('==')[1].strip()
        
        log(f"Versiones encontradas: {versions}")
        return versions
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        log(f"Error al ejecutar 'pip freeze' con {python_executable}: {e}")
        return versions

def update_pip_if_needed(python_executable):
    """
    Pregunta al usuario si desea actualizar pip en el entorno actual y lo ejecuta.
    """
    print("\n🔧 Verificando estado de PIP...")
    
    pip_update_choice = input("¿Deseas actualizar el gestor de paquetes PIP antes de continuar? (Recomendado, s/n): ")
    if pip_update_choice.strip().lower() == 's':
        log(f"Iniciando actualización de PIP en {python_executable}.")
        print("⬆️ Actualizando PIP...")
        try:
            # Comando estándar para actualizar pip usando el módulo de Python
            subprocess.run([python_executable, '-m', 'pip', 'install', '--upgrade', 'pip'], check=True)
            print("✅ PIP actualizado con éxito.")
            log("PIP actualizado con éxito.")
        except subprocess.CalledProcessError as e:
            log(f"Error al actualizar PIP: {e}")
            print("❌ Error: No se pudo actualizar PIP.")
            print("Esto podría deberse a problemas de permisos. Intentando continuar...")
        except FileNotFoundError:
            log(f"Error: No se encontró el ejecutable de python: {python_executable}")
            print("❌ Error: No se encontró el ejecutable de Python.")
    else:
        print("⏭️ Omitiendo actualización de PIP.")


def run_reinstall_fix(python_executable, is_venv, attempts=2):
    """
    Ejecuta la reinstalación forzada de frida y frida-tools y reintenta la validación.
    """
    if not is_venv:
        # Solo se ejecuta esta lógica de reparación en entornos virtuales (donde ocurre el error del launcher)
        return False 
    
    # 1. Mensaje de Autoreparación
    print("\n========================================================")
    print("🩹 INTENTO DE AUTOREPARACIÓN: Reconstruyendo Binarios (Launcher)")
    print("========================================================")
    log("Iniciando intento de autoreparación (reinstalación forzada) en VENV.")

    # 2. Reinstalación Forzada de frida-tools (arregla los ejecutables/launchers)
    print("🔧 1/2: Reinstalando frida-tools para corregir los lanzadores (frida.exe, frida-ps.exe)...")
    try:
        subprocess.run([python_executable, '-m', 'pip', 'install', 'frida-tools', '--force-reinstall', '--no-deps'], check=True)
        print("✅ frida-tools reinstalado con éxito.")
    except subprocess.CalledProcessError as e:
        log(f"Error al reinstalar frida-tools: {e}")
        print("❌ Error al reinstalar frida-tools. Deteniendo reparación.")
        return False

    # 3. Reinstalación Forzada de frida (arregla el módulo Python)
    print("🔧 2/2: Reinstalando frida para asegurar la integridad del módulo Python...")
    try:
        subprocess.run([python_executable, '-m', 'pip', 'install', 'frida', '--force-reinstall', '--no-deps'], check=True)
        print("✅ frida reinstalado con éxito.")
    except subprocess.CalledProcessError as e:
        log(f"Error al reinstalar frida: {e}")
        print("❌ Error al reinstalar frida. Deteniendo reparación.")
        return False
        
    print("✅ Reparación completada. Reintentando la prueba de funcionalidad en 3 segundos...")
    time.sleep(3)
    
    # 4. Reintentar la prueba de funcionalidad
    return run_validation_functionality(python_executable, is_venv, is_retry=True)


def run_validation_functionality(python_executable, is_venv, is_retry=False):
    """
    Ejecuta solo la prueba de funcionalidad (frida-ps -Uai) y devuelve True si es exitosa.
    """
    
    # Obtener el nombre de la carpeta del VENV si existe
    venv_name = os.path.basename(os.path.dirname(os.path.dirname(python_executable))) if is_venv else None
    
    # Ejecutar la prueba de funcionalidad
    print(f"\n🚀 Ejecutando prueba de funcionalidad ({'REINTENTO' if is_retry else 'INICIAL'})...")
    try:
        # Lógica para encontrar el ejecutable de frida-ps
        if is_venv and sys.platform == "win32":
            frida_ps_executable = os.path.join(os.path.dirname(python_executable), "frida-ps.exe")
        elif is_venv and sys.platform != "win32":
            frida_ps_executable = os.path.join(os.path.dirname(python_executable), "frida-ps")
        else:
            # Para el host, asumimos que está en el PATH
            frida_ps_executable = 'frida-ps'
            
        result = subprocess.run([frida_ps_executable, '-Uai'], capture_output=True, text=True, check=True, timeout=15)
        print("✅ La prueba de funcionalidad se ejecutó con éxito. ¡Todo listo!")
        log(f"Prueba de funcionalidad exitosa ({'REINTENTO' if is_retry else 'INICIAL'}).")
        print("\n--- Ejemplo de salida ---")
        print(result.stdout)
        return True
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        log(f"Error en la prueba de funcionalidad ({'REINTENTO' if is_retry else 'INICIAL'}): {e}")
        print(f"❌ Error en la prueba de funcionalidad: {e}")
        print("Revisa si hay problemas de permisos o si la instalación no se completó.")
        
        # --- LÓGICA DE AYUDA PARA VENV (solo si falla el reintento o si no es un VENV) ---
        if is_venv and venv_name and (is_retry or not is_venv):
            print("\n========================================================")
            print("💡 AYUDA: Fallo en Entorno Virtual")
            print("========================================================")
            print(f"El fallo de 'frida-ps -Uai' probablemente se debe a que NO hay un dispositivo móvil conectado O el 'frida-server' no está ejecutándose en él.")
            print(f"Para depurar manualmente, ACTIVA el entorno virtual y reintenta:")
            
            # Intentamos determinar la ruta del VENV de forma relativa a la ubicación del script
            script_dir = os.path.abspath(os.path.dirname(sys.argv[0]))
            relative_venv_dir = os.path.relpath(os.path.join(script_dir, venv_name))

            if sys.platform == "win32":
                print(f"\n🖥️  Windows (CMD o PowerShell):")
                print(f"   cd {relative_venv_dir}")
                print(f"   .\\Scripts\\activate")
                print("\n   Luego intenta:")
                print(f"   frida-ps -Uai")
            else:
                print(f"\n🐧/🍎 Linux o macOS (Bash/Zsh):")
                print(f"   source {relative_venv_dir}/bin/activate")
                print("\n   Luego intenta:")
                print(f"   frida-ps -Uai")
            
            print("\n⚠️  Recuerda: El servidor 'frida-server' (misma versión) debe estar corriendo en el dispositivo móvil.")
            print("========================================================")
        
        return False # Falla la prueba de funcionalidad

def run_validation_generic(python_executable, is_venv):
    """
    Función de validación unificada para host y venv, incluyendo la lógica de autoreparación.
    """
    log(f"Iniciando validación de versiones y funcionalidad. Ejecutable: {python_executable}")
    versions = get_frida_versions_from_pip(python_executable)
    print("\n🔍 Verificando versiones...")
    
    frida_version = versions.get('frida')
    frida_tools_version = versions.get('frida-tools')
    
    # Formatear la salida de las versiones
    print(f"✅ Frida-tools: {frida_tools_version if frida_tools_version else 'No Instalado'}")
    print(f"✅ Frida: {frida_version if frida_version else 'No Instalado'}")
    
    if frida_version and frida_tools_version:
        print("🎉 ¡Todo listo! Las versiones están disponibles.")
    else:
        print("⚠️ Advertencia: No se pudieron obtener las versiones completas. Comprobando funcionalidad...")
        log("Advertencia: No se pudieron obtener todas las versiones.")
    
    # Lógica de prueba y reparación
    if run_validation_functionality(python_executable, is_venv):
        # La prueba inicial fue exitosa, no hace falta reparar.
        pass
    elif is_venv:
        # La prueba inicial falló Y estamos en un VENV, intentamos reparar.
        run_reinstall_fix(python_executable, is_venv)
        
    print("\n--- Proceso completado ---")


def update_frida(is_venv, python_executable=sys.executable):
    """
    Ejecuta el proceso de actualización para frida y frida-tools, con pre-verificación de PIP.
    """
    log(f"Iniciando actualización. Entorno virtual: {is_venv}, Ejecutable: {python_executable}")
    
    # PASO 1: Actualizar PIP
    update_pip_if_needed(python_executable)

    # PASO 2: Actualizar Frida y Frida-tools
    print("\n⬆️ Intentando actualizar frida y frida-tools...")
    
    try:
        subprocess.run([python_executable, '-m', 'pip', 'install', '--upgrade', 'frida-tools', 'frida'], check=True)
        print("✅ Actualización de Frida/Frida-tools completada con éxito.")
        log("Actualización de Frida/Frida-tools completada con éxito.")
    except subprocess.CalledProcessError as e:
        log(f"Error de actualización: {e}")
        print("❌ Error: No se pudo actualizar frida.")
        if not is_venv:
            print("Intenta ejecutar el script con permisos de administrador (sudo en Linux/macOS).")
        return False
    except FileNotFoundError:
        log(f"Error: No se encontró el ejecutable de python: {python_executable}")
        print("❌ Error: No se encontró el ejecutable de Python para el entorno.")
        return False
    
    # PASO 3: Ejecutar validación post-actualización
    run_validation_generic(python_executable, is_venv)
    return True


def install_and_verify(is_venv, python_executable=sys.executable):
    """
    Maneja la lógica de instalación para el entorno virtual o el host.
    """
    
    # PASO 1: Preguntar por la actualización de PIP
    update_pip_if_needed(python_executable)

    # PASO 2: Instalación de Frida
    try:
        log(f"Iniciando instalación. Entorno virtual: {is_venv}, Ejecutable: {python_executable}")
        print("\n📦 Intentando instalar frida y frida-tools...")
        subprocess.run([python_executable, '-m', 'pip', 'install', 'frida-tools', 'frida'], check=True)
        print("✅ Instalación completada con éxito.")
        log("Instalación completada con éxito.")
    except subprocess.CalledProcessError as e:
        log(f"Error de instalación: {e}")
        print("❌ Error: No se pudo instalar frida.")
        if not is_venv:
            print("Intenta ejecutar el script con permisos de administrador (sudo en Linux/macOS).")
        sys.exit(1)

# --- Funciones de Menú (No modificadas) ---

def setup_virtual_env_auto():
    # ... (código anterior sin cambios) ...
    log("Iniciando configuración de entorno virtual.")
    print("\n--- Instalación en un Entorno Virtual ---")
    default_venv_dir = "frida_env"
    
    user_choice = input(f"¿Deseas mantener el nombre del entorno virtual '{default_venv_dir}'? (s/n): ")
    if user_choice.strip().lower() != 's':
        venv_dir = input("Ingresa el nombre para el entorno virtual: ").strip()
        if not venv_dir:
            venv_dir = default_venv_dir
            print(f"Nombre no válido. Se usará el nombre por defecto: {default_venv_dir}")
    else:
        venv_dir = default_venv_dir
        
    python_executable = os.path.join(venv_dir, "Scripts", "python") if sys.platform == "win32" else os.path.join(venv_dir, "bin", "python")

    # 1. Comprobar si el VENV y Frida ya existen
    if os.path.exists(venv_dir):
        print(f"⚠️ El entorno virtual '{venv_dir}' ya existe.")
        
        # Comprobar si Frida ya está instalado dentro del venv
        versions = get_frida_versions_from_pip(python_executable)
        
        if versions.get('frida') or versions.get('frida-tools'):
            print("✅ Frida ya parece estar instalado en este entorno.")
            
            update_choice = input("¿Deseas ejecutar el proceso de ACTUALIZACIÓN de Frida y Frida-tools? (s/n): ")
            if update_choice.strip().lower() == 's':
                update_frida(is_venv=True, python_executable=python_executable)
                return
            else:
                run_validation_generic(python_executable, is_venv=True)
                return

    # 2. Creación del entorno virtual
    print(f"👉 Creando entorno virtual en: ./{venv_dir}")
    try:
        subprocess.run([sys.executable, '-m', 'venv', venv_dir], check=True)
        print("✅ Entorno virtual creado con éxito.")
        log("Entorno virtual creado.")
    except subprocess.CalledProcessError:
        print("❌ Error: No se pudo crear el entorno virtual. Asegúrate de tener el módulo 'venv'.")
        log("Error al crear entorno virtual.")
        return

    # 3. Instalación inicial (incluye actualización de PIP si el usuario la acepta)
    print(f"✅ Activando e instalando en el entorno virtual '{venv_dir}'...")
    install_and_verify(is_venv=True, python_executable=python_executable)
    
    # 4. Verificación final
    print("\n--- Verificación final de la instalación en el entorno virtual ---")
    run_validation_generic(python_executable, is_venv=True)


def setup_host_auto():
    # ... (código anterior sin cambios) ...
    log("Iniciando configuración en sistema host.")
    print("\n--- Instalación/Actualización en el Sistema Host (Global) ---")
    
    # 1. Comprobar si Frida ya está instalado
    versions_before = get_frida_versions_from_pip(sys.executable)
    
    if versions_before['frida'] or versions_before['frida-tools']:
        print("✅ Frida o sus herramientas ya están instaladas en el sistema host.")
        
        update_choice = input("¿Deseas ejecutar el proceso de ACTUALIZACIÓN de Frida y Frida-tools? (s/n): ")
        if update_choice.strip().lower() == 's':
            update_frida(is_venv=False, python_executable=sys.executable)
        else:
            run_validation_generic(sys.executable, is_venv=False)
    else:
        # 2. Instalación inicial (incluye actualización de PIP si el usuario la acepta)
        install_and_verify(is_venv=False, python_executable=sys.executable)
        # 3. Verificación final
        run_validation_generic(sys.executable, is_venv=False)


def main():
    """
    Muestra el menú de configuración de Frida y sus herramientas.
    """
    load_config() # Carga la configuración al inicio
    global ENABLE_LOGS
    while True:
        print("---------------------------------------")
        print("        Frida Environment Setup Tool         ")
        print("---------------------------------------")
        print(f"Versión: {VERSION}")
        print("Descripción: Este script automatiza la instalación y validación de Frida.")
        print("\nOpciones:")
        print("1. Instalar/Actualizar en un Entorno Virtual (Recomendado) 🚀")
        print("2. Instalar/Actualizar en el Sistema Host (Global)")
        print("3. Validar/Actualizar Instalación del Host (Rápida)")
        print(f"4. Toggle Logging (Actual: {'Activado' if ENABLE_LOGS else 'Desactivado'})")
        print("5. Salir del script")
        print("---------------------------------------")
        try:
            choice = input("Selecciona una opción (1-5): ")
            if choice == '1':
                setup_virtual_env_auto()
            elif choice == '2':
                setup_host_auto()
            elif choice == '3':
                # Opción para validar/actualizar la instalación global
                print("\n--- Validación y posible Actualización en el Sistema Host ---")
                versions_before = get_frida_versions_from_pip(sys.executable)
                
                if versions_before['frida'] or versions_before['frida-tools']:
                    update_choice = input("Frida parece estar instalado. ¿Deseas ejecutar el proceso de ACTUALIZACIÓN de Frida y Frida-tools? (s/n): ")
                    if update_choice.strip().lower() == 's':
                        update_frida(is_venv=False, python_executable=sys.executable)
                    else:
                        run_validation_generic(sys.executable, is_venv=False)
                else:
                    print("⚠️ Frida no parece estar instalado en el Host. Usa la opción 2 para instalarlo.")
                    run_validation_generic(sys.executable, is_venv=False) # Solo valida lo que encuentre
            elif choice == '4':
                config = load_config()
                config["enable_logs"] = not config["enable_logs"]
                save_config(config)
                ENABLE_LOGS = config["enable_logs"]
                print(f"Logging ahora está: {'Activado' if ENABLE_LOGS else 'Desactivado'}")
            elif choice == '5':
                print("\n👋 Saliendo del script. ¡Hasta la próxima!")
                log("Usuario salió del script mediante opción de menú.")
                break
            else:
                print("❌ Opción no válida. Por favor, elige una opción del 1 al 5.")
        except KeyboardInterrupt:
            # Esto captura Ctrl+C dentro del input o ciclo
            print("\n\n👋 Proceso cancelado por el usuario (Ctrl+C). Saliendo del script.")
            log("Proceso cancelado por el usuario (Ctrl+C).")
            break


print("\n[!] AVISO LEGAL: Use solo con autorizacion. / LEGAL NOTICE: Authorized use only.\n")
if __name__ == "__main__":
    main()