
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

import subprocess
import argparse
import sys
import time
import requests
import os
import shutil

LANG = "es"

TR: dict[str, dict[str, str]] = {
    "es": {
        "ejecutando": "Ejecutando",
        "error_comando": "ERROR al ejecutar el comando",
        "tip_docker": "Tip: Asegurate de estar en el directorio raiz de pwndoc donde se encuentra docker-compose.yml.",
        "cmd_no_encontrado": "ERROR: {} no se encontro. Asegurate de que este instalado y en tu PATH.",
        "cmd_no_encontrado_gen": "ERROR: Comando no encontrado",
        "interrumpido": "Operacion interrumpida por el usuario.",
        "timeout_comando": "ERROR: El comando {} ha excedido el tiempo de ejecucion (300s).",
        "verificando_docker": "Verificando el estado del Docker Daemon...",
        "docker_ok": "Docker Daemon esta accesible.",
        "docker_error": "Fallo de conexion al Docker Daemon.",
        "docker_iniciar": "Por favor, inicia **Docker Desktop** o el **servicio Docker** y vuelve a intentarlo.",
        "docker_timeout": "La verificacion del Docker Daemon agoto el tiempo de espera.",
        "docker_error_inesperado": "ERROR Inesperado durante la verificacion del Daemon",
        "esperando_pwndoc": "Esperando a que el servicio Pwndoc este listo en",
        "pausa_inicial": "Pausa inicial de {} segundos para la inicializacion",
        "continuar_verificacion": "... Continuar verificacion.",
        "pwndoc_ok": "Servicio Pwndoc OK! El sitio web principal respondio correctamente.",
        "accede_pwndoc": "Accede a Pwndoc en tu navegador en",
        "pwndoc_error": "ERROR! El servicio Pwndoc no estuvo disponible en {} segundos.",
        "clonando_repo": "El archivo 'docker-compose.yml' no se encuentra en el directorio actual.",
        "clonando_proceder": "Clonando el repositorio de pwndoc en la carpeta",
        "directorio_cambiado": "Se ha cambiado el directorio de trabajo a",
        "carpeta_encontrada": "Se encontro la carpeta",
        "cambiando_directorio": "Cambiando el directorio de trabajo.",
        "iniciando_build": "Iniciando: Construyendo imagenes y levantando contenedores (en segundo plano)...",
        "orquestacion_ok": "Proceso de Orquestacion Finalizado con Exito.",
        "orquestacion_https": "El acceso es HTTPS (https://localhost:8443).",
        "orquestacion_recordatorio": "Recordatorio: Debes cambiar los certificados SSL y el secreto JWT para produccion.",
        "orquestacion_fallo_validacion": "La validacion del servicio Pwndoc fallo despues de levantarse. Ver logs con 'logs'.",
        "orquestacion_fallo_up": "El comando 'docker-compose up' fallo. Revisa los logs de error anteriores.",
        "mostrando_logs": "Mostrando logs en tiempo real para el servicio",
        "deteniendo_contenedores": "Deteniendo contenedores de pwndoc...",
        "iniciando_contenedores": "Iniciando contenedores de pwndoc...",
        "eliminando_contenedores": "Eliminando contenedores, redes y volumenes de pwndoc...",
        "error_no_docker_compose": "ERROR CRITICO: No se encontro 'docker-compose.yml'.",
        "error_para_actualizar": "Para actualizar, debes ejecutar este script DENTRO de la carpeta 'pwndoc'. Abortando.",
        "proceso_actualizacion": "Proceso de Actualizacion de pwndoc",
        "no_detener": "No se pudo detener completamente la aplicacion (puede que no estuviera corriendo), continuando...",
        "actualizando_codigo": "Actualizando codigo fuente con git pull...",
        "error_git_pull": "No se pudo realizar el git pull. Abortando actualizacion.",
        "reconstruyendo": "Reconstruyendo y levantando la aplicacion con el nuevo codigo...",
        "actualizacion_completada": "Actualizacion de pwndoc completada!",
        "error_critico_no_dir": "ERROR CRITICO: No se encontro el archivo 'docker-compose.yml' y tampoco la carpeta 'pwndoc'.",
        "error_ejecutar_accion": "Para ejecutar esta accion, debes estar dentro del directorio 'pwndoc' o ejecutar 'up' primero.",
        "no_directorio": "No se pudo configurar el directorio de pwndoc. Abortando.",
        "advertencias": "Advertencias/Salida de error (no fatal)",
    },
    "en": {
        "ejecutando": "Running",
        "error_comando": "ERROR running command",
        "tip_docker": "Tip: Make sure you are in the pwndoc root directory where docker-compose.yml is located.",
        "cmd_no_encontrado": "ERROR: {} not found. Make sure it is installed and in your PATH.",
        "cmd_no_encontrado_gen": "ERROR: Command not found",
        "interrumpido": "Operation interrupted by the user.",
        "timeout_comando": "ERROR: Command {} exceeded execution time (300s).",
        "verificando_docker": "Checking Docker Daemon status...",
        "docker_ok": "Docker Daemon is accessible.",
        "docker_error": "Failed to connect to Docker Daemon.",
        "docker_iniciar": "Please start **Docker Desktop** or the **Docker service** and try again.",
        "docker_timeout": "Docker Daemon check timed out.",
        "docker_error_inesperado": "Unexpected error during Daemon check",
        "esperando_pwndoc": "Waiting for Pwndoc service to be ready at",
        "pausa_inicial": "Initial pause of {} seconds for initialization",
        "continuar_verificacion": "... Continuing verification.",
        "pwndoc_ok": "Pwndoc Service OK! The main website responded successfully.",
        "accede_pwndoc": "Access Pwndoc in your browser at",
        "pwndoc_error": "ERROR! Pwndoc service was not available within {} seconds.",
        "clonando_repo": "The file 'docker-compose.yml' was not found in the current directory.",
        "clonando_proceder": "Cloning pwndoc repository into folder",
        "directorio_cambiado": "Changed working directory to",
        "carpeta_encontrada": "Folder found",
        "cambiando_directorio": "Changing working directory.",
        "iniciando_build": "Starting: Building images and starting containers (background)...",
        "orquestacion_ok": "Orchestration Process Completed Successfully.",
        "orquestacion_https": "Access is HTTPS (https://localhost:8443).",
        "orquestacion_recordatorio": "Reminder: You must change SSL certificates and JWT secret for production.",
        "orquestacion_fallo_validacion": "Pwndoc service validation failed after startup. Check logs with 'logs'.",
        "orquestacion_fallo_up": "Command 'docker-compose up' failed. Check error logs above.",
        "mostrando_logs": "Showing real-time logs for service",
        "deteniendo_contenedores": "Stopping pwndoc containers...",
        "iniciando_contenedores": "Starting pwndoc containers...",
        "eliminando_contenedores": "Removing pwndoc containers, networks and volumes...",
        "error_no_docker_compose": "CRITICAL ERROR: 'docker-compose.yml' not found.",
        "error_para_actualizar": "To update, you must run this script INSIDE the 'pwndoc' folder. Aborting.",
        "proceso_actualizacion": "Pwndoc Update Process",
        "no_detener": "Could not fully stop the application (it may not have been running), continuing...",
        "actualizando_codigo": "Updating source code with git pull...",
        "error_git_pull": "Could not perform git pull. Aborting update.",
        "reconstruyendo": "Rebuilding and starting the application with the new code...",
        "actualizacion_completada": "Pwndoc update completed!",
        "error_critico_no_dir": "CRITICAL ERROR: Neither 'docker-compose.yml' nor 'pwndoc' folder was found.",
        "error_ejecutar_accion": "To run this action, you must be inside the 'pwndoc' directory or run 'up' first.",
        "no_directorio": "Could not set up pwndoc directory. Aborting.",
        "advertencias": "Warnings/Error output (non-fatal)",
    },
}


def _(key: str, **kwargs) -> str:
    t = TR.get(LANG, TR["es"]).get(key, key)
    if kwargs:
        t = t.format(**kwargs)
    return t


# --- Constantes de Configuracion ---
PWNDOC_PORT = 8443
BACKEND_SERVICE = "pwndoc-backend"
TIMEOUT_SECONDS = 180
INITIAL_WAIT = 20
PWNDOC_REPO_URL = "https://github.com/pwndoc/pwndoc.git"
PWNDOC_DIR_NAME = "pwndoc"


def run_command(command, check=True):
    command_str = " ".join(command)
    if command[0] != "docker-compose" or command[1] != "logs":
        print(f"\n--- {_('ejecutando')}: {command_str} ---")

    try:
        result = subprocess.run(
            command,
            check=check,
            text=True,
            capture_output=(command[0] != "docker-compose" or command[1] != "logs"),
            timeout=300
        )

        if result.stdout and (command[0] != "docker-compose" or command[1] != "logs"):
            print(result.stdout)

        if result.stderr and check and (command[0] != "docker-compose" or command[1] != "logs"):
            print(f"{_('advertencias')}: {result.stderr}")

        return result

    except subprocess.CalledProcessError as e:
        print(f"\n!!! {_('error_comando')}: {command_str} !!!")
        print(f"Salida de error:\n{e.stderr}")
        print(f"💡 {_('tip_docker')}")
        sys.exit(1)
    except FileNotFoundError:
        if command[0] in ["docker-compose", "git"]:
            print(f"\n!!! {_('cmd_no_encontrado').format(command[0])} !!!")
        else:
            print(f"\n!!! {_('cmd_no_encontrado_gen')}: {command[0]} !!!")
        sys.exit(1)
    except KeyboardInterrupt:
        print(f"\n{_('interrumpido')}")
        sys.exit(1)
    except subprocess.TimeoutExpired:
        print(f"\n!!! {_('timeout_comando').format(command_str)} !!!")
        sys.exit(1)
    return None

def check_docker_daemon():
    print(f"\U0001f50e {_('verificando_docker')}")
    try:
        subprocess.run(
            ["docker", "info"],
            check=True,
            text=True,
            capture_output=True,
            timeout=10
        )
        print(f"\u2705 {_('docker_ok')}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"\u274c **{_('docker_error')}**")
        if "error during connect" in e.stderr.lower() or "connection refused" in e.stderr.lower():
            print(f"\u27a1\ufe0f {_('docker_iniciar')}")
        else:
            print(f"Detalle del error:\n{e.stderr}")
        sys.exit(1)
    except subprocess.TimeoutExpired:
        print(f"\u274c **{_('docker_timeout')}**")
        sys.exit(1)
    except Exception as e:
        print(f"\u274c {_('docker_error_inesperado')}: {e}")
        sys.exit(1)

def check_pwndoc_status(port):
    service_url = f"https://localhost:{port}"
    start_time = time.time()
    print(f"\n\U0001f50d {_('esperando_pwndoc')} {service_url}...")

    print(f"   ({_('pausa_inicial').format(INITIAL_WAIT)})", end="", flush=True)
    time.sleep(INITIAL_WAIT)
    print(f"{_('continuar_verificacion')}")

    while time.time() - start_time < TIMEOUT_SECONDS:
        try:
            response = requests.get(service_url, verify=False, timeout=10)

            if response.status_code == 200 and "pwndoc" in response.text.lower():
                print(f"\n\U0001f389 **{_('pwndoc_ok')}**")
                print(f"\U0001f310 {_('accede_pwndoc')}: **{service_url}**")
                return True

            print("|", end="", flush=True)
            time.sleep(5)

        except requests.exceptions.ConnectionError:
            print(".", end="", flush=True)
            time.sleep(5)
        except requests.exceptions.Timeout:
            print("T", end="", flush=True)
            time.sleep(10)
        except requests.exceptions.RequestException as e:
            if "certificate verify failed" not in str(e):
                print("E", end="", flush=True)
            else:
                print("S", end="", flush=True)
            time.sleep(5)

    print(f"\n\u274c **{_('pwndoc_error').format(TIMEOUT_SECONDS)}**")
    return False

def setup_pwndoc_directory():
    if os.path.exists("docker-compose.yml"):
        return True

    if not os.path.isdir(PWNDOC_DIR_NAME):
        print(f"\n\u26a0\ufe0f {_('clonando_repo')}")
        print(f"\u2b07\ufe0f {_('clonando_proceder')} '{PWNDOC_DIR_NAME}'...")

        run_command(["git", "clone", PWNDOC_REPO_URL, PWNDOC_DIR_NAME])

        os.chdir(PWNDOC_DIR_NAME)
        print(f"\u2705 {_('directorio_cambiado')}: {os.getcwd()}")
        return True

    else:
        print(f"\n\u27a1\ufe0f {_('carpeta_encontrada')} '{PWNDOC_DIR_NAME}'. {_('cambiando_directorio')}")
        os.chdir(PWNDOC_DIR_NAME)
        print(f"\u2705 {_('directorio_cambiado')}: {os.getcwd()}")
        return True

    return False


def build_and_run():
    check_docker_daemon()

    if not setup_pwndoc_directory():
        print(f"\u274c {_('no_directorio')}")
        sys.exit(1)

    print(f"{_('iniciando_build')}")
    command = ["docker-compose", "up", "-d", "--build"]

    if run_command(command, check=False):
        if check_pwndoc_status(PWNDOC_PORT):
            print(f"\n\u2705 {_('orquestacion_ok')}")
            print(f"{_('orquestacion_https')}")
            print(f"{_('orquestacion_recordatorio')}")
        else:
            print(f"\n\u274c {_('orquestacion_fallo_validacion')}")
    else:
        print(f"\n\u274c {_('orquestacion_fallo_up')}")
        sys.exit(1)


def show_logs():
    print(f"{_('mostrando_logs')}: {BACKEND_SERVICE}")
    run_command(["docker-compose", "logs", "-f", BACKEND_SERVICE], check=False)


def stop_containers():
    print(f"{_('deteniendo_contenedores')}")
    run_command(["docker-compose", "stop"])

def start_containers():
    check_docker_daemon()
    print(f"{_('iniciando_contenedores')}")
    if run_command(["docker-compose", "start"]):
        check_pwndoc_status(PWNDOC_PORT)

def remove_containers():
    print(f"{_('eliminando_contenedores')}")
    run_command(["docker-compose", "down"])

def update_application():
    check_docker_daemon()

    if not os.path.exists("docker-compose.yml"):
        print(f"\n\u274c **{_('error_no_docker_compose')}**")
        print(f"\u27a1\ufe0f {_('error_para_actualizar')}")
        sys.exit(1)

    print(f"--- {_('proceso_actualizacion')} ---")

    if run_command(["docker-compose", "down"], check=False).returncode != 0:
        print(f"\u26a0\ufe0f {_('no_detener')}")

    print(f"\n{_('actualizando_codigo')}")
    result = run_command(["git", "pull"], check=False)
    if result is None or result.returncode != 0:
        print(f"\u274c {_('error_git_pull')}")
        return

    print(f"\n{_('reconstruyendo')}")
    build_and_run()
    print(f"\n*** {_('actualizacion_completada')} ***")

def main():
    global LANG
    parser = argparse.ArgumentParser(
        description=f"Orquestador en Python para la aplicacion pwndoc (multi-contenedor) con docker-compose. Acceso en https://localhost:{PWNDOC_PORT}.",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument("action", choices=[
        "up",
        "logs",
        "stop",
        "start",
        "down",
        "update"
    ], help=(
        "Acciones disponibles (Ejecutar desde el directorio del orquestador):\n"
        "  up    : Verifica Docker, CLONA/MUEVE a pwndoc, construye imagenes y valida el servicio (docker-compose up -d --build)\n"
        "  logs  : Muestra logs en tiempo real del backend.\n"
        "  stop  : Detiene los contenedores.\n"
        "  start : Verifica Docker, inicia los contenedores detenidos y valida el servicio.\n"
        "  down  : Baja y elimina contenedores/redes/volumenes por defecto.\n"
        "  update: Detiene, actualiza el codigo fuente con git pull, y vuelve a levantar (DEBE EJECUTARSE DENTRO DE LA CARPETA PWNDOC)."
    ))

    parser.add_argument(
        "--lang",
        choices=["es", "en"],
        default="es",
        help="Idioma: es (espanol) / en (english) [default: es]",
    )

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()
    LANG = args.lang

    actions = {
        "up": build_and_run,
        "logs": show_logs,
        "stop": stop_containers,
        "start": start_containers,
        "down": remove_containers,
        "update": update_application,
    }

    if args.action != 'up' and not os.path.exists("docker-compose.yml"):

        if os.path.isdir(PWNDOC_DIR_NAME):
            os.chdir(PWNDOC_DIR_NAME)
        else:
            print(f"\n\u274c **{_('error_critico_no_dir')}**")
            print(f"\u27a1\ufe0f {_('error_ejecutar_accion')}")
            sys.exit(1)

    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    actions[args.action]()


print("\n[!] AVISO LEGAL: Use solo con autorizacion. / LEGAL NOTICE: Authorized use only.\n")
if __name__ == "__main__":
    main()
