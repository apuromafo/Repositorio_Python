import subprocess
import argparse
import sys
import time
import requests
import os
import shutil

# --- Constantes de Configuración ---
PWNDOC_PORT = 8443
BACKEND_SERVICE = "pwndoc-backend"
TIMEOUT_SECONDS = 180
INITIAL_WAIT = 20 # Pausa inicial después de levantar los contenedores
PWNDOC_REPO_URL = "https://github.com/pwndoc/pwndoc.git"
PWNDOC_DIR_NAME = "pwndoc" # Nombre de la carpeta que crea git clone

# --- Funciones Auxiliares Comunes ---

def run_command(command, check=True):
    """
    Ejecuta un comando en el shell y maneja la salida y los errores.
    
    Args:
        command (list): Lista de cadenas que representan el comando a ejecutar.
        check (bool): Si es True, lanza un error si el comando falla.
    """
    command_str = " ".join(command)
    # Excluir logs de la impresión inicial para comandos interactivos
    if command[0] != "docker-compose" or command[1] != "logs":
        print(f"\n--- Ejecutando: {command_str} ---")
        
    try:
        # Usamos check=True para que lance CalledProcessError si el comando falla
        # capture_output se usa para capturar logs/errores si no es un proceso interactivo
        result = subprocess.run(
            command, 
            check=check, 
            text=True, 
            capture_output=(command[0] != "docker-compose" or command[1] != "logs"),
            timeout=300 # Aumentado el timeout para que la clonación/build tenga tiempo
        )
        
        # Si capturamos la salida, la imprimimos
        if result.stdout and (command[0] != "docker-compose" or command[1] != "logs"):
            print(result.stdout)
        
        # Si hubo un error no fatal o advertencia
        if result.stderr and check and (command[0] != "docker-compose" or command[1] != "logs"):
             print(f"Advertencias/Salida de error (no fatal): {result.stderr}")
             
        return result

    except subprocess.CalledProcessError as e:
        print(f"\n!!! ERROR al ejecutar el comando: {command_str} !!!")
        print(f"Salida de error:\n{e.stderr}")
        print("💡 Tip: Asegúrate de estar en el directorio raíz de pwndoc donde se encuentra docker-compose.yml.")
        sys.exit(1)
    except FileNotFoundError:
        # Captura errores de "comando no encontrado"
        if command[0] in ["docker-compose", "git"]:
            print(f"\n!!! ERROR: {command[0]} no se encontró. Asegúrate de que esté instalado y en tu PATH. !!!")
        else:
            print(f"\n!!! ERROR: Comando no encontrado: {command[0]} !!!")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nOperación interrumpida por el usuario.")
        sys.exit(1)
    except subprocess.TimeoutExpired:
        print(f"\n!!! ERROR: El comando {command_str} ha excedido el tiempo de ejecución (300s). !!!")
        sys.exit(1)
    return None

def check_docker_daemon():
    """Verifica si Docker está accesible antes de empezar."""
    print("🔎 Verificando el estado del Docker Daemon...")
    try:
        subprocess.run(
            ["docker", "info"], 
            check=True, 
            text=True, 
            capture_output=True,
            timeout=10
        )
        print("✅ Docker Daemon está accesible.")
        return True
    except subprocess.CalledProcessError as e:
        print("❌ **¡ERROR CRÍTICO!** Fallo de conexión al Docker Daemon.")
        if "error during connect" in e.stderr.lower() or "connection refused" in e.stderr.lower():
            print("➡️ Por favor, inicia **Docker Desktop** o el **servicio Docker** y vuelve a intentarlo.")
        else:
             print(f"Detalle del error:\n{e.stderr}")
        sys.exit(1)
    except subprocess.TimeoutExpired:
        print("❌ **¡ERROR CRÍTICO!** La verificación del Docker Daemon agotó el tiempo de espera.")
        sys.exit(1)
    except Exception as e:
        print(f"❌ ERROR Inesperado durante la verificación del Daemon: {e}")
        sys.exit(1)
        
def check_pwndoc_status(port):
    """Verifica si el servicio web de Pwndoc está respondiendo."""
    service_url = f"https://localhost:{port}"
    start_time = time.time()
    print(f"\n🕵️ Esperando a que el servicio Pwndoc esté listo en {service_url}...")
    
    # Pausa inicial para dar tiempo a la base de datos/backend a iniciarse
    print(f"   (Pausa inicial de {INITIAL_WAIT} segundos para la inicialización)", end="", flush=True)
    time.sleep(INITIAL_WAIT)
    print("... Continuar verificación.")
    
    while time.time() - start_time < TIMEOUT_SECONDS:
        try:
            # Deshabilitamos la verificación de SSL ya que usa un certificado autofirmado por defecto
            response = requests.get(service_url, verify=False, timeout=10) 
            
            # Pwndoc debería devolver un 200 para la página de login
            if response.status_code == 200 and "pwndoc" in response.text.lower():
                print("\n🎉 **¡Servicio Pwndoc OK!** El sitio web principal respondió correctamente.")
                print(f"🌐 Accede a Pwndoc en tu navegador en: **{service_url}**")
                return True

            print(f"|", end="", flush=True) # Mostrar progreso
            time.sleep(5)

        except requests.exceptions.ConnectionError:
            print(".", end="", flush=True) # Mostrar progreso
            time.sleep(5)
        except requests.exceptions.Timeout:
            print("T", end="", flush=True) # Mostrar progreso por timeout
            time.sleep(10)
        except requests.exceptions.RequestException as e:
            # Evitar imprimir errores de SSL aquí, ya que el certificado es autofirmado
            if "certificate verify failed" not in str(e):
                 print(f"E", end="", flush=True) # Mostrar progreso por error de request
            else:
                 print("S", end="", flush=True) # SSL error (esperado)
            time.sleep(5)
            
    print(f"\n❌ **¡ERROR!** El servicio Pwndoc no estuvo disponible en {TIMEOUT_SECONDS} segundos.")
    return False

def setup_pwndoc_directory():
    """Clona el repositorio si no existe la carpeta 'pwndoc'."""
    # 1. Comprobar si ya estamos en un directorio pwndoc (donde está docker-compose.yml)
    if os.path.exists("docker-compose.yml"):
        return True # Ya estamos en el lugar correcto

    # 2. Si no estamos allí, comprobar si la carpeta pwndoc ya existe en el directorio actual
    if not os.path.isdir(PWNDOC_DIR_NAME):
        print(f"\n⚠️ El archivo 'docker-compose.yml' no se encuentra en el directorio actual.")
        print(f"⬇️ Clonando el repositorio de pwndoc en la carpeta '{PWNDOC_DIR_NAME}'...")
        
        # Clonar el repositorio
        run_command(["git", "clone", PWNDOC_REPO_URL, PWNDOC_DIR_NAME])
        
        # Mover al nuevo directorio
        os.chdir(PWNDOC_DIR_NAME)
        print(f"✅ Se ha cambiado el directorio de trabajo a: {os.getcwd()}")
        return True
    
    # 3. Si la carpeta existe, mover a ella
    else:
        print(f"\n➡️ Se encontró la carpeta '{PWNDOC_DIR_NAME}'. Cambiando el directorio de trabajo.")
        os.chdir(PWNDOC_DIR_NAME)
        print(f"✅ Se ha cambiado el directorio de trabajo a: {os.getcwd()}")
        return True
    
    return False # En caso de error inesperado
    
# --- Funciones de Orquestación ---

def build_and_run():
    """Configura el directorio, construye y levanta los contenedores y verifica el estado."""
    check_docker_daemon()
    
    # Paso Cero: Asegurar que estamos en el directorio correcto
    if not setup_pwndoc_directory():
        print("❌ No se pudo configurar el directorio de pwndoc. Abortando.")
        sys.exit(1)
        
    print("Iniciando: Construyendo imágenes y levantando contenedores (en segundo plano)...")
    command = ["docker-compose", "up", "-d", "--build"]
    
    if run_command(command, check=False):
        # La verificación es crítica, no solo la ejecución del comando
        if check_pwndoc_status(PWNDOC_PORT):
             print("\n✅ Proceso de Orquestación Finalizado con Éxito.")
             print("Aviso: El acceso es HTTPS (https://localhost:8443).")
             print("Recordatorio: Debes cambiar los certificados SSL y el secreto JWT para producción.")
        else:
             print("\n❌ La validación del servicio Pwndoc falló después de levantarse. Ver logs con 'logs'.")
             # No forzamos la salida aquí, ya que el usuario podría querer debuggear con los contenedores arriba
    else:
        print("\n❌ El comando 'docker-compose up' falló. Revisa los logs de error anteriores.")
        sys.exit(1)


def show_logs():
    """Muestra los logs del servicio de backend de pwndoc."""
    # La acción de logs NO necesita que se haya levantado el contenedor primero.
    print(f"Mostrando logs en tiempo real para el servicio: {BACKEND_SERVICE}")
    # Nota: run_command está configurado para no capturar la salida de logs en tiempo real
    run_command(["docker-compose", "logs", "-f", BACKEND_SERVICE], check=False)


def stop_containers():
    """Detiene los contenedores."""
    print("Deteniendo contenedores de pwndoc...")
    run_command(["docker-compose", "stop"])

def start_containers():
    """Inicia los contenedores previamente detenidos y verifica el estado."""
    check_docker_daemon()
    print("Iniciando contenedores de pwndoc...")
    if run_command(["docker-compose", "start"]):
         check_pwndoc_status(PWNDOC_PORT)

def remove_containers():
    """Baja y elimina los contenedores, redes y volúmenes por defecto."""
    print("Eliminando contenedores, redes y volúmenes de pwndoc...")
    run_command(["docker-compose", "down"])

def update_application():
    """Detiene, actualiza el código via git pull, y reconstruye/levanta la aplicación."""
    check_docker_daemon()
    
    # Si no estamos en el directorio de pwndoc, no podemos hacer git pull
    if not os.path.exists("docker-compose.yml"):
        print("\n❌ **ERROR CRÍTICO:** No se encontró 'docker-compose.yml'.")
        print("➡️ Para actualizar, debes ejecutar este script DENTRO de la carpeta 'pwndoc'. Abortando.")
        sys.exit(1)
        
    print("--- Proceso de Actualización de pwndoc ---")
    
    # 1. Detener
    if run_command(["docker-compose", "down"], check=False).returncode != 0:
        print("⚠️ No se pudo detener completamente la aplicación (puede que no estuviera corriendo), continuando...")
        
    # 2. Pull
    print("\nActualizando código fuente con git pull...")
    # Ejecutar pull
    result = run_command(["git", "pull"], check=False)
    if result is None or result.returncode != 0:
        print("❌ No se pudo realizar el git pull. Abortando actualización.")
        return
        
    # 3. Reconstruir y levantar
    print("\nReconstruyendo y levantando la aplicación con el nuevo código...")
    build_and_run()
    print("\n*** ¡Actualización de pwndoc completada! ***")
    
def main():
    parser = argparse.ArgumentParser(
        description=f"Orquestador en Python para la aplicación pwndoc (multi-contenedor) con docker-compose. Acceso en https://localhost:{PWNDOC_PORT}.",
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
        "  up    : Verifica Docker, CLONA/MUEVE a pwndoc, construye imágenes y valida el servicio (docker-compose up -d --build)\n"
        "  logs  : Muestra logs en tiempo real del backend.\n"
        "  stop  : Detiene los contenedores.\n"
        "  start : Verifica Docker, inicia los contenedores detenidos y valida el servicio.\n"
        "  down  : Baja y elimina contenedores/redes/volúmenes por defecto.\n"
        "  update: Detiene, actualiza el código fuente con git pull, y vuelve a levantar (DEBE EJECUTARSE DENTRO DE LA CARPETA PWNDOC)."
    ))
    
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()
    
    # Mapeo de acciones a funciones
    actions = {
        "up": build_and_run,
        "logs": show_logs,
        "stop": stop_containers,
        "start": start_containers,
        "down": remove_containers,
        "update": update_application,
    }
    
    
    # Las acciones 'logs', 'stop', 'start', 'down', 'update' necesitan docker-compose.yml
    # Si no lo encuentran, notifican el error y salen.
    # Solo 'up' tiene la lógica para clonar/cambiar de directorio.
    if args.action != 'up' and not os.path.exists("docker-compose.yml"):
        
        # Para las acciones que dependen de docker-compose, verificamos si existe la carpeta pwndoc y cambiamos si es necesario
        if os.path.isdir(PWNDOC_DIR_NAME):
            os.chdir(PWNDOC_DIR_NAME)
        else:
            print("\n❌ **ERROR CRÍTICO:** No se encontró el archivo 'docker-compose.yml' y tampoco la carpeta 'pwndoc'.")
            print("➡️ Para ejecutar esta acción, debes estar dentro del directorio 'pwndoc' o ejecutar 'up' primero.")
            sys.exit(1)
            

    # Suprimimos los warnings de SSL por defecto de requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    actions[args.action]()

if __name__ == "__main__":
    main()