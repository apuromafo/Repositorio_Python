#!/usr/bin/python

'''
Copyright 2009, The Android Open Source Project

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
'''

import argparse
import sys
import re
import subprocess
import os
import time
from subprocess import PIPE
from datetime import datetime
from colorama import init, Fore, Style

# Inicializa colorama para manejar colores en la terminal
init(autoreset=True)

__version__ = '3.4.0'

# --- CONFIGURACIÓN Y MAPPING ---

LOG_LEVELS = 'VDIWEF'
LOG_LEVELS_MAP = {LOG_LEVELS[i]: i for i in range(len(LOG_LEVELS))}

# Nombres de archivos de salida simples, ya que la carpeta será descriptiva.
LEVEL_FILENAMES = {
    'F': 'fatal.log',
    'E': 'error.log',
    'W': 'warning.log',
    'I': 'info.log',
    'D': 'debug.log',
    'V': 'verbose.log',
}

# --- FUNCIONES DE ADB Y DISPOSITIVO ---

def run_adb_command(command, device_serial=None):
    """Ejecuta un comando adb y retorna la salida (stdout)."""
    base_command = ['adb']
    if device_serial:
        base_command.extend(['-s', device_serial])
    
    full_command = base_command + command
    try:
        process = subprocess.Popen(full_command, stdout=PIPE, stderr=PIPE)
        stdout, stderr = process.communicate()
        if process.returncode != 0 and stderr:
             # Imprime el error de adb pero no lo trata como un error fatal del script
            print(f"{Fore.RED}Error ADB: {stderr.decode().strip()}{Style.RESET_ALL}")
        return stdout.decode('utf-8', 'replace').strip()
    except FileNotFoundError:
        print(f"{Fore.RED}Error: El comando 'adb' no se encontró. Asegúrate de que está en tu PATH.{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}Error al ejecutar ADB: {e}{Style.RESET_ALL}")
        sys.exit(1)


def get_devices():
    """Obtiene una lista de dispositivos conectados, incluyendo su estado."""
    output = run_adb_command(['devices', '-l'])
    devices = []
    unauthorized_count = 0

    for line in output.splitlines():
        if not line.startswith('List of') and line.strip():
            match = re.match(r'(\S+)\s+(device|offline|unauthorized)\s*(.*)', line)
            if match:
                serial = match.group(1)
                state = match.group(2)
                attributes = match.group(3)
                
                # Se utiliza el modelo reportado por ADB para la selección inicial
                model_match = re.search(r'model:(\S+)', attributes)
                model = model_match.group(1) if model_match else 'Desconocido'
                
                devices.append({
                    'serial': serial, 
                    'state': state,
                    'model': model
                })
                
                if state == 'unauthorized':
                    unauthorized_count += 1
    
    if unauthorized_count > 0:
        print(f"{Fore.RED}ADVERTENCIA: Se detectaron {unauthorized_count} dispositivo(s) 'unauthorized'. Asegúrate de aceptar la clave RSA en el dispositivo.{Style.RESET_ALL}")

    return [d for d in devices if d['state'] == 'device'], [d for d in devices if d['state'] == 'unauthorized']


def select_device_interactive(devices):
    """Muestra un menú interactivo para seleccionar el dispositivo."""
    print(f"\n{Fore.CYAN}--- SELECCIÓN DE DISPOSITIVO ---{Style.RESET_ALL}")
    for i, d in enumerate(devices):
        print(f"{Fore.YELLOW}{i+1}{Style.RESET_ALL}: {d['serial']} (Modelo: {d['model']})")
        
    while True:
        try:
            choice = input(f"{Fore.MAGENTA}Ingresa el número del dispositivo (1-{len(devices)}): {Style.RESET_ALL}")
            idx = int(choice) - 1
            if 0 <= idx < len(devices):
                return devices[idx]['serial'], devices[idx]['model']
            else:
                print(f"{Fore.RED}Selección fuera de rango. Intenta de nuevo.{Style.RESET_ALL}")
        except ValueError:
            print(f"{Fore.RED}Entrada inválida. Debe ser un número.{Style.RESET_ALL}")
            
def select_device(desired_serial=None):
    """Selecciona un dispositivo basado en el argumento, la lista o de forma interactiva."""
    devices, unauthorized_devices = get_devices()
    
    if not devices:
        if unauthorized_devices:
            print(f"{Fore.RED}No hay dispositivos autorizados disponibles para loguear.{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}No se encontraron dispositivos conectados. Asegúrate de que ADB está habilitado y funcionando.{Style.RESET_ALL}")
        sys.exit(1)
    
    if desired_serial:
        selected = next((d for d in devices if d['serial'] == desired_serial), None)
        if selected:
            return selected['serial'], selected['model']
        else:
            print(f"{Fore.RED}Dispositivo '{desired_serial}' no encontrado o no está en estado 'device'.{Style.RESET_ALL}")
            sys.exit(1)

    if len(devices) == 1:
        return devices[0]['serial'], devices[0]['model']
    else:
        return select_device_interactive(devices)


def get_device_properties(device_serial):
    """Obtiene información detallada del dispositivo usando ADB."""
    info = {}
    props = [
        ("Android Version", "ro.build.version.release"),
        ("Architecture", "ro.product.cpu.abi"),
        ("Model", "ro.product.model"),
        ("Device Name", "ro.product.name"),
        ("Manufacturer", "ro.product.manufacturer"),
        ("SDK Level", "ro.build.version.sdk"),
    ]
    
    for key, prop in props:
        value = run_adb_command(
            ["shell", "getprop", prop],
            device_serial=device_serial
        )
        info[key] = value.strip()
    
    return info

# --- FUNCIONES DE FILTRADO Y SELECCIÓN DE PAQUETES ---

def is_valid_package_format(pkg_name):
    """
    Verifica si el string se parece a un nombre de paquete de Android válido.
    Debe contener al menos un punto ('.') y solo caracteres alfanuméricos, puntos y guiones bajos.
    """
    if pkg_name.isdigit(): # Excluye PIDs
        return False
    if '.' not in pkg_name:
        return False
    # Solo permite letras, números, puntos y guiones bajos (formato de paquete típico)
    if not re.match(r'^[a-zA-Z0-9._]+$', pkg_name):
        return False
    return True

def filtrar_aplicaciones(aplicaciones):
    """
    Filtra las aplicaciones irrelevantes (sistema, Google, AOSP, etc.) para enfocarse en las de usuario.
    Se utiliza la lista de exclusión proporcionada para ser muy específico.
    """
    # Lista de paquetes conocidos que suelen ser internos o de sistema (acortada para este script)
    lista_blanca = {
        "android.car.cluster.maserati", "com.android.apps.tag", "com.android.auto.embedded.cts.verifier", "com.android.car.carlauncher",
        "com.android.car.home", "com.android.car.retaildemo", "com.android.car.settingslib.robotests", "com.android.car.setupwizardlib.robotests",
        "com.android.cardock", "com.android.connectivity.metrics", "com.android.facelock", "com.android.google.gce.gceservice",
        "com.android.hotwordenrollment.okgoogle", "com.android.hotwordenrollment.tgoogle", "com.android.hotwordenrollment.xgoogle",
        "com.android.inputmethod.latin", "com.android.media.update", "com.android.netspeed", "com.android.onemedia",
        "com.android.pixellogger", "com.android.ramdump", "com.android.settingslib.robotests", "com.android.simappdialog",
        "com.android.statsd.dogfood", "com.android.statsd.loadtest", "com.android.systemui.shared", "com.android.test.power",
        "com.android.test.voiceenrollment", "com.android.tv.provision", "com.google.SSRestartDetector", "com.google.android.apps.nexuslauncher",
        "com.google.android.apps.wallpaper", "com.google.android.asdiv", "com.google.android.athome.globalkeyinterceptor",
        "com.google.android.car.bugreport", "com.google.android.car.defaultstoragemonitoringcompanionapp",
        "com.google.android.car.diagnosticrecorder", "com.google.android.car.diagnosticverifier", "com.google.android.car.diskwriteapp",
        "com.google.android.car.flashapp", "com.google.android.car.kitchensink", "com.google.android.car.obd2app",
        "com.google.android.car.setupwizard", "com.google.android.car.usb.aoap.host", "com.google.android.car.vms.subscriber",
        "com.google.android.carrier", "com.google.android.carriersetup", "com.google.android.connectivitymonitor",
        "com.google.android.edu.harnesssettings", "com.google.android.ext.services", "com.google.android.factoryota",
        "com.google.android.feedback", "com.google.android.gsf", "com.google.android.hardwareinfo", "com.google.android.hiddenmenu",
        "com.google.android.onetimeinitializer", "com.google.android.permissioncontroller", "com.google.android.partner.provisioning",
        "com.google.android.partnersetup", "com.google.android.pixel.setupwizard", "com.google.android.preloaded_drawable_viewer",
        "com.google.android.printservice.recommendation", "com.google.android.sampledeviceowner", "com.google.android.apps.scone",
        "com.google.android.sdksetup", "com.google.android.setupwizard", "com.google.android.storagemanager", "com.google.android.tag",
        "com.google.android.tungsten.overscan", "com.google.android.tungsten.setupwraith", "com.google.android.tv.bugreportsender",
        "com.google.android.tv.frameworkpackagestubs", "com.google.android.tv.pairedsetup", "com.google.android.vendorloggingservice",
        "com.google.android.volta", "com.google.android.wfcactivation", "com.google.mds", "com.google.modemservice",
        "com.htc.omadm.trigger", "com.qualcomm.qcrilmsgtunnel", "com.ustwo.lwp", "org.chromium.arc.accessibilityhelper",
        "org.chromium.arc.apkcacheprovider", "org.chromium.arc.applauncher", "org.chromium.arc.backup_settings",
        "org.chromium.arc.cast_receiver", "org.chromium.arc.crash_collector", "org.chromium.arc.file_system",
        "org.chromium.arc.gms", "org.chromium.arc.home", "org.chromium.arc.intent_helper", "org.telegram.messenger.web",
        "org.chromium.arc.tts"
    }
    
    aplicaciones_filtradas = [
        app for app in aplicaciones
        if not (
            app.startswith("com.google.") or
            app.startswith("com.android.") or
            app.startswith("com.breel.") or
            app.startswith("com.genymotion.") or
            app.startswith("com.example.android.") or
            app.startswith("com.amaze.") or
            app.startswith("android.ext.") or
            app.startswith("org.chromium.") or
            app.startswith("com.opengapps.") or
            app == "android" or
            "android.auto_generated_rro_product__" in app or
            app in lista_blanca
        )
    ]
    return aplicaciones_filtradas

def select_package_from_list_interactive(device_serial):
    """
    Lista las aplicaciones de usuario instaladas y permite al usuario seleccionar una por número.
    Retorna el nombre del paquete o None si el usuario elige ingresar el paquete manualmente.
    """
    print(f"\n{Fore.CYAN}--- LISTANDO APLICACIONES DE USUARIO ---{Style.RESET_ALL}")
    
    # 1. Obtener todos los paquetes
    output = run_adb_command(
        ['shell', 'pm list packages'], 
        device_serial=device_serial
    )
    # Se asegura de que la línea comience con 'package:'
    aplicaciones = [line.split(":")[1].strip() for line in output.splitlines() if line.startswith('package:')]
    
    # 2. Filtrar
    aplicaciones_filtradas = filtrar_aplicaciones(aplicaciones)
    
    if not aplicaciones_filtradas:
        print(f"{Fore.YELLOW}Advertencia: No se encontraron aplicaciones de usuario relevantes después del filtro.{Style.RESET_ALL}")
        return None

    # 3. Mostrar lista
    print(f"[+] Se encontraron {len(aplicaciones_filtradas)} aplicaciones relevantes:")
    for idx, app in enumerate(aplicaciones_filtradas, start=1):
        print(f"    {Fore.YELLOW}{idx}{Style.RESET_ALL}. {app}")

    # 4. Selección interactiva
    while True:
        try:
            choice = input(f"{Fore.MAGENTA}Ingresa el NÚMERO de la aplicación o 'M' para ingresar el paquete manualmente: {Style.RESET_ALL}").strip().upper()
            
            if choice == 'M':
                return None # Vuelve al modo de entrada manual en main()
                
            if choice.isdigit():
                idx = int(choice) - 1
                if 0 <= idx < len(aplicaciones_filtradas):
                    paquete = aplicaciones_filtradas[idx]
                    return paquete
                else:
                    print(f"{Fore.RED}Selección fuera de rango. Intenta de nuevo.{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}Entrada inválida. Ingresa el número o 'M'.{Style.RESET_ALL}")
        except KeyboardInterrupt:
            # Re-lanza la interrupción para que el manejador principal la capture
            raise 

# --- VISUALIZACIÓN Y FORMATO ---

def colorize(level, text):
    """Aplica color al mensaje de log según su nivel."""
    if level in ['F', 'E']:
        return f"{Fore.RED}{Style.BRIGHT}{text}{Style.RESET_ALL}"
    elif level == 'W':
        return f"{Fore.YELLOW}{text}{Style.RESET_ALL}"
    elif level == 'I':
        return f"{Fore.GREEN}{text}{Style.RESET_ALL}"
    elif level == 'D':
        return f"{Fore.BLUE}{text}{Style.RESET_ALL}"
    else: # V
        return f"{Fore.WHITE}{Style.DIM}{text}{Style.RESET_ALL}"

def format_log_line(level, tag, owner, message, relative_time, line_count, tag_width):
    """Formatea la línea para la salida en consola, incluyendo el contador de líneas."""
    
    colored_message = colorize(level, message)
    formatted_tag = f"{tag[:tag_width]:<{tag_width}}"
    
    output_line = (
        f"[{Fore.BLUE}{line_count:<6}{Style.RESET_ALL}]"
        f"[{Fore.CYAN}{relative_time:<10}{Style.RESET_ALL}] "
        f"{level}/"                                             
        f"{Fore.MAGENTA}{formatted_tag}{Style.RESET_ALL} "      
        f"({owner}): "                                          
        f"{colored_message}"                                    
    )
    return output_line

# --- PROGRAMA PRINCIPAL ---

def main():
    # --- 1. Argumentos (SOLO paquete y dispositivo) ---
    parser = argparse.ArgumentParser(description='Filtra logcat por un paquete específico o la app en primer plano, con ajustes predeterminados para auditoría.')
    
    # Único argumento posicional opcional (el paquete)
    parser.add_argument('package', nargs='?', default=None, help='Nombre del paquete de la aplicación a filtrar (opcional). Por defecto, usa la app actual.')
    
    # Argumento de dispositivo (necesario para entornos multidevice)
    parser.add_argument('-d', '--device', dest='device_serial', type=str, help='Número de serie del dispositivo ADB a usar.')
    
    global args
    args = parser.parse_args()

    # --- 2. DEFAULTS HARDCODED para Auditoría y Usabilidad ---
    DEFAULT_MIN_LEVEL = 'I'  # Info, Warning, Error, Fatal
    DEFAULT_TAG_WIDTH = 23
    
    min_level_index = LOG_LEVELS_MAP[DEFAULT_MIN_LEVEL]
    tag_width = DEFAULT_TAG_WIDTH

    target_packages = [args.package.strip()] if args.package else []
    start_time = datetime.now()
    line_counter = 0

    # Determinar si estamos en modo "App Actual" (solo si no se pasó el argumento 'package')
    current_app_mode = not bool(args.package)
    running_package_name = None
    
    # Seleccionar dispositivo y obtener propiedades detalladas
    device_serial, device_model_short = select_device(args.device_serial)
    device_properties = get_device_properties(device_serial)
    android_version = device_properties.get("Android Version", "Desconocido")
    
    print(f"\n{Fore.GREEN}Dispositivo Seleccionado: {device_model_short} (Android {android_version}){Style.RESET_ALL}")
    
    # Mostrar información adicional del dispositivo
    print(f"{Fore.CYAN}--- INFO DETALLADA DEL DISPOSITIVO ---{Style.RESET_ALL}")
    for key, value in device_properties.items():
        print(f"  - {key}: {value}")
    print("----------------------------------------")
    
    # --- 3. Obtener Paquete de la App Actual (si se necesita) o Pedirlo al Usuario ---
    if current_app_mode:
        print(f"{Fore.YELLOW}Buscando aplicación actual... (Modo por defecto){Style.RESET_ALL}")
        system_dump = run_adb_command(
            ["shell", "dumpsys", "activity", "activities"], 
            device_serial=device_serial
        )
        match = re.search(r"mResumedActivity: [^ ]* ([^ ^}]*)/", system_dump)
        
        if match:
            running_package_name = match.group(1).split('/')[0] 
            target_packages.append(running_package_name)
            print(f"{Fore.GREEN}Filtro: Agregado paquete de la app actual: {running_package_name}{Style.RESET_ALL}")
        else:
            # La detección automática falló. Dar opciones al usuario.
            print(f"{Fore.RED}ADVERTENCIA: No se pudo determinar el paquete de la app actual automáticamente.{Style.RESET_ALL}")
            
            # Opción 1: Seleccionar de la lista filtrada
            selected_package = select_package_from_list_interactive(device_serial)
            
            if selected_package:
                running_package_name = selected_package
                target_packages.append(running_package_name)
                print(f"{Fore.GREEN}Filtro: Usando el paquete seleccionado de la lista: {running_package_name}{Style.RESET_ALL}")
            else:
                # Opción 2: Entrada manual (incluye validación)
                while not running_package_name:
                    user_input = input(f"{Fore.MAGENTA}Ingresa el nombre exacto del paquete de la app a auditar (Ej: com.ejemplo.app): {Style.RESET_ALL}").strip()
                    
                    # Saneamiento y validación estricta de la entrada
                    if not user_input:
                        print(f"{Fore.RED}El nombre del paquete no puede estar vacío. Intenta de nuevo.{Style.RESET_ALL}")
                    
                    elif not is_valid_package_format(user_input):
                        print(f"{Fore.RED}El formato del paquete '{user_input}' parece inválido (debe contener '.' y ser alfanumérico). Intenta de nuevo.{Style.RESET_ALL}")
                    
                    else:
                        running_package_name = user_input
                        target_packages.append(running_package_name)
                        print(f"{Fore.GREEN}Filtro: Usando el paquete proporcionado manualmente: {running_package_name}{Style.RESET_ALL}")

    # --- 4. Configuración de Directorio de Salida Amigable ---
    
    if running_package_name:
        package_base = running_package_name
    elif target_packages:
        package_base = target_packages[0] if len(target_packages) == 1 else "multi_packages"
    else:
        package_base = "device_wide_unfiltered"

    timestamp_str = start_time.strftime('%Y%m%d_%H%M%S')
    
    # Limpieza de caracteres no válidos para el nombre del directorio
    clean_model = re.sub(r'[^a-zA-Z0-9_]', '_', device_properties.get("Model", "Desconocido"))
    clean_version = re.sub(r'[^a-zA-Z0-9_]', '_', android_version)
    clean_package = re.sub(r'[^a-zA-Z0-9_.]', '_', package_base) # Permite el punto en el nombre base

    output_dir_name = (
        f"{clean_package.replace('.', '-')}_"
        f"{clean_model}_"
        f"(Android_V{clean_version})_"
        f"{timestamp_str}"
    )
    
    base_log_dir = 'log_sessions'
    final_output_dir = os.path.join(base_log_dir, output_dir_name)

    os.makedirs(final_output_dir, exist_ok=True)
    file_handles = {}
    
    # 4c. Abrir archivos de salida categorizados
    print(f"\n{Fore.CYAN}--- ARCHIVOS DE SALIDA ---{Style.RESET_ALL}")
    for level, filename in LEVEL_FILENAMES.items():
        filepath = os.path.join(final_output_dir, filename)
        file_handles[level] = open(filepath, 'w', encoding='utf-8', buffering=1)
        print(f"  - Logs de nivel {level} se guardarán en: {filepath}")

    if not target_packages:
        print(f"{Fore.CYAN}Modo Sin Filtro: Mostrando log de TODO el dispositivo (Nivel: {DEFAULT_MIN_LEVEL}+).{Style.RESET_ALL}")
    else:
        print(f"{Fore.CYAN}Paquete(s) filtrando: {', '.join(target_packages)} (Nivel: {DEFAULT_MIN_LEVEL}+){Style.RESET_ALL}")

    # --- 5. Ejecución de Logcat ---
    
    # Se limpia el buffer de logcat antes de empezar
    run_adb_command(['logcat', '-c'], device_serial=device_serial)
    
    adb = subprocess.Popen(
        ['adb', '-s', device_serial, 'logcat', '-v', 'brief'], 
        stdout=PIPE, 
        stderr=PIPE
    )

    print(f"\n{Fore.CYAN}--- INICIANDO SESIÓN DE LOGCAT ---{Style.RESET_ALL}")
    print(f"Directorio de sesión: {Fore.YELLOW}{final_output_dir}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Presiona Ctrl+C para detener y guardar.{Style.RESET_ALL}\n")

    try:
        # Bucle principal de lectura de logs
        while adb.poll() is None:
            line = adb.stdout.readline().decode('utf-8', 'replace').strip()
            if not line:
                continue

            # Patrón de logcat -v brief: [Nivel]/[Tag]( [PID]): [Mensaje]
            log_line_match = re.match(r'^([A-Z])/(.+?)\( *(\d+)\): (.*?)$', line)
            
            if log_line_match:
                level, tag, owner, message = log_line_match.groups()
                
                # Chequeo 1: Nivel mínimo
                if LOG_LEVELS_MAP[level] < min_level_index:
                    continue

                # Chequeo 2: Filtro por paquete (basado en Tag o Mensaje)
                is_target_package_log = False
                if target_packages:
                    # Intenta inferir el paquete desde el TAG o el Mensaje
                    for pkg in target_packages:
                        if pkg in tag or pkg in message:
                            is_target_package_log = True
                            break
                    if not is_target_package_log:
                        continue 
                
                line_counter += 1
                # --- Generación de Tiempo Relativo ---
                time_delta = datetime.now() - start_time
                relative_time_str = f"{time_delta.total_seconds():.3f}s" 

                # --- 6. Salida Consola y Categorizada ---
                
                # 6a. Salida en Consola (con colores y contador)
                console_output_line = format_log_line(level, tag, owner, message, relative_time_str, line_counter, tag_width)
                sys.stdout.write(console_output_line + '\r')
                sys.stdout.flush()
                
                # 6b. Salida a Archivos Categorizados (sin colores)
                flat_line = f"[{start_time.strftime('%H:%M:%S.%f')[:-3]} +{relative_time_str:<10}] {level}/{tag:<{tag_width}} ({owner}): {message}\n"
                
                if level in file_handles:
                    file_handles[level].write(flat_line)
                
                if level == 'F' and 'E' in file_handles:
                    file_handles['E'].write(flat_line) 

    except KeyboardInterrupt:
        # Manejo de Ctrl+C (salida amigable)
        print(f"\n{Fore.CYAN}--- LOGCAT DETENIDO ({line_counter} líneas procesadas) ---{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}Ocurrió un error inesperado: {e}{Style.RESET_ALL}")
    finally:
        # Cierra todos los archivos y termina el proceso ADB
        for handle in file_handles.values():
            handle.close()
        
        if adb.poll() is None:
            adb.terminate()

        print(f"{Fore.GREEN}Sesión finalizada. Logs guardados de forma segura en: {final_output_dir}{Style.RESET_ALL}")
        
if __name__ == '__main__':
    main()
