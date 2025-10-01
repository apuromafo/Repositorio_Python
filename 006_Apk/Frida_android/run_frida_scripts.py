#--------------------------------------------------------------------------------------
# Nombre del Script: Frida Script Runner
# Versión: 1.9.9
# Descripción:
#   Automatiza la ejecución de scripts de Frida en un dispositivo.
#   Ofrece funcionalidades avanzadas como la selección de dispositivos,
#   la obtención de información del sistema, gestión de logs y la configuración
#   personalizada de la carpeta de scripts.
#--------------------------------------------------------------------------------------
# ==============================================================================
# --- HISTORIAL DE VERSIONES ---
# ==============================================================================
# v1.0.0 (2025-09-10) - [INICIO]
#   ✅ Funcionalidad básica de ejecución de scripts.
# v1.1.0 (2025-09-10) - [ACTUALIZACIÓN]
#   ✅ Agregado sistema de logging configurable.
# v1.1.1 (2025-09-11) - [MEJORA DE CONTROL DE ERRORES]
#   ✅ Corrección de la lógica de rutas.
# v1.2.0 (2025-09-11) - [MEJORA DE SELECCIÓN DE DISPOSITIVOS]
#   ✅ Introducción de una función para listar y seleccionar dispositivos.
# v1.3.0 (2025-09-11) - [MEJORA DE INFORMACIÓN DEL SISTEMA]
#   ✅ Agregada la funcionalidad para obtener la plataforma y arquitectura del dispositivo.
# v1.4.0 (2025-09-11) - [MEJORA DE USABILIDAD]
#   ✅ Implementado el manejo amigable de la interrupción por teclado (Ctrl+C).
# v1.5.0 (2025-09-11) - [MEJORA DE CONFIGURACIÓN Y ESTRUCTURA]
#   ✅ El usuario puede configurar el nombre de la carpeta de scripts en 'config.json'.
# v1.6.0 (2025-09-11) - [CORRECCIÓN DE ERRORES Y MEJORA DE UX]
#   ✅ Manejo más robusto del error "Failed to spawn".
# v1.7.0 (2025-09-11) - [INFORMACIÓN DETALLADA DEL DISPOSITIVO]
#   ✅ Integrada la lógica para obtener información detallada del dispositivo a través de ADB.
# v1.7.1 (2025-09-11) - [MEJORA EN EL MANEJO DE SEÑALES]
#   ✅ Implementación completa y robusta del manejo de Ctrl+C para una salida limpia.
# v1.7.2 (2025-09-11) - [REFINAMIENTO DE LA GESTIÓN DE INTERRUPCIONES]
#   ✅ Integración de `try/except KeyboardInterrupt` en los bucles de entrada del usuario
#      para garantizar una salida limpia y consistente en todas las etapas.
# v1.7.3 (2025-09-11) - [CORRECCIÓN DE MANEJO DE ERRORES]
#   ✅ Corrección del error 'AttributeError: 'NoneType' object has no attribute 'decode''
#      al capturar la salida de errores de 'frida' que no existe.
# v1.7.4 (2025-09-11) - [REFINAMIENTO DE MANEJO DE ERRORES]
#   ✅ Mejora en la captura y visualización del mensaje de error real de Frida
#      cuando el proceso falla con un código de salida no cero.
# v1.7.5 (2025-09-11) - [MEJORA EN LA EXPERIENCIA DE USUARIO Y REVISIÓN DE CÓDIGO]
#   ✅ Elimina el mensaje de error genérico cuando la salida de error de Frida es nula.
# v1.8.0 (2025-09-11) - [SOLUCIÓN ROBUSTA AL 'FAILED TO SPAWN']
#   ✅ Se reincorpora la función `get_device_info`.
#   ✅ Se agrega una lógica de reintento para ofrecer la opción de "attach" cuando el modo "spawn" falla.
# v1.9.0 (2025-09-11) - [CORRECCIÓN CRÍTICA DE SINTAXIS Y MEJORAS GENERALES]
#   ✅ Se corrige el uso del flag de dispositivo de '-U' a '-D' para una compatibilidad
#      correcta con el comando 'frida'.
# v1.9.1 (2025-09-11) - [CORRECCIÓN DE FLAG INEXISTENTE]
#   ✅ Se elimina el flag `--no-pause` que no existe en la documentación de Frida.
# v1.9.2 (2025-09-11) - [MANEJO DE SALIDA CON COLORES Y UNICODE]
#   ✅ Se modifica la función de ejecución para manejar la salida como un flujo de bytes,
#      preservando así los códigos de color ANSI y los caracteres Unicode.
# v1.9.3 (2025-09-11) - [CORRECCIÓN DE UNICODE Y FORMATO]
#   ✅ Se modifica la lógica de impresión para decodificar explícitamente la salida
#      de bytes a una cadena de texto (UTF-8) y luego imprimirla. Esto garantiza
#      que los caracteres Unicode como '✅' se muestren correctamente, ya que
#      muchas herramientas envían la representación de texto 'u2705'.
# v1.9.4 (2025-09-11) - [REINTEGRACIÓN DE MANEJO DE BYTES]
#   ✅ Se revierte la decodificación explícita de texto en la salida. Ahora se
#      escriben los bytes sin procesar directamente en el buffer de la salida estándar.
#      Esto permite que la terminal nativa maneje la decodificación de caracteres
#      Unicode y los códigos de color, solucionando el problema del 'u2705'.
# v1.9.5 (2025-09-11) - [SELECCIÓN INICIAL DE MODO DE EJECUCIÓN]
#   ✅ Se agrega una nueva función para que el usuario pueda elegir entre el modo
#      'spawn' (ejecutar la app) o 'attach' (adjuntar a una app en ejecución) al inicio.
# v1.9.6 (2025-09-11) - [SOLUCIÓN DEFINITIVA A LA SALIDA DE UNICODE Y COLORES]
#   ✅ Se vuelve a la decodificación explícita de la salida del subproceso, pero
#      se configura `universal_newlines=True` y `encoding='utf-8'` para que Python
#      se encargue de la codificación de forma robusta, resolviendo los problemas
#      de compatibilidad con la terminal de Windows.
# v1.9.7 (2025-09-11) - [SOPORTE DE COLORES ANSI EN WINDOWS]
#   ✅ Se añade `os.system("")` para forzar la activación de colores ANSI en terminales compatibles de Windows.
# v1.9.8 (2025-09-11) - [CORRECCIÓN DE FLAG EN MODO 'ATTACH']
#   ✅ Se corrige la función `ejecutar_script_frida` para usar el flag `-f` en el modo 'attach' en lugar de `-n` para adjuntarse por identificador de paquete.
# v1.9.9 (2025-09-11) - [SOLUCIÓN DEFINITIVA DE VISUALIZACIÓN DE EMOJIS]
#   ✅ Se implementa una función para convertir secuencias de escape Unicode literales como `\u2705` a sus caracteres reales.

# ==============================================================================

import os
import subprocess
import sys
import json
import signal
import re

VERSION = "1.9.9"
CONFIG_FILE = r"config\config_run_frida_scripts.json"
LOG_FILE = "frida_runner.log"
global ENABLE_LOGS
global SCRIPTS_FOLDER

# ==============================================================================
# --- SECCIÓN 1: CONFIGURACIÓN Y UTILIDADES BÁSICAS ---
# ==============================================================================

def enable_ansi_colors():
    """
    Habilita el soporte para colores ANSI en terminales de Windows.
    """
    if sys.platform == "win32":
        os.system("")

def load_config():
    # Asegura que la carpeta de configuración exista
    if not os.path.exists("config"):
        os.makedirs("config")
    
    # Asegura que la carpeta de configuración exista
    if not os.path.exists("config"):
        os.makedirs("config")
    
    """
    Carga la configuración desde un archivo JSON o crea uno por defecto.
    """
    global ENABLE_LOGS, SCRIPTS_FOLDER
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                config = json.load(f)
                ENABLE_LOGS = config.get("enable_logs", False)
                SCRIPTS_FOLDER = config.get("scripts_folder", "scripts")
                return config
        except json.JSONDecodeError:
            print("❌ Error: Archivo de configuración corrupto. Creando uno nuevo.")
            config = {"enable_logs": False, "scripts_folder": "scripts"}
            save_config(config)
            ENABLE_LOGS = False
            SCRIPTS_FOLDER = "scripts"
            return config
    else:
        config = {"enable_logs": False, "scripts_folder": "scripts"}
        save_config(config)
        ENABLE_LOGS = False
        SCRIPTS_FOLDER = "scripts"
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
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{os.path.basename(sys.argv[0])}] {message}\n")

def handle_interrupt(signum, frame):
    """
    Maneja la interrupción por teclado (Ctrl+C).
    """
    print("\n[!] Interrupción detectada. Saliendo del programa...")
    log("Interrupción por Ctrl+C detectada. Saliendo.")
    sys.exit(0)

def show_options_menu():
    """
    Muestra un menú de opciones de configuración al inicio del script.
    """
    global ENABLE_LOGS
    print("\n--- Opciones del Script ---")
    print(f"Versión: {VERSION}")
    print(f"1. Continuar con la ejecución")
    print(f"2. Toggle Logging (Actual: {'Activado' if ENABLE_LOGS else 'Desactivado'})")
    print(f"3. Salir")
    print("----------------------------")
    while True:
        try:
            opcion = input("[?] Selecciona una opción: ").strip()
            if opcion == '1':
                return True
            elif opcion == '2':
                config = load_config()
                config["enable_logs"] = not config["enable_logs"]
                save_config(config)
                ENABLE_LOGS = config["enable_logs"]
                print(f"Logging ahora está: {'Activado' if ENABLE_LOGS else 'Desactivado'}")
                log(f"Logging toggled to {'on' if ENABLE_LOGS else 'off'}")
                return show_options_menu()
            elif opcion == '3':
                return False
            else:
                print("[-] Opción no válida. Inténtalo de nuevo.")
        except KeyboardInterrupt:
            handle_interrupt(None, None)

# ==============================================================================
# --- SECCIÓN 2: LÓGICA DE DETECCIÓN Y SELECCIÓN ---
# ==============================================================================

def verificar_frida_instalado():
    """Verifica si Frida está instalado en el sistema."""
    log("Verificando si Frida está instalado...")
    try:
        resultado = subprocess.run(['frida', '--version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if resultado.returncode == 0:
            print(f"[+] Frida está instalado. Versión: {resultado.stdout.strip()}")
            log(f"Frida instalado. Versión: {resultado.stdout.strip()}")
            return True
        else:
            print("[-] Frida no está instalado o no se encuentra en el PATH.")
            log("Frida no está instalado o no se encuentra en el PATH.")
            return False
    except Exception as e:
        print(f"[-] Error al verificar Frida: {e}")
        log(f"Error al verificar Frida: {e}")
        return False

def is_usb_device(device_id):
    """
    Determina si un dispositivo es un dispositivo USB.
    """
    # Simple heurística: los emuladores suelen tener un nombre con "emulator"
    # y los dispositivos USB suelen ser un hash alfanumérico.
    # Esta función puede necesitar ser más robusta para otros casos.
    return not "emulator" in device_id and re.match(r'^[a-f0-9]+$', device_id)

def listar_dispositivos():
    """Lista los dispositivos Android conectados y permite al usuario seleccionar uno."""
    log("Listando dispositivos Android...")
    try:
        resultado = subprocess.run(['adb', 'devices'], stdout=subprocess.PIPE, text=True)
        lineas = resultado.stdout.strip().split('\n')
        dispositivos = [line.split('\t')[0] for line in lineas[1:] if 'device' in line and line.strip() != '']
        
        if not dispositivos:
            print("[-] No se encontraron dispositivos conectados.")
            log("No se encontraron dispositivos conectados.")
            return None
        
        print("\n--- Dispositivos Conectados ---")
        for idx, dev in enumerate(dispositivos, start=1):
            flag = "-U" if is_usb_device(dev) else "-D"
            print(f"    {idx}. {dev} ({flag})")
        print("-------------------------------")
        
        while True:
            try:
                seleccion = input("[?] Ingresa el número del dispositivo a utilizar: ").strip()
                if not seleccion.isdigit() or int(seleccion) < 1 or int(seleccion) > len(dispositivos):
                    print("[-] Selección inválida. Inténtalo nuevamente.")
                    continue
                
                dispositivo_seleccionado = dispositivos[int(seleccion) - 1]
                log(f"Dispositivo seleccionado: {dispositivo_seleccionado}")
                return dispositivo_seleccionado
            except KeyboardInterrupt:
                handle_interrupt(None, None)

    except (FileNotFoundError, subprocess.CalledProcessError) as e:
        print(f"[-] Error al listar dispositivos. Asegúrate de que 'adb' esté en tu PATH: {e}")
        log(f"Error al listar dispositivos: {e}")
        return None

def verificar_frida_server_activo(dispositivo):
    """Verifica si frida-server está en ejecución en el dispositivo."""
    log(f"Verificando si frida-server está activo en {dispositivo}...")
    try:
        resultado = subprocess.run(
            ['adb', '-s', dispositivo, 'shell', 'ps | grep frida-server'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        if "frida-server" in resultado.stdout:
            print(f"[+] frida-server está en ejecución en el dispositivo ({dispositivo}).")
            log(f"frida-server en ejecución en {dispositivo}.")
            return True
        else:
            print(f"[-] frida-server no está en ejecución en el dispositivo ({dispositivo}).")
            log(f"frida-server no está en ejecución en {dispositivo}.")
            return False
    except Exception as e:
        print(f"[-] Error al verificar si frida-server está en ejecución en el dispositivo ({dispositivo}): {e}")
        log(f"Error al verificar frida-server: {e}")
        return False

def get_device_info(device_id):
    """Obtiene información detallada del dispositivo usando ADB."""
    log(f"Recopilando información detallada del dispositivo {device_id}...")
    info = {}
    try:
        info["Android Version"] = subprocess.run(["adb", "-s", device_id, "shell", "getprop", "ro.build.version.release"], capture_output=True, text=True, check=True).stdout.strip()
        info["Architecture"] = subprocess.run(["adb", "-s", device_id, "shell", "getprop", "ro.product.cpu.abi"], capture_output=True, text=True, check=True).stdout.strip()
        info["Model"] = subprocess.run(["adb", "-s", device_id, "shell", "getprop", "ro.product.model"], capture_output=True, text=True, check=True).stdout.strip()
        info["Device Name"] = subprocess.run(["adb", "-s", device_id, "shell", "getprop", "ro.product.name"], capture_output=True, text=True, check=True).stdout.strip()
        info["Manufacturer"] = subprocess.run(["adb", "-s", device_id, "shell", "getprop", "ro.product.manufacturer"], capture_output=True, text=True, check=True).stdout.strip()
        info["SDK Level"] = subprocess.run(["adb", "-s", device_id, "shell", "getprop", "ro.build.version.sdk"], capture_output=True, text=True, check=True).stdout.strip()
        
        print(f"\n[+] Información del dispositivo {device_id}:")
        for key, value in info.items():
            print(f"    - {key}: {value}")
        log(f"Información del dispositivo obtenida: {info}")
        return info

    except subprocess.CalledProcessError as e:
        print(f"[-] Error al obtener información del dispositivo {device_id}. Comando fallido: {e.cmd}")
        log(f"Error al obtener información del dispositivo: {e.output}")
        return None
    except Exception as e:
        print(f"[-] Error inesperado al obtener información del dispositivo {device_id}: {e}")
        log(f"Error inesperado al obtener información del dispositivo: {e}")
        return None

def filtrar_aplicaciones(aplicaciones):
    """
    Filtra las aplicaciones irrelevantes para enfocarse en las de usuario.
    """
    log("Filtrando aplicaciones irrelevantes...")
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
    log(f"Aplicaciones filtradas: {len(aplicaciones_filtradas)}")
    return aplicaciones_filtradas

def listar_aplicaciones_relevantes(dispositivo):
    """
    Lista las aplicaciones relevantes en el dispositivo para que el usuario pueda elegir.
    """
    log(f"Listando aplicaciones relevantes en el dispositivo {dispositivo}...")
    try:
        resultado = subprocess.run(
            ['adb', '-s', dispositivo, 'shell', 'pm list packages'],
            stdout=subprocess.PIPE,
            text=True
        )
        aplicaciones = [line.split(":")[1].strip() for line in resultado.stdout.splitlines()]
        aplicaciones_filtradas = filtrar_aplicaciones(aplicaciones)
        if aplicaciones_filtradas:
            print(f"[+] Aplicaciones relevantes en el dispositivo ({dispositivo}):")
            for idx, app in enumerate(aplicaciones_filtradas, start=1):
                print(f"    {idx}. {app}")
            return aplicaciones_filtradas
        else:
            print(f"[-] No se encontraron aplicaciones relevantes en el dispositivo ({dispositivo}).")
            return []
    except Exception as e:
        print(f"[-] Error al listar aplicaciones en el dispositivo ({dispositivo}): {e}")
        log(f"Error al listar aplicaciones: {e}")
        return []

def seleccionar_aplicacion(aplicaciones):
    """
    Permite al usuario seleccionar una aplicación de la lista por número.
    """
    while True:
        try:
            opcion = input("[?] Ingresa el número de la aplicación que deseas seleccionar: ").strip()
            if not opcion.isdigit() or int(opcion) < 1 or int(opcion) > len(aplicaciones):
                print("[-] Selección inválida. Inténtalo nuevamente.")
                continue
            paquete = aplicaciones[int(opcion) - 1]
            log(f"Aplicación seleccionada: {paquete}")
            return paquete
        except KeyboardInterrupt:
            handle_interrupt(None, None)

def select_execution_mode():
    """
    Permite al usuario elegir entre el modo 'spawn' y 'attach'.
    Retorna True para 'attach' y False para 'spawn'.
    """
    print("\n--- Modo de Ejecución de Frida ---")
    print("1. Modo 'Spawn': Lanza la aplicación e inyecta el script.")
    print("2. Modo 'Attach': Se adjunta a una aplicación que ya está en ejecución.")
    print("---------------------------------")
    while True:
        try:
            opcion = input("[?] Selecciona el modo de ejecución (1/2): ").strip()
            if opcion == '1':
                log("Modo de ejecución seleccionado: 'spawn'")
                return False  # False para 'spawn'
            elif opcion == '2':
                log("Modo de ejecución seleccionado: 'attach'")
                return True  # True para 'attach'
            else:
                print("[-] Opción no válida. Por favor, ingresa '1' o '2'.")
        except KeyboardInterrupt:
            handle_interrupt(None, None)

# ==============================================================================
# --- SECCIÓN 3: GESTIÓN Y EJECUCIÓN DE SCRIPTS ---
# ==============================================================================

def normalizar_validar_ruta(ruta, directorio_base=None):
    """
    Normaliza y valida una ruta de archivo, manejando rutas relativas y absolutas.
    """
    log(f"Normalizando y validando la ruta: {ruta}")
    try:
        ruta = ruta.strip('"').strip("'").strip()
        if not os.path.isabs(ruta) and directorio_base:
            ruta_completa = os.path.join(directorio_base, ruta)
        else:
            ruta_completa = ruta
        ruta_normalizada = os.path.normpath(ruta_completa)
        
        if os.path.isfile(ruta_normalizada):
            log(f"Ruta validada: {ruta_normalizada}")
            return ruta_normalizada
        else:
            print(f"[-] La ruta '{ruta_normalizada}' no es un archivo válido.")
            log(f"La ruta no es un archivo válido: {ruta_normalizada}")
            return None
    except Exception as e:
        print(f"[-] Error al procesar la ruta '{ruta}': {e}")
        log(f"Error al procesar la ruta: {e}")
        return None

def listar_scripts_disponibles(directorio_scripts):
    """
    Lista los scripts disponibles en el directorio especificado.
    """
    log(f"Listando scripts en el directorio {directorio_scripts}...")
    if not os.path.isdir(directorio_scripts):
        print(f"[-] El directorio de scripts '{directorio_scripts}' no existe. Por favor, créalo o cámbialo en 'config.json'.")
        log(f"Directorio de scripts no existe: {directorio_scripts}")
        return []
    
    scripts = []
    for root, _, files in os.walk(directorio_scripts):
        for file in files:
            if file.endswith(".js"):
                ruta_relativa = os.path.relpath(os.path.join(root, file), directorio_scripts)
                scripts.append(ruta_relativa)
    
    if scripts:
        print(f"[+] Scripts disponibles en '{directorio_scripts}':")
        for idx, script in enumerate(scripts, start=1):
            print(f"    {idx}. {script}")
        log(f"Scripts encontrados: {len(scripts)}")
        return scripts
    else:
        print(f"[-] No se encontraron scripts en '{directorio_scripts}'.")
        log("No se encontraron scripts.")
        return []

def seleccionar_scripts(scripts_disponibles):
    """
    Permite al usuario seleccionar scripts por número o rango, o ingresar una ruta manual.
    """
    scripts_seleccionados = []
    while True:
        try:
            entrada = input("[?] Ingresa números de scripts (ej: 5, 8-10), 'q' para continuar, o 'm' para manual: ").strip().lower()
            if entrada == 'q':
                break
            elif entrada == 'm':
                ruta_manual = input("[?] Ingresa la ruta completa al script de Frida (.js): ").strip()
                ruta_validada = normalizar_validar_ruta(ruta_manual)
                if ruta_validada:
                    scripts_seleccionados.append(ruta_validada)
                    print(f"[+] Script añadido: {ruta_validada}")
                else:
                    print("[-] La ruta ingresada no es válida.")
            else:
                try:
                    partes = [p.strip() for p in entrada.split(',')]
                    for parte in partes:
                        if '-' in parte:
                            inicio, fin = map(int, parte.split('-'))
                            if inicio < 1 or fin > len(scripts_disponibles):
                                print(f"[-] Rango fuera de límites: {parte}")
                                continue
                            for idx in range(inicio, fin + 1):
                                ruta_script = scripts_disponibles[idx - 1]
                                ruta_completa = os.path.join(SCRIPTS_FOLDER, ruta_script)
                                ruta_validada = normalizar_validar_ruta(ruta_completa)
                                if ruta_validada and ruta_validada not in scripts_seleccionados:
                                    scripts_seleccionados.append(ruta_validada)
                                    print(f"[+] Script añadido: {scripts_disponibles[idx-1]}")
                        else:
                            idx = int(parte)
                            if idx < 1 or idx > len(scripts_disponibles):
                                print(f"[-] Número inválido: {parte}")
                                continue
                            ruta_script = scripts_disponibles[idx - 1]
                            ruta_completa = os.path.join(SCRIPTS_FOLDER, ruta_script)
                            ruta_validada = normalizar_validar_ruta(ruta_completa)
                            if ruta_validada and ruta_validada not in scripts_seleccionados:
                                scripts_seleccionados.append(ruta_validada)
                                print(f"[+] Script añadido: {scripts_disponibles[idx-1]}")
                except (ValueError, IndexError):
                    print(f"[-] Error al procesar la entrada '{entrada}'. Asegúrate de usar el formato correcto.")
        except KeyboardInterrupt:
            handle_interrupt(None, None)
    
    return scripts_seleccionados

def convertir_unicode_en_linea(linea):
    """
    Convierte secuencias de escape Unicode literales como '\u2705' a sus caracteres reales.
    """
    def reemplazar(match):
        hex_code = match.group(1)
        return chr(int(hex_code, 16))
    
    # Expresión regular para encontrar '\uXXXX'
    patron_unicode = r'\\u([0-9a-fA-F]{4})'
    
    return re.sub(patron_unicode, reemplazar, linea)

def ejecutar_script_frida(dispositivo, paquete, rutas_scripts, modo_attach=False):
    """
    Ejecuta múltiples scripts de Frida en una aplicación, con opción de 'spawn' o 'attach'.
    La salida se maneja para preservar colores y caracteres especiales.
    """
    if modo_attach:
        log(f"Ejecutando {len(rutas_scripts)} script(s) en modo 'attach' en la aplicación {paquete}.")
    else:
        log(f"Ejecutando {len(rutas_scripts)} script(s) en modo 'spawn' en la aplicación {paquete}.")
    
    device_flag = "-U" if is_usb_device(dispositivo) else "-D"
    
    if modo_attach:
        # Se corrige el flag a -f para adjuntar por identificador de paquete
        comando = ['frida', device_flag, dispositivo, '-f', paquete]
    else:
        comando = ['frida', device_flag, dispositivo, '-f', paquete]

    for ruta in rutas_scripts:
        comando += ['-l', ruta]

    print(f"\n[+] Ejecutando comando: {' '.join(comando)}")
    print("[!] Esperando a la salida de Frida...")

    try:
        proceso = subprocess.Popen(
            comando,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,  # Redirige stderr a stdout
            text=True,                 # Habilita el modo texto
            encoding='utf-8',          # Decodifica la salida como UTF-8
            errors='replace'           # Reemplaza los caracteres inválidos
        )
        
        while True:
            linea = proceso.stdout.readline()
            if not linea:
                break
            
            # Procesar la línea para reemplazar secuencias de escape Unicode
            linea_procesada = convertir_unicode_en_linea(linea)
            print(linea_procesada, end='', flush=True)

        proceso.wait()
        
        if proceso.returncode == 0:
            print("\n[+] Todos los scripts se ejecutaron correctamente.")
            log("Ejecución de scripts exitosa.")
            return True
        else:
            print(f"\n[-] El comando de Frida terminó con un error. Código de salida: {proceso.returncode}")
            log(f"Error al ejecutar scripts. Código de salida: {proceso.returncode}")
            
            # La salida ya fue impresa en tiempo real
            return False
            
    except FileNotFoundError:
        print("[-] Error: El comando 'frida' no se encuentra. Asegúrate de que esté instalado y en tu PATH.")
        log("Error: Comando 'frida' no encontrado.")
        return False
    except Exception as e:
        print(f"[-] Error inesperado al ejecutar los scripts: {e}")
        log(f"Error inesperado al ejecutar scripts: {e}")
        return False

# ==============================================================================
# --- SECCIÓN 4: FUNCIÓN PRINCIPAL ---
# ==============================================================================

def main():
    """
    Función principal que orquesta la ejecución del script.
    """
    signal.signal(signal.SIGINT, handle_interrupt)
    
    enable_ansi_colors()
    load_config()
    
    print(f"[*] Iniciando {os.path.basename(sys.argv[0])}...")
    
    if not show_options_menu():
        print("Saliendo del programa.")
        return

    # 1. Verificación de dependencias
    if not verificar_frida_instalado():
        print("[-] La ejecución no puede continuar sin Frida instalado.")
        return

    # 2. Selección de dispositivo
    dispositivo_seleccionado = listar_dispositivos()
    if not dispositivo_seleccionado:
        print("[-] No se pudo seleccionar un dispositivo. Saliendo del script.")
        return

    # 3. Obtención de información del sistema
    info_dispositivo = get_device_info(dispositivo_seleccionado)
    
    # 4. Verificación de frida-server
    if not verificar_frida_server_activo(dispositivo_seleccionado):
        print("[-] frida-server no está en ejecución en el dispositivo seleccionado. Asegúrate de iniciarlo antes de continuar.")
        return

    # 5. Selección de aplicación
    aplicaciones = listar_aplicaciones_relevantes(dispositivo_seleccionado)
    if not aplicaciones:
        print("[-] No se encontraron aplicaciones relevantes en el dispositivo.")
        return
    paquete_seleccionado = seleccionar_aplicacion(aplicaciones)
    print(f"[+] Aplicación seleccionada: {paquete_seleccionado}")

    # 6. Selección de scripts
    scripts = listar_scripts_disponibles(SCRIPTS_FOLDER)
    if not scripts:
        print("[-] No hay scripts para seleccionar. Saliendo.")
        return
        
    scripts_a_ejecutar = seleccionar_scripts(scripts)
    
    if not scripts_a_ejecutar:
        print("[-] No se seleccionaron scripts para ejecutar.")
        return

    # 7. Selección del modo de ejecución
    modo_attach = select_execution_mode()

    # 8. Ejecución
    if not ejecutar_script_frida(dispositivo_seleccionado, paquete_seleccionado, scripts_a_ejecutar, modo_attach):
        # Si la ejecución en modo spawn falló, preguntar si quiere intentar en modo attach
        if not modo_attach:
            respuesta = input("\n[?] ¿Deseas intentar de nuevo con el modo 'attach'? (s/n): ").strip().lower()
            if respuesta == 's':
                print("\n[!] Por favor, inicia manualmente la aplicación en tu dispositivo.")
                input("[!] Presiona Enter una vez que la aplicación esté abierta para continuar...")
                ejecutar_script_frida(dispositivo_seleccionado, paquete_seleccionado, scripts_a_ejecutar, modo_attach=True)

if __name__ == "__main__":
    main()