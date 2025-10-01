#--------------------------------------------------------------------------------------
# Nombre del Script: Frida Script Runner
# Versión: 1.5.0
# Descripción:
#   Automatiza la ejecución de scripts de Frida en un dispositivo.
#   Ofrece funcionalidades avanzadas como la selección de dispositivos,
#   la obtención de información del sistema, gestión de logs y, ahora,
#   la configuración personalizada de la carpeta de scripts.
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
#   ✅ Reestructuración del código en secciones claras y comentadas.
# ==============================================================================

import os
import subprocess
import sys
import json
import signal

VERSION = "1.5.0"
CONFIG_FILE = r"config\config_restart_frida_server.json"
LOG_FILE = "frida_runner.log"
global ENABLE_LOGS
global SCRIPTS_FOLDER

# ==============================================================================
# --- SECCIÓN 1: CONFIGURACIÓN Y UTILIDADES BÁSICAS ---
# ==============================================================================

def load_config():
    # Asegura que la carpeta de configuración exista
    if not os.path.exists("config"):
        os.makedirs("config")
    
    # Asegura que la carpeta de configuración exista
    if not os.path.exists("config"):
        os.makedirs("config")
    
    """
    Carga la configuración desde un archivo JSON. Si no existe, crea uno por defecto.
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
            print(f"    {idx}. {dev}")
        print("-------------------------------")
        
        while True:
            seleccion = input("[?] Ingresa el número del dispositivo a utilizar: ").strip()
            if not seleccion.isdigit() or int(seleccion) < 1 or int(seleccion) > len(dispositivos):
                print("[-] Selección inválida. Inténtalo nuevamente.")
                continue
            
            dispositivo_seleccionado = dispositivos[int(seleccion) - 1]
            log(f"Dispositivo seleccionado: {dispositivo_seleccionado}")
            return dispositivo_seleccionado

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

def obtener_info_sistema(dispositivo):
    """Obtiene información del sistema como la plataforma y la arquitectura."""
    log(f"Obteniendo información del sistema para el dispositivo {dispositivo}...")
    try:
        resultado = subprocess.run(
            ['frida', '-U', dispositivo, '-i'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        plataforma = None
        arquitectura = None
        
        for line in resultado.stdout.splitlines():
            if "Platform:" in line:
                plataforma = line.split(":")[-1].strip()
            elif "Architecture:" in line:
                arquitectura = line.split(":")[-1].strip()
        
        if plataforma and arquitectura:
            print(f"[+] Información del sistema para {dispositivo}:")
            print(f"    - Plataforma: {plataforma}")
            print(f"    - Arquitectura: {arquitectura}")
            log(f"Info del sistema obtenida: Plataforma={plataforma}, Arquitectura={arquitectura}")
            return plataforma, arquitectura
        else:
            print("[-] No se pudo obtener la información del sistema.")
            log("No se pudo obtener la información del sistema.")
            return None, None
            
    except Exception as e:
        print(f"[-] Error al obtener la información del sistema: {e}")
        log(f"Error al obtener info del sistema: {e}")
        return None, None

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
        opcion = input("[?] Ingresa el número de la aplicación que deseas seleccionar: ").strip()
        if not opcion.isdigit() or int(opcion) < 1 or int(opcion) > len(aplicaciones):
            print("[-] Selección inválida. Inténtalo nuevamente.")
            continue
        paquete = aplicaciones[int(opcion) - 1]
        log(f"Aplicación seleccionada: {paquete}")
        return paquete

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
            print(f"[+] Ruta válida: {ruta_normalizada}")
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
                # Para mostrar la ruta relativa al directorio base de scripts
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
            except Exception as e:
                print(f"[-] Error al procesar la entrada '{entrada}': {e}")
    
    return scripts_seleccionados

def ejecutar_script_frida(dispositivo, paquete, rutas_scripts):
    """Ejecuta múltiples scripts de Frida en una aplicación."""
    log(f"Ejecutando {len(rutas_scripts)} script(s) en la aplicación {paquete}.")
    try:
        print(f"[+] Ejecutando {len(rutas_scripts)} script(s) en la aplicación {paquete}...")
        comando = ['frida', '-U', dispositivo, '-f', paquete]
        for ruta in rutas_scripts:
            comando += ['-l', ruta]
        subprocess.run(comando, check=True)
        print(f"[+] Todos los scripts se ejecutaron correctamente en {paquete}.")
        log("Ejecución de scripts exitosa.")
    except Exception as e:
        print(f"[-] Error al ejecutar los scripts en {paquete}: {e}")
        log(f"Error al ejecutar scripts: {e}")

# ==============================================================================
# --- SECCIÓN 4: FUNCIÓN PRINCIPAL ---
# ==============================================================================

def main():
    """
    Función principal que orquesta la ejecución del script.
    """
    signal.signal(signal.SIGINT, handle_interrupt)
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
    obtener_info_sistema(dispositivo_seleccionado)
    
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

    # 7. Ejecución
    ejecutar_script_frida(dispositivo_seleccionado, paquete_seleccionado, scripts_a_ejecutar)

if __name__ == "__main__":
    main()