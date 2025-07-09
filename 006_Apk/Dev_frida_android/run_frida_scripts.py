import os
import subprocess

# Ruta predeterminada donde se guardarán los scripts de Frida
RUTA_SCRIPTS = "./scripts"

def verificar_frida_instalado():
    """Verifica si Frida está instalado en el sistema."""
    try:
        resultado = subprocess.run(['frida', '--version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if resultado.returncode == 0:
            print(f"[+] Frida está instalado. Versión: {resultado.stdout.strip()}")
            return True
        else:
            print("[-] Frida no está instalado o no se encuentra en el PATH.")
            return False
    except Exception as e:
        print(f"[-] Error al verificar Frida: {e}")
        return False


def verificar_frida_server_activo(dispositivo):
    """Verifica si frida-server está en ejecución en el dispositivo."""
    try:
        resultado = subprocess.run(
            ['adb', '-s', dispositivo, 'shell', 'ps | grep frida-server'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        if "frida-server" in resultado.stdout:
            print(f"[+] frida-server está en ejecución en el dispositivo ({dispositivo}).")
            return True
        else:
            print(f"[-] frida-server no está en ejecución en el dispositivo ({dispositivo}).")
            return False
    except Exception as e:
        print(f"[-] Error al verificar si frida-server está en ejecución en el dispositivo ({dispositivo}): {e}")
        return False


def filtrar_aplicaciones(aplicaciones):
    """Filtra las aplicaciones excluyendo aquellas irrelevantes o en la lista blanca."""
    # Lista de paquetes en la lista blanca
    lista_blanca = {
        "android.car.cluster.maserati",
        "com.android.apps.tag",
        "com.android.auto.embedded.cts.verifier",
        "com.android.car.carlauncher",
        "com.android.car.home",
        "com.android.car.retaildemo",
        "com.android.car.settingslib.robotests",
        "com.android.car.setupwizardlib.robotests",
        "com.android.cardock",
        "com.android.connectivity.metrics",
        "com.android.facelock",
        "com.android.google.gce.gceservice",
        "com.android.hotwordenrollment.okgoogle",
        "com.android.hotwordenrollment.tgoogle",
        "com.android.hotwordenrollment.xgoogle",
        "com.android.inputmethod.latin",
        "com.android.media.update",
        "com.android.netspeed",
        "com.android.onemedia",
        "com.android.pixellogger",
        "com.android.ramdump",
        "com.android.settingslib.robotests",
        "com.android.simappdialog",
        "com.android.statsd.dogfood",
        "com.android.statsd.loadtest",
        "com.android.systemui.shared",
        "com.android.test.power",
        "com.android.test.voiceenrollment",
        "com.android.tv.provision",
        "com.google.SSRestartDetector",
        "com.google.android.apps.nexuslauncher",
        "com.google.android.apps.wallpaper",
        "com.google.android.asdiv",
        "com.google.android.athome.globalkeyinterceptor",
        "com.google.android.car.bugreport",
        "com.google.android.car.defaultstoragemonitoringcompanionapp",
        "com.google.android.car.diagnosticrecorder",
        "com.google.android.car.diagnosticverifier",
        "com.google.android.car.diskwriteapp",
        "com.google.android.car.flashapp",
        "com.google.android.car.kitchensink",
        "com.google.android.car.obd2app",
        "com.google.android.car.setupwizard",
        "com.google.android.car.usb.aoap.host",
        "com.google.android.car.vms.subscriber",
        "com.google.android.carrier",
        "com.google.android.carriersetup",
        "com.google.android.connectivitymonitor",
        "com.google.android.edu.harnesssettings",
        "com.google.android.ext.services",
        "com.google.android.factoryota",
        "com.google.android.feedback",
        "com.google.android.gsf",
        "com.google.android.hardwareinfo",
        "com.google.android.hiddenmenu",
        "com.google.android.onetimeinitializer",
        "com.google.android.permissioncontroller",
        "com.google.android.partner.provisioning",
        "com.google.android.partnersetup",
        "com.google.android.pixel.setupwizard",
        "com.google.android.preloaded_drawable_viewer",
        "com.google.android.printservice.recommendation",
        "com.google.android.sampledeviceowner",
        "com.google.android.apps.scone",
        "com.google.android.sdksetup",
        "com.google.android.setupwizard",
        "com.google.android.storagemanager",
        "com.google.android.tag",
        "com.google.android.tungsten.overscan",
        "com.google.android.tungsten.setupwraith",
        "com.google.android.tv.bugreportsender",
        "com.google.android.tv.frameworkpackagestubs",
        "com.google.android.tv.pairedsetup",
        "com.google.android.vendorloggingservice",
        "com.google.android.volta",
        "com.google.android.wfcactivation",
        "com.google.mds",
        "com.google.modemservice",
        "com.htc.omadm.trigger",
        "com.qualcomm.qcrilmsgtunnel",
        "com.ustwo.lwp",
        "org.chromium.arc.accessibilityhelper",
        "org.chromium.arc.apkcacheprovider",
        "org.chromium.arc.applauncher",
        "org.chromium.arc.backup_settings",
        "org.chromium.arc.cast_receiver",
        "org.chromium.arc.crash_collector",
        "org.chromium.arc.file_system",
        "org.chromium.arc.gms",
        "org.chromium.arc.home",
        "org.chromium.arc.intent_helper",
        "org.chromium.arc.tts"
    }

    # Filtrar aplicaciones
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
            app in lista_blanca  # Añadimos la condición para omitir los paquetes en la lista blanca
        )
    ]
    return aplicaciones_filtradas


def listar_aplicaciones_relevantes(dispositivo):
    """Lista las aplicaciones relevantes en el dispositivo."""
    try:
        resultado = subprocess.run(
            ['adb', '-s', dispositivo, 'shell', 'pm list packages'],
            stdout=subprocess.PIPE,
            text=True
        )
        aplicaciones = [line.split(":")[1].strip() for line in resultado.stdout.splitlines()]
        # Filtrar aplicaciones
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
        return []


def seleccionar_aplicacion(aplicaciones):
    """Permite al usuario seleccionar una aplicación por número."""
    while True:
        opcion = input("[?] Ingresa el número de la aplicación que deseas seleccionar: ").strip()
        if not opcion.isdigit() or int(opcion) < 1 or int(opcion) > len(aplicaciones):
            print("[-] Selección inválida. Inténtalo nuevamente.")
            continue
        return aplicaciones[int(opcion) - 1]


def normalizar_validar_ruta(ruta):
    """
    Normaliza una ruta eliminando comillas y verifica si es un archivo válido.
    Args:
        ruta (str): La ruta proporcionada por el usuario.
    Returns:
        str: La ruta normalizada si es válida.
        None: Si la ruta no es válida.
    """
    try:
        # Paso 1: Eliminar comillas adicionales al inicio y al final
        ruta = ruta.strip('"').strip("'")
        # Paso 2: Normalizar la ruta para compatibilidad
        ruta_normalizada = os.path.normpath(ruta)
        # Paso 3: Verificar si la ruta es un archivo válido
        if os.path.isfile(ruta_normalizada):
            print(f"[+] Ruta válida: {ruta_normalizada}")
            return ruta_normalizada
        else:
            print(f"[-] La ruta '{ruta_normalizada}' no es un archivo válido.")
            return None
    except Exception as e:
        print(f"[-] Error al procesar la ruta '{ruta}': {e}")
        return None


def listar_scripts_disponibles(directorio_scripts):
    """Lista los scripts disponibles en el directorio especificado y sus subdirectorios."""
    if not os.path.isdir(directorio_scripts):
        print(f"[-] El directorio de scripts '{directorio_scripts}' no existe.")
        return []
    # Buscar archivos .js de forma recursiva en todas las subcarpetas
    scripts = []
    for root, _, files in os.walk(directorio_scripts):
        for file in files:
            if file.endswith(".js"):
                # Guardar la ruta relativa al directorio principal
                ruta_relativa = os.path.relpath(os.path.join(root, file), directorio_scripts)
                scripts.append(ruta_relativa)
    if scripts:
        print(f"[+] Scripts disponibles en '{directorio_scripts}':")
        for idx, script in enumerate(scripts, start=1):
            print(f"    {idx}. {script}")
        return scripts
    else:
        print(f"[-] No se encontraron scripts en '{directorio_scripts}'.")
        return []


def ejecutar_script_frida(dispositivo, paquete, rutas_scripts):
    """Ejecuta múltiples scripts de Frida en una aplicación."""
    try:
        print(f"[+] Ejecutando {len(rutas_scripts)} script(s) en la aplicación {paquete}...")
        comando = ['frida', '-U', '-f', paquete]
        for ruta in rutas_scripts:
            comando += ['-l', ruta]
        subprocess.run(comando, check=True)
        print(f"[+] Todos los scripts se ejecutaron correctamente en {paquete}.")
    except Exception as e:
        print(f"[-] Error al ejecutar los scripts en {paquete}: {e}")


def main():
    print("[*] Iniciando validación y ejecución de Frida...")
    # Paso 1: Verificar que Frida esté instalado
    if not verificar_frida_instalado():
        print("[-] La ejecución no puede continuar sin Frida instalado.")
        return

    # Paso 2: Listar dispositivos conectados
    try:
        resultado = subprocess.run(['adb', 'devices'], stdout=subprocess.PIPE, text=True)
        lineas = resultado.stdout.strip().split('\n')
        if len(lineas) <= 1:
            print("[-] No hay dispositivos conectados.")
            return
        dispositivos = [line.split('\t')[0] for line in lineas[1:] if 'device' in line]
        if dispositivos:
            print(f"[+] Dispositivos conectados: {', '.join(dispositivos)}")
        else:
            print("[-] No hay dispositivos conectados.")
            return
    except Exception as e:
        print(f"[-] Error al listar dispositivos: {e}")
        return

    # Paso 3: Seleccionar un dispositivo
    dispositivo = dispositivos[0]  # Por simplicidad, seleccionamos el primer dispositivo
    print(f"[+] Usando dispositivo: {dispositivo}")

    # Paso 4: Validar que frida-server esté en ejecución
    if not verificar_frida_server_activo(dispositivo):
        print("[-] frida-server no está en ejecución. Asegúrate de iniciarlo antes de continuar.")
        return

    # Paso 5: Listar aplicaciones relevantes
    aplicaciones = listar_aplicaciones_relevantes(dispositivo)
    if not aplicaciones:
        print("[-] No se encontraron aplicaciones relevantes en el dispositivo.")
        return

    # Paso 6: Seleccionar una aplicación
    paquete_seleccionado = seleccionar_aplicacion(aplicaciones)
    print(f"[+] Aplicación seleccionada: {paquete_seleccionado}")

    # Paso 7: Listar scripts disponibles
    scripts = listar_scripts_disponibles(RUTA_SCRIPTS)

    # Paso 8: Permitir al usuario seleccionar uno o varios scripts
    scripts_seleccionados = []

    while True:
        entrada = input("[?] Ingresa números de scripts (ej: 5, 8-10), 'q' para salir: ").strip()
        if entrada.lower() == 'q':
            break

        try:
            partes = [p.strip() for p in entrada.split(',')]
            for parte in partes:
                if '-' in parte:
                    # Es un rango
                    inicio, fin = map(int, parte.split('-'))
                    if inicio < 1 or fin > len(scripts):
                        print(f"[-] Rango fuera de límites: {parte}")
                        continue
                    for idx in range(inicio, fin + 1):
                        ruta_script = os.path.join(RUTA_SCRIPTS, scripts[idx - 1])
                        ruta_validada = normalizar_validar_ruta(ruta_script)
                        if ruta_validada and ruta_validada not in scripts_seleccionados:
                            scripts_seleccionados.append(ruta_validada)
                            print(f"[+] Script añadido: {scripts[idx - 1]}")
                else:
                    # Número individual
                    idx = int(parte)
                    if idx < 1 or idx > len(scripts):
                        print(f"[-] Número inválido: {parte}")
                        continue
                    ruta_script = os.path.join(RUTA_SCRIPTS, scripts[idx - 1])
                    ruta_validada = normalizar_validar_ruta(ruta_script)
                    if ruta_validada and ruta_validada not in scripts_seleccionados:
                        scripts_seleccionados.append(ruta_validada)
                        print(f"[+] Script añadido: {scripts[idx - 1]}")
        except Exception as e:
            print(f"[-] Error al procesar la entrada '{entrada}': {e}")

    # Paso 9: Opción de ingresar manualmente una ruta
    while True:
        respuesta_manual = input("[?] ¿Deseas ingresar manualmente una ruta de script? (s/n): ").strip().lower()
        if respuesta_manual == 'n':
            break
        elif respuesta_manual == 's':
            ruta_manual = input("[?] Ingresa la ruta completa al script de Frida (.js): ").strip()
            ruta_validada = normalizar_validar_ruta(ruta_manual)
            if ruta_validada:
                scripts_seleccionados.append(ruta_validada)
                print(f"[+] Script añadido: {ruta_validada}")
            else:
                print("[-] La ruta ingresada no es válida.")
        else:
            print("[-] Respuesta inválida. Ingresa 's' para sí o 'n' para no.")

    if not scripts_seleccionados:
        print("[-] No se seleccionaron scripts para ejecutar.")
        return

    # Paso 10: Ejecutar los scripts seleccionados
    ejecutar_script_frida(dispositivo, paquete_seleccionado, scripts_seleccionados)


if __name__ == "__main__":
    main()