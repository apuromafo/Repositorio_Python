import sys
import subprocess
import os

# Funciones
def ejecutar_comando_adb(comando, selector_dispositivo=None):
    """
    Ejecuta un comando ADB de forma segura y devuelve su salida.
    Maneja la selección de dispositivo (serial o transport ID).
    """
    if selector_dispositivo:
        if selector_dispositivo.isdigit():  # Es un transport ID
            cmd_prefix = ['adb', f'-t{selector_dispositivo}']
        else:  # Es un serial
            cmd_prefix = ['adb', '-s', selector_dispositivo]
    else:
        cmd_prefix = ['adb']

    full_cmd = cmd_prefix + comando
    try:
        resultado = subprocess.run(full_cmd, capture_output=True, text=True, check=True)
        return resultado.stdout
    except subprocess.CalledProcessError as e:
        print(f"[-] Error al ejecutar el comando ADB: {' '.join(full_cmd)}")
        print(f"    Salida de error: {e.stderr}")
        sys.exit(1)
    except FileNotFoundError:
        print("[-] Error: 'adb' no se encontró. Asegúrate de que Android SDK Platform-Tools esté instalado y en tu PATH.")
        sys.exit(1)


def seleccionar_dispositivo():
    """Selecciona un dispositivo conectado a la computadora y muestra su información."""
    print("--- Selección de Dispositivo ---")
    resultado_devices = ejecutar_comando_adb(['devices', '-l'])

    dispositivos = []
    lineas = resultado_devices.strip().split('\n')[1:] # Saltar la primera línea

    if not lineas:
        print("[-] No se encontraron dispositivos conectados. Asegúrate de que ADB esté funcionando y tu dispositivo esté conectado y autorizado.")
        sys.exit(1)

    active_devices_lines = [line for line in lineas if "device" in line and "offline" not in line]

    if not active_devices_lines:
        print("[-] No se encontraron dispositivos activos. Asegúrate de que tu dispositivo esté online.")
        sys.exit(1)

    for linea in active_devices_lines:
        parts = linea.strip().split()
        serial = parts[0]
        transport_id = next((p.split(':')[1] for p in parts if p.startswith('transport_id:')), serial)
        device_name_parts = [p.split(':')[1] for p in parts if p.startswith('model:')]
        device_name = device_name_parts[0] if device_name_parts else 'Unknown Device'
        product_name_parts = [p.split(':')[1] for p in parts if p.startswith('product:')]
        product_name = product_name_parts[0] if product_name_parts else 'Unknown Product'
        device_status = next((p for p in parts if p in ['device', 'offline']), 'unknown')


        dispositivos.append({
            'serial': serial,
            'nombre_dispositivo': device_name,
            'nombre_producto': product_name,
            'transporte': transport_id if transport_id != serial else None,
            'estado': device_status
        })

    selector_final = None
    if len(dispositivos) == 1:
        print(f"[*] Solo hay un dispositivo conectado: {dispositivos[0]['nombre_dispositivo']} ({dispositivos[0]['serial']})")
        selector_final = dispositivos[0]['transporte'] if dispositivos[0]['transporte'] else dispositivos[0]['serial']
    else:
        print('Dispositivos disponibles:')
        for i, dispositivo in enumerate(dispositivos):
            print(f"{i+1}) {dispositivo['nombre_dispositivo']} (Serial: {dispositivo['serial']}) [Estado: {dispositivo['estado']}]")
            if dispositivo['transporte']:
                print(f"    Transport ID: {dispositivo['transporte']}")

        while True:
            seleccion = input('Selecciona un dispositivo (1-%d): ' % len(dispositivos))
            try:
                indice = int(seleccion) - 1
                if 0 <= indice < len(dispositivos):
                    selector_final = dispositivos[indice]['transporte'] if dispositivos[indice]['transporte'] else dispositivos[indice]['serial']
                    break
            except ValueError:
                pass
            print('Selección no válida.')

    # Mostrar información adicional del dispositivo seleccionado
    if selector_final:
        print("\n--- Información del Dispositivo Seleccionado ---")
        try:
            modelo = ejecutar_comando_adb(['shell', 'getprop', 'ro.product.model'], selector_final).strip()
            fabricante = ejecutar_comando_adb(['shell', 'getprop', 'ro.product.manufacturer'], selector_final).strip()
            arquitectura = ejecutar_comando_adb(['shell', 'getprop', 'ro.product.cpu.abi'], selector_final).strip()
            version_android = ejecutar_comando_adb(['shell', 'getprop', 'ro.build.version.release'], selector_final).strip()

            print(f"[*] Modelo: {modelo}")
            print(f"[*] Fabricante: {fabricante}")
            print(f"[*] Arquitectura (ABI): {arquitectura}")
            print(f"[*] Versión de Android: {version_android}")
        except Exception as e:
            print(f"[-] No se pudo obtener toda la información del dispositivo: {e}")
            print("    Continuando con la extracción de APKs.")
    
    return selector_final


def listar_aplicaciones_usuario(selector_dispositivo):
    """Lista las aplicaciones instaladas por el usuario en un dispositivo."""
    print("\n--- Aplicaciones Instaladas por el Usuario ---")
    salida = ejecutar_comando_adb(['shell', 'pm', 'list', 'packages', '-3'], selector_dispositivo)

    paquetes_usuario = []
    lineas = salida.strip().split('\n')
    for linea in lineas:
        if 'package:' in linea:
            paquete = linea.split(':')[1].strip()
            paquetes_usuario.append(paquete)

    if paquetes_usuario:
        print("[+] Se encontraron las siguientes aplicaciones de usuario:")
        for indice, aplicacion in enumerate(paquetes_usuario):
            print(f"{indice+1}) {aplicacion}")
    else:
        print("[-] No se encontraron aplicaciones instaladas por el usuario.")
    
    return paquetes_usuario


def listar_aplicaciones(palabra_clave, selector_dispositivo):
    """Lista las aplicaciones instaladas en un dispositivo que coincidan con una palabra clave."""
    print("\n--- Búsqueda de Aplicaciones ---")
    salida = ejecutar_comando_adb(['shell', 'pm', 'list', 'packages'], selector_dispositivo)

    paquetes = []
    lineas = salida.strip().split('\n')
    for linea in lineas:
        if palabra_clave.lower() in linea.lower():  # Búsqueda insensible a mayúsculas y minúsculas
            paquete = linea.split(':')[1]
            paquetes.append(paquete.strip())

    if paquetes:
        print(f"[+] Paquetes encontrados que contienen '{palabra_clave}':")
        for indice, aplicacion in enumerate(paquetes):
            print(f"{indice+1}) {aplicacion}")

        while True:
            try:
                opcion = int(input("Selecciona un número de paquete para continuar (o 0 para salir): "))
                if opcion == 0:
                    sys.exit(0)
                if 1 <= opcion <= len(paquetes):
                    return paquetes[opcion-1]
            except ValueError:
                pass

            print("[-] Opción no válida. Intenta nuevamente.")
    else:
        print(f"[-] No se encontraron nombres de paquetes que contengan '{palabra_clave}'.")
        sys.exit(1)


def listar_apks(nombre_paquete, selector_dispositivo):
    """Lista las rutas de las APKs instaladas para un nombre de paquete específico."""
    print("\n--- Listado de Rutas APK ---")
    rutas_apk = []
    salida = ejecutar_comando_adb(['shell', 'pm', 'path', nombre_paquete], selector_dispositivo)

    lineas = salida.strip().split('\n')
    for linea in lineas:
        if 'package:' in linea:
            ruta_apk = linea.split(':')[1].strip()
            rutas_apk.append(ruta_apk)

    if rutas_apk:
        print(f"[+] APKs encontradas para '{nombre_paquete}':")
        for ruta_apk in rutas_apk:
            print(f"    - {ruta_apk}")
        return rutas_apk
    else:
        print(f"[-] No se encontraron APKs para el paquete '{nombre_paquete}'. Esto podría indicar un problema o que el paquete no está instalado correctamente.")
        sys.exit(1)

def extraer_apks(rutas_apk, nombre_paquete, selector_dispositivo):
    """Extrae las APKs en el directorio actual, creando una subcarpeta para el paquete."""
    print("\n--- Extracción de APKs ---")
    current_dir = os.getcwd()
    
    # Crear una subcarpeta con el nombre del paquete para organizar los APKs
    output_dir = os.path.join(current_dir, f"APKs_{nombre_paquete}")
    os.makedirs(output_dir, exist_ok=True)
    print(f"[*] Las APKs se guardarán en el directorio: {output_dir}")

    for i, ruta in enumerate(rutas_apk):
        original_filename = ruta.split('/')[-1]
        output_filepath = os.path.join(output_dir, original_filename)

        print(f"[*] Extrayendo {i+1}/{len(rutas_apk)}: '{original_filename}' desde '{ruta}'...")
        ejecutar_comando_adb(['pull', ruta, output_filepath], selector_dispositivo)
        print(f"[+] '{output_filepath}' extraído correctamente.")
    print("\n[+] ¡Todos los archivos APK han sido extraídos exitosamente!")


def main():
    print("--- Herramienta de Extracción de APK ---")
    
    selector_dispositivo = seleccionar_dispositivo()
    
    # Listar aplicaciones instaladas por el usuario
    listar_aplicaciones_usuario(selector_dispositivo)

    palabra_clave = input("\nIngresa una palabra clave para buscar aplicaciones (ej. 'chrome', 'whatsapp') o presiona Enter para ver todas las aplicaciones: ")
    
    if not palabra_clave:
        print("[*] Listando todas las aplicaciones instaladas (puede tardar un poco)...")
        # Si la palabra clave está vacía, mostramos todas las aplicaciones.
        # Para ello, usamos una palabra clave que seguramente estará en todos los nombres de paquete "package:".
        nombre_paquete_seleccionado = listar_aplicaciones("package:", selector_dispositivo)
    else:
        nombre_paquete_seleccionado = listar_aplicaciones(palabra_clave, selector_dispositivo)

    rutas_apk = listar_apks(nombre_paquete_seleccionado, selector_dispositivo)
    extraer_apks(rutas_apk, nombre_paquete_seleccionado, selector_dispositivo)

if __name__ == "__main__":
    main()