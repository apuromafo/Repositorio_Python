import os
import subprocess
import sys
import urllib.request
import zipfile

# Configuración de las herramientas
CONFIG = {
    "apktool": {
        "path": "herramientas/apktool/apktool.jar",
        "url": "https://github.com/iBotPeaches/Apktool/releases/download/v2.5.0/apktool_2.5.0.jar",
    },
    "dex2jar": {
         "path": "herramientas/d2j-dex2jar/dex-tools-v2.4/d2j-jar2dex.bat" if sys.platform == 'win32' else "herramientas/d2j-dex2jar/dex-tools-v2.4/d2j-jar2dex.sh",
        "url": "https://github.com/pxb1988/dex2jar/releases/download/v2.4/dex-tools-v2.4.zip",
    },
    "uberapksigner": {
        "path": "herramientas/uber-apk-signer/uber-apk-signer.jar",
        "url": "https://github.com/patrickfav/uber-apk-signer/releases/download/v1.3.0/uber-apk-signer-1.3.0.jar",
    },
}

def verificar_herramientas():
    for tool, config in CONFIG.items():
        print(f"Verificando {tool} en {config['path']}")
        if not os.path.isfile(config["path"]):
            print(f"{tool} no encontrado en {config['path']}. Descargando...")
            descargar_herramienta(tool, config["url"], config["path"])

def descargar_herramienta(tool, url, path):
    # Crea la carpeta si no existe
    os.makedirs(os.path.dirname(path), exist_ok=True)
    
    try:
        if tool == "dex2jar":
            zip_path = "herramientas/d2j-dex2jar.zip"
            print(f"Descargando {tool} desde {url}...")
            urllib.request.urlretrieve(url, zip_path)
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall("herramientas/d2j-dex2jar")
            os.remove(zip_path)
            print(f"{tool} descargado y extraído en herramientas/d2j-dex2jar/")
            # Verifica si el archivo se extrajo
            if not os.path.isfile(config["path"]):
                print(f"[-] Error: {tool} no se encontró después de la extracción.")
        else:
            print(f"Descargando {tool} desde {url}...")
            urllib.request.urlretrieve(url, path)
            print(f"{tool} descargado en {path}")
    except Exception as e:
        print(f"[-] Error al descargar {tool}: {e}")

def seleccionar_dispositivo():
    """Selecciona un dispositivo conectado a la computadora."""
    resultado = subprocess.run(['adb', 'devices', '-l'], capture_output=True, text=True)
    dispositivos = []
    lineas = resultado.stdout.strip().split('\n')[1:]
    
    if len(lineas) > 1:
        for linea in lineas:
            info_dispositivo = linea.strip()
            nombre_dispositivo = info_dispositivo.split('ce:')[1]
            transporte = info_dispositivo.split('id:')
            dispositivos.append({
                'serial': info_dispositivo.split()[0],
                'nombre_dispositivo': nombre_dispositivo.split(' ')[0],
                'transporte': transporte[1]
            })

        print('Dispositivos disponibles:')
        for i, dispositivo in enumerate(dispositivos):
            print('%d)' % (i + 1), dispositivo['nombre_dispositivo'], '->', 'transport_id:', dispositivo['transporte'])

        while True:
            seleccion = input('Selecciona un dispositivo (1-%d): ' % len(dispositivos))
            try:
                indice = int(seleccion) - 1
                if 0 <= indice < len(dispositivos):
                    return dispositivos[indice]['transporte']
            except ValueError:
                pass
            print('Selección no válida.')
    else:
        print('No hay dispositivos conectados.')
        return 0

def listar_aplicaciones(palabra_clave, id_transporte):
    """Lista las aplicaciones instaladas en un dispositivo que coincidan con una palabra clave."""
    if id_transporte == 0:
        cmd = 'adb shell pm list packages'
    else:
        cmd = f'adb -t{id_transporte} shell pm list packages'

    try:
        resultado = subprocess.run(cmd, capture_output=True, text=True, shell=True)
        salida = resultado.stdout
        paquetes = []
        lineas = salida.strip().split('\n')
        
        for linea in lineas:
            if palabra_clave in linea:
                paquete = linea.split(':')[1]
                paquetes.append(paquete.strip())

        if paquetes:
            print("[+] Paquetes encontrados:")
            for indice, aplicacion in enumerate(paquetes):
                print("{}) {}".format(indice + 1, aplicacion))

            while True:
                try:
                    opcion = int(input("Selecciona una opción: "))
                    if 1 <= opcion <= len(paquetes):
                        return paquetes[opcion - 1]
                except ValueError:
                    pass

                print("[-] Opción no válida. Intenta nuevamente.")
        else:
            print("[-] No se encontraron nombres de paquetes con la palabra clave proporcionada.")
            sys.exit(1)
    except subprocess.CalledProcessError as e:
        print("[-] Error al ejecutar el comando.")
        sys.exit(1)

def listar_apks(nombre_paquete, id_transporte):
    """Lista las APK instaladas en un dispositivo que coincidan con un nombre de paquete."""
    try:
        rutas_apk = []
        if id_transporte == 0:
            cmd = f'adb shell pm path {nombre_paquete}'
        else:
            cmd = f'adb -t{id_transporte} shell pm path {nombre_paquete}'

        resultado = subprocess.run(cmd, capture_output=True, text=True, shell=True)
        salida = resultado.stdout.strip()
        lineas = salida.split('\n')
        
        for linea in lineas:
            if 'package:' in linea:
                ruta_apk = linea.split(':')[1].strip()
                rutas_apk.append(ruta_apk)

        if rutas_apk:
            print("[+] APKs encontradas:")
            for ruta_apk in rutas_apk:
                print(ruta_apk)
            return rutas_apk
        else:
            print("[-] No se encontraron APKs para el paquete especificado.")
            sys.exit(1)
    except subprocess.CalledProcessError as e:
        print("[-] Error al ejecutar el comando.")
        sys.exit(1)

def extraer_apks(rutas_apk):
    """Extrae las APKs en el directorio actual."""
    try:
        for ruta in rutas_apk:
            nombre_archivo = ruta.split('/')[-1]
            cmd = f'adb pull {ruta} {nombre_archivo}'
            subprocess.run(cmd, shell=True, check=True)
        print("[+] Todos los archivos APK extraídos correctamente.")
    except subprocess.CalledProcessError as e:
        print("[-] Error al extraer las APKs.")
        sys.exit(1)

def instalar_apk(ruta_apk, id_transporte):
    """Instala un APK en el dispositivo seleccionado."""
    if id_transporte == 0:
        cmd = f'adb install {ruta_apk}'
    else:
        cmd = f'adb -t{id_transporte} install {ruta_apk}'

    try:
        subprocess.run(cmd, shell=True, check=True)
        print("[+] APK instalado correctamente.")
    except subprocess.CalledProcessError as e:
        print("[-] Error al instalar el APK.")
        sys.exit(1)

def descompilar(ruta_archivo):
    apktool = CONFIG["apktool"]["path"]
    if os.path.isfile(ruta_archivo) and ruta_archivo.endswith('.apk'):
        carp_desc = ruta_archivo.replace('.apk', '')
        cmd = ['java', '-jar', apktool, 'd', ruta_archivo, '-o', carp_desc]
        subprocess.run(cmd)
        print(f'Archivo descompilado en: {carp_desc}')
    else:
        print('Error: Solo se admite archivos con extensión .apk')

def compilar(ruta_archivo):
    apktool = CONFIG["apktool"]["path"]
    carp_desc = ruta_archivo.replace('.apk', '')
    if os.path.isdir(carp_desc):
        nombre_archivo = os.path.basename(ruta_archivo)
        new_nombre_archivo = 'new_' + nombre_archivo
        ruta_archivo2 = ruta_archivo.replace(nombre_archivo, new_nombre_archivo)

        cmd = ['java', '-jar', apktool, 'b', carp_desc, '-o', ruta_archivo2]
        subprocess.run(cmd)
        print(f'Archivo compilado en: {ruta_archivo2}')
    else:
        print('Error: No se encuentra la carpeta')

def dex2jar(archivo):
    dex2jar_cmd = CONFIG["dex2jar"]["path"]
    extension = os.path.splitext(archivo)[1]

    if extension in ['.dex', '.apk']:
        new_archivo = archivo.replace(extension, '.jar')
        cmd = [dex2jar_cmd, archivo, '-o', new_archivo]
        subprocess.run(cmd)
        print(f'Archivo JAR creado en: {new_archivo}')
    else:
        print('Error: Solo se admite archivos con extensión .apk o .dex')

def jar2dex(archivo):
    jar2dex_cmd = CONFIG["dex2jar"]["path"]

    if archivo.endswith('.jar'):
        new_archivo = archivo.replace('.jar', '.dex')
        cmd = [jar2dex_cmd, archivo, '-o', new_archivo]
        subprocess.run(cmd)
        print(f'Archivo DEX creado en: {new_archivo}')
    else:
        print('Error: Solo se admite archivos con extensión .jar')

def firmar(archivo):
    uberapksigner = CONFIG["uberapksigner"]["path"]
    if os.path.isfile(archivo) and archivo.endswith('.apk'):
        carp_desc = archivo.replace('.apk', '')  # Ruta sin extensión
        cmd = ['java', '-jar', uberapksigner, '-a', archivo, '-o', carp_desc]
        subprocess.run(cmd)
        print(f'Archivo firmado en: {carp_desc}')
    else:
        print('Error: Solo se admite archivos con extensión .apk')

def main():
    verificar_herramientas()
    
    while True:
        print("\nOpciones:")
        print("1. Seleccionar dispositivo")
        print("2. Listar aplicaciones")
        print("3. Extraer APKs")
        print("4. Instalar APK")
        print("5. Descompilar APK")
        print("6. Compilar APK")
        print("7. Convertir DEX a JAR")
        print("8. Convertir JAR a DEX")
        print("9. Firmar APK")
        print("0. Salir")

        opcion = input("Selecciona una opción: ")

        if opcion == '1':
            seleccionar_dispositivo()
        elif opcion == '2':
            palabra_clave = input("Ingresa una palabra clave para buscar aplicaciones: ")
            id_transporte = seleccionar_dispositivo()
            nombre_paquete = listar_aplicaciones(palabra_clave, id_transporte)
        elif opcion == '3':
            id_transporte = seleccionar_dispositivo()
            palabra_clave = input("Ingresa una palabra clave para buscar aplicaciones: ")
            nombre_paquete = listar_aplicaciones(palabra_clave, id_transporte)
            rutas_apk = listar_apks(nombre_paquete, id_transporte)
            extraer_apks(rutas_apk)
        elif opcion == '4':
            ruta_apk = input("Introduce la ruta del archivo APK a instalar: ")
            id_transporte = seleccionar_dispositivo()
            instalar_apk(ruta_apk, id_transporte)
        elif opcion == '5':
            ruta_archivo = input("Introduce la ruta del archivo APK: ")
            descompilar(ruta_archivo)
        elif opcion == '6':
            ruta_archivo = input("Introduce la ruta del archivo APK: ")
            compilar(ruta_archivo)
        elif opcion == '7':
            archivo = input("Introduce la ruta del archivo DEX o APK: ")
            dex2jar(archivo)
        elif opcion == '8':
            archivo = input("Introduce la ruta del archivo JAR: ")
            jar2dex(archivo)
        elif opcion == '9':
            archivo = input("Introduce la ruta del archivo APK: ")
            firmar(archivo)
        elif opcion == '0':
            print("Saliendo...")
            break
        else:
            print("Opción no válida. Intenta de nuevo.")

if __name__ == '__main__':
    main()