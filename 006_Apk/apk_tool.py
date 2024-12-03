import os
import subprocess
import sys
import urllib.request
import zipfile
import json

# Configuración de las herramientas
CONFIG_JSON = """
{
  "tools": [
    {
      "name": "apktool",
      "version": "2.10.0",
      "downloadUrl": "https://github.com/iBotPeaches/Apktool/releases/download/v2.10.0/apktool_2.10.0.jar",
      "fileName": "herramientas/apktool/apktool.jar",
      "configName": "apktoolPath",
      "zipped": false
    },
    {
      "name": "dex2jar",
      "version": "2.4",
      "downloadUrl": "https://github.com/pxb1988/dex2jar/releases/download/v2.4/dex-tools-v2.4.zip",
      "fileName": "herramientas/dex-tools-v2.4.zip",
      "configName": "dex2jarPath",
      "zipped": true,
      "unzipDir": "herramientas/dex-tools-v2.4",
      "requiredFiles": ["d2j-dex2jar.sh", "d2j-jar2dex.sh", "d2j-dex2jar.bat", "d2j-jar2dex.bat"]
    },
    {
      "name": "uber-apk-signer",
      "version": "1.3.0",
      "downloadUrl": "https://github.com/patrickfav/uber-apk-signer/releases/download/v1.3.0/uber-apk-signer-1.3.0.jar",
      "fileName": "herramientas/uber-apk-signer/uber-apk-signer.jar",
      "configName": "apkSignerPath",
      "zipped": false
    },
    {
      "name": "jadx",
      "version": "1.4.7",
      "downloadUrl": "https://github.com/skylot/jadx/releases/download/v1.4.7/jadx-1.4.7.zip",
      "fileName": "herramientas/jadx/jadx-1.4.7.zip",
      "configName": "jadxDirPath",
      "zipped": true,
      "unzipDir": "herramientas/jadx"
    }
  ]
}
"""

CONFIG = json.loads(CONFIG_JSON)
LOCK_FILE = 'herramientas/lock.txt'

def verificar_herramientas():
    if os.path.isfile(LOCK_FILE):
        print("Las herramientas ya están instaladas y configuradas. No es necesario descargar nuevamente.")
        return

    for tool in CONFIG['tools']:
        tool_name = tool['name']
        tool_path = tool['fileName']

        # Verificar si el archivo de la herramienta ya existe
        if not os.path.isfile(tool_path):
            print(f"Descargando {tool_name}...")
            descargar_herramienta(tool)
        elif tool['zipped']:
            # Verificar si la carpeta descomprimida existe
            if not os.path.isdir(tool['unzipDir']):
                print(f"Descomprimiendo {tool_name}...")
                descargar_herramienta(tool)
            else:
                # Verificar que todos los archivos requeridos existan
                missing_files = [required_file for required_file in tool.get('requiredFiles', []) if not os.path.isfile(os.path.join(tool['unzipDir'], required_file))]
                if missing_files:
                    print(f"Descomprimiendo {tool_name} porque faltan archivos requeridos: {', '.join(missing_files)}...")
                    descargar_herramienta(tool)
                else:
                    print(f"{tool_name} ya está instalado y configurado correctamente.")

    # Crear archivo de bloqueo
    with open(LOCK_FILE, 'w') as f:
        f.write("Lock file to indicate that tools are installed.")

def descargar_herramienta(tool):
    url = tool['downloadUrl']
    path = tool['fileName']

    # Crea la carpeta si no existe
    os.makedirs(os.path.dirname(path), exist_ok=True)

    try:
        if tool['zipped']:
            zip_path = path
            urllib.request.urlretrieve(url, zip_path)
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(os.path.dirname(path))
            os.remove(zip_path)
            print(f"{tool['name']} descargado y extraído.")
        else:
            urllib.request.urlretrieve(url, path)
            print(f"{tool['name']} descargado.")
    except Exception as e:
        print(f"[-] Error al descargar {tool['name']}: {e}")

def seleccionar_dispositivo():
    """Selecciona un dispositivo conectado a la computadora."""
    resultado = subprocess.run(['adb', 'devices', '-l'], capture_output=True, text=True)
    dispositivos = []
    lineas = resultado.stdout.strip().split('\n')[1:]

    if len(lineas) > 1:
        for linea in lineas:
            info_dispositivo = linea.strip()
            parts = info_dispositivo.split()
            if len(parts) > 1:
                dispositivos.append({
                    'serial': parts[0],
                    'nombre_dispositivo': ' '.join(parts[1:]),
                })

        print('Dispositivos disponibles:')
        for i, dispositivo in enumerate(dispositivos):
            print(f"{i + 1}) {dispositivo['nombre_dispositivo']} -> Serial: {dispositivo['serial']}")

        while True:
            seleccion = input(f'Selecciona un dispositivo (1-{len(dispositivos)}): ')
            try:
                indice = int(seleccion) - 1
                if 0 <= indice < len(dispositivos):
                    return dispositivos[indice]['serial']
            except ValueError:
                pass
            print('Selección no válida.')
    else:
        print('No hay dispositivos conectados.')
        return None

def listar_aplicaciones(palabra_clave, id_transporte):
    """Lista las aplicaciones instaladas en un dispositivo que coincidan con una palabra clave."""
    cmd = f'adb shell pm list packages | grep {palabra_clave}' if id_transporte is None else f'adb -s {id_transporte} shell pm list packages | grep {palabra_clave}'

    try:
        resultado = subprocess.run(cmd, capture_output=True, text=True, shell=True)
        salida = resultado.stdout.strip().split('\n')

        if salida:
            print("[+] Paquetes encontrados:")
            for indice, aplicacion in enumerate(salida):
                print(f"{indice + 1}) {aplicacion}")

            while True:
                try:
                    opcion = int(input("Selecciona una opción: "))
                    if 1 <= opcion <= len(salida):
                        return salida[opcion - 1]
                except ValueError:
                    pass

                print("[-] Opción no válida. Intenta nuevamente.")
        else:
            print("[-] No se encontraron aplicaciones con la palabra clave proporcionada.")
            sys.exit(1)
    except subprocess.CalledProcessError as e:
        print("[-] Error al ejecutar el comando.")
        sys.exit(1)

def listar_apks(nombre_paquete, id_transporte):
    """Lista las APK instaladas en un dispositivo que coincidan con un nombre de paquete."""
    cmd = f'adb shell pm path {nombre_paquete}' if id_transporte is None else f'adb -s {id_transporte} shell pm path {nombre_paquete}'

    try:
        resultado = subprocess.run(cmd, capture_output=True, text=True, shell=True)
        salida = resultado.stdout.strip().split('\n')

        rutas_apk = [linea.split(':')[1].strip() for linea in salida if 'package:' in linea]

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
            nombre_archivo = os.path.basename(ruta)
            cmd = f'adb pull {ruta} {nombre_archivo}'
            subprocess.run(cmd, shell=True, check=True)
        print("[+] Todos los archivos APK extraídos correctamente.")
    except subprocess.CalledProcessError as e:
        print("[-] Error al extraer las APKs.")
        sys.exit(1)

def instalar_apk(ruta_apk, id_transporte):
    """Instala un APK en el dispositivo seleccionado."""
    cmd = f'adb install {ruta_apk}' if id_transporte is None else f'adb -s {id_transporte} install {ruta_apk}'

    try:
        subprocess.run(cmd, shell=True, check=True)
        print("[+] APK instalado correctamente.")
    except subprocess.CalledProcessError as e:
        print("[-] Error al instalar el APK.")
        sys.exit(1)

def descompilar_apk(ruta_archivo):
    """Descompila un APK usando JADX."""
    if not os.path.isfile(ruta_archivo) or not ruta_archivo.endswith('.apk'):
        print('Error: Solo se admite archivos con extensión .apk')
        return

    opciones = seleccionar_opciones()

    # Crear un directorio de salida
    output_dir = os.path.join(os.path.dirname(ruta_archivo), os.path.basename(ruta_archivo) + "_output")
    os.makedirs(output_dir, exist_ok=True)

    # Usar os.path.join para crear la ruta del ejecutable de manera correcta
    jadx_cmd = os.path.join(os.getcwd(), CONFIG['tools'][3]['unzipDir'], 'bin', 'jadx.bat')

    # Asegúrate de que el archivo existe
    if not os.path.isfile(jadx_cmd):
        print(f"[-] El ejecutable de JADX no se encontró en: {jadx_cmd}")
        return

    # Filtrar las opciones para asegurarse de que sean válidas
    opciones_validas = ['--no-src', '--no-res', '--no-assets', '--no-debug-info', '--deobf', '--show-bad-code']
    opciones_filtradas = [opcion for opcion in opciones if opcion in opciones_validas]

    # Asegúrate de que las opciones se pasen correctamente
    command = [jadx_cmd, ruta_archivo, '--output-dir', output_dir] + opciones_filtradas
    print(f"Comando a ejecutar: {command}")

    try:
        # Ejecutar el comando
        subprocess.run(command, check=True)
        print(f'Descompilación completada para: {ruta_archivo}. Salida en: {output_dir}')
    except subprocess.CalledProcessError as e:
        print(f"[-] Error al descompilar el APK: {e}")
    except FileNotFoundError:
        print("[-] No se encontró el ejecutable de JADX. Asegúrate de que esté instalado correctamente.")
        
def seleccionar_opciones():
    opciones = {
        '1': '--no-src',
        '2': '--no-res',
        '3': '--no-assets',
        '4': '--only-main-classes',
        '5': '--no-debug-info',
        '6': '--deobf',
        '7': '--show-bad-code'
    }

    seleccionadas = []
    print("Selecciona las opciones de descompilación (puedes elegir varias, separadas por comas):")
    for key, value in opciones.items():
        print(f"{key}. {value}")

    eleccion = input("Ingresa los números de las opciones elegidas (ejemplo: 1,2,3): ")
    for num in eleccion.split(','):
        num = num.strip()
        if num in opciones:
            seleccionadas.append(opciones[num])
    
    return seleccionadas

def compilar(ruta_archivo):
    apktool = CONFIG['tools'][0]['fileName']
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
        
def seleccionar_opciones_descompilacion():
    opciones = {
        '1': '--no-src',
        '2': '--no-res',
        '3': '--only-main-classes',
        '4': '--no-debug-info',
        # Eliminar '--deobf' de la lista
    }

    seleccionadas = []
    print("Selecciona las opciones de descompilación (puedes elegir varias, separadas por comas):")
    for key, value in opciones.items():
        print(f"{key}. {value}")

    eleccion = input("Ingresa los números de las opciones elegidas (ejemplo: 1,2,3): ")
    for num in eleccion.split(','):
        num = num.strip()
        if num in opciones:
            seleccionadas.append(opciones[num])
    
    return seleccionadas

    
def descompilar_apktool(ruta_archivo):
    """Descompila un APK usando ApkTool."""
    if not os.path.isfile(ruta_archivo) or not ruta_archivo.endswith('.apk'):
        print('Error: Solo se admite archivos con extensión .apk')
        return

    # Obtener las opciones seleccionadas
    opciones_usuario = seleccionar_opciones_descompilacion()  # Llama a la función para seleccionar opciones

    # Crear un sufijo para las opciones seleccionadas
    sufijo_opciones = '_'.join(opciones_usuario).replace('--', '').replace(' ', '_')  # Eliminar '--' y reemplazar espacios por '_'

    # Generar el directorio de salida con el sufijo
    output_dir = os.path.join(os.path.dirname(ruta_archivo), os.path.basename(ruta_archivo) + f"_output_{sufijo_opciones}")
    os.makedirs(output_dir, exist_ok=True)

    apktool_cmd = CONFIG['tools'][0]['fileName']  # Ruta a apktool.jar


    # Seleccionar opciones
    opciones_usuario = seleccionar_opciones_descompilacion()  # Obtener opciones del usuario

    # Construir el comando
    command = ['java', '-jar', apktool_cmd, 'd', ruta_archivo,
               '-o', output_dir ,'-f' ] + opciones_usuario 

    print(f"Comando a ejecutar: {command}")

    try:
        subprocess.run(command, check=True)
        print(f'Descompilación completada para: {ruta_archivo}. Salida en: {output_dir}')
    except subprocess.CalledProcessError as e:
        print(f"[-] Error al descompilar el APK: {e}")
    except FileNotFoundError:
        print("[-] No se encontró el archivo ApkTool. Asegúrate de que esté instalado correctamente.")
        
def descompilar_apk_jadx(ruta_archivo):
    """Descompila un APK usando JADX."""
    if not os.path.isfile(ruta_archivo) or not ruta_archivo.endswith('.apk'):
        print('Error: Solo se admite archivos con extensión .apk')
        return

    # Crear un directorio de salida
    output_dir = os.path.join(os.path.dirname(ruta_archivo), os.path.basename(ruta_archivo) + "_jadx_output")
    os.makedirs(output_dir, exist_ok=True)

    # Ruta del ejecutable de JADX
    jadx_cmd = os.path.join(CONFIG['tools'][3]['unzipDir'], 'bin', 'jadx.bat')

    # Asegúrate de que el archivo existe
    if not os.path.isfile(jadx_cmd):
        print(f"[-] El ejecutable de JADX no se encontró en: {jadx_cmd}")
        return

    # Construir el comando de ejecución
    command = [jadx_cmd, ruta_archivo, '--output-dir', output_dir, '--deobf', '--show-bad-code']
    print(f"Comando a ejecutar: {command}")

    try:
        # Ejecutar el comando
        subprocess.run(command, check=True)
        print(f'Descompilación completada para: {ruta_archivo}. Salida en: {output_dir}')
    except subprocess.CalledProcessError as e:
        print(f"[-] Error al descompilar el APK con JADX: {e}")
    except FileNotFoundError:
        print("[-] No se encontró el ejecutable de JADX. Asegúrate de que esté instalado correctamente.")
        

def dex2jar(archivo):
    dex2jar_cmd = os.path.join(CONFIG["tools"][1]["fileName"].replace('.zip', ''), 'd2j-jar2dex' + ('.bat' if sys.platform == 'win32' else '.sh'))
    extension = os.path.splitext(archivo)[1]

    if extension in ['.dex', '.apk']:
        new_archivo = archivo.replace(extension, '.jar')
        cmd = [dex2jar_cmd, archivo, '-o', new_archivo]
        subprocess.run(cmd)
        print(f'Archivo JAR creado en: {new_archivo}')
    else:
        print('Error: Solo se admite archivos con extensión .apk o .dex')

def jar2dex(archivo):
    jar2dex_cmd = os.path.join(CONFIG["tools"][1]["fileName"].replace('.zip', ''), 'd2j-jar2dex' + ('.bat' if sys.platform == 'win32' else '.sh'))

    if archivo.endswith('.jar'):
        new_archivo = archivo.replace('.jar', '.dex')
        cmd = [jar2dex_cmd, archivo, '-o', new_archivo]
        subprocess.run(cmd)
        print(f'Archivo DEX creado en: {new_archivo}')
    else:
        print('Error: Solo se admite archivos con extensión .jar')

def firmar(archivo):
    uberapksigner = CONFIG["tools"][2]["fileName"]
    if os.path.isfile(archivo) and archivo.endswith('.apk'):
        carp_desc = archivo.replace('.apk', '')  # Ruta sin extensión
        cmd = ['java', '-jar', uberapksigner, '-a', archivo, '-o', carp_desc]
        subprocess.run(cmd)
        print(f'Archivo firmado en: {carp_desc}')
    else:
        print('Error: Solo se admite archivos con extensión .apk')

def menu():
    opciones = {
        '1': seleccionar_dispositivo,
        '2': listar_aplicaciones_usuario,
        '3': extraer_apks_usuario,
        '4': instalar_apk_usuario,
        '5': descompilar_apktool_usuario,
        '6': compilar_apk_usuario,
        '7': dex2jar_usuario,
        '8': jar2dex_usuario,
        '9': firmar_usuario,
        '10': descompilar_apk_jadx_usuario,
        '0': salir
    }

    while True:
        print("\nOpciones:")
        print("1. Seleccionar dispositivo")
        print("2. Listar aplicaciones")
        print("3. Extraer APKs")
        print("4. Instalar APK")
        print("5. Descompilar APK usando ApkTool")
        print("6. Compilar APK")
        print("7. Convertir DEX a JAR")
        print("8. Convertir JAR a DEX")
        print("9. Firmar APK")
        print("10. Descompilar APK usando Jadx")
        print("0. Salir")

        opcion = input("Selecciona una opción: ")

        # Ejecutar la función correspondiente si existe
        funcion = opciones.get(opcion)
        if funcion:
            funcion()
        else:
            print("Opción no válida. Intenta de nuevo.")

def listar_aplicaciones_usuario():
    palabra_clave = input("Ingresa una palabra clave para buscar aplicaciones: ")
    id_transporte = seleccionar_dispositivo()
    listar_aplicaciones(palabra_clave, id_transporte)

def extraer_apks_usuario():
    id_transporte = seleccionar_dispositivo()
    palabra_clave = input("Ingresa una palabra clave para buscar aplicaciones: ")
    nombre_paquete = listar_aplicaciones(palabra_clave, id_transporte)
    rutas_apk = listar_apks(nombre_paquete, id_transporte)
    extraer_apks(rutas_apk)

def instalar_apk_usuario():
    ruta_apk = input("Introduce la ruta del archivo APK a instalar: ")
    id_transporte = seleccionar_dispositivo()
    instalar_apk(ruta_apk, id_transporte)

def descompilar_apktool_usuario():
    ruta_archivo = input("Introduce la ruta del archivo APK: ")
    descompilar_apktool(ruta_archivo)

def compilar_apk_usuario():
    ruta_archivo = input("Introduce la ruta del archivo APK: ")
    compilar(ruta_archivo)

def dex2jar_usuario():
    archivo = input("Introduce la ruta del archivo DEX o APK: ")
    dex2jar(archivo)

def jar2dex_usuario():
    archivo = input("Introduce la ruta del archivo JAR: ")
    jar2dex(archivo)

def firmar_usuario():
    archivo = input("Introduce la ruta del archivo APK: ")
    firmar(archivo)

def descompilar_apk_jadx_usuario():
    ruta_archivo = input("Introduce la ruta del archivo APK para descompilar usando Jadx: ")
    descompilar_apk_jadx(ruta_archivo)

def salir():
    print("Saliendo...")
    sys.exit(0)

def main():
    verificar_herramientas()
    menu()

if __name__ == '__main__':
    main()