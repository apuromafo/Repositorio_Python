import os
import subprocess
import sys
import urllib.request
import zipfile
import json
from datetime import datetime



# --- Configuración de las herramientas ---
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


# --- Funciones de Gestión de Herramientas ---
def verificar_herramientas():
    if os.path.isfile(LOCK_FILE):
        print("Las herramientas ya están instaladas y configuradas. No es necesario descargar nuevamente.")
        return

    for tool in CONFIG['tools']:
        tool_name = tool['name']
        tool_path = tool['fileName']

        if not os.path.isfile(tool_path):
            print(f"Descargando {tool_name}...")
            descargar_herramienta(tool)
        elif tool['zipped']:
            if not os.path.isdir(tool['unzipDir']):
                print(f"Descomprimiendo {tool_name}...")
                descargar_herramienta(tool)
            else:
                missing_files = [
                    required_file for required_file in tool.get('requiredFiles', [])
                    if not os.path.isfile(os.path.join(tool['unzipDir'], required_file))
                ]
                if missing_files:
                    print(f"Descomprimiendo {tool_name} porque faltan archivos requeridos: {', '.join(missing_files)}...")
                    descargar_herramienta(tool)
                else:
                    print(f"{tool_name} ya está instalado y configurado correctamente.")
        else:
            print(f"{tool_name} ya está instalado y configurado correctamente.")

    with open(LOCK_FILE, 'w') as f:
        f.write("Lock file to indicate that tools are installed.")

def descargar_herramienta(tool):
    url = tool['downloadUrl']
    path = tool['fileName']

    os.makedirs(os.path.dirname(path), exist_ok=True)

    try:
        if tool['zipped']:
            zip_path = path
            print(f"Descargando {tool['name']} desde {url} a {zip_path}...")
            urllib.request.urlretrieve(url, zip_path)
            print(f"Descomprimiendo {tool['name']} en {os.path.dirname(path)}...")
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(os.path.dirname(path))
            os.remove(zip_path)
            print(f"{tool['name']} descargado y extraído correctamente.")
        else:
            print(f"Descargando {tool['name']} desde {url} a {path}...")
            urllib.request.urlretrieve(url, path)
            print(f"{tool['name']} descargado correctamente.")
    except Exception as e:
        print(f"[-] Error al descargar {tool['name']}: {e}")
        sys.exit(1)


# --- Funciones ADB ---
def ejecutar_comando_adb(comando_args, selector_dispositivo=None):
    """
    Ejecuta un comando ADB de forma segura y devuelve su salida.
    Usa el selector de dispositivo (serial) cuando sea necesario.
    """
    cmd_prefix = ['adb']
    if selector_dispositivo:
        cmd_prefix.extend(['-s', selector_dispositivo])

    full_cmd = cmd_prefix + comando_args
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
    """
    Selecciona un dispositivo conectado a la computadora.
    """
    print("\n--- Selección de Dispositivo ---")
    
    try:
        resultado = subprocess.run(['adb', 'devices', '-l'], capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"[-] Error al ejecutar 'adb devices -l': {e}")
        print(f"    Salida de error: {e.stderr}")
        sys.exit(1)
    except FileNotFoundError:
        print("[-] Error: 'adb' no se encontró. Asegúrate de que Android SDK Platform-Tools esté instalado y en tu PATH.")
        sys.exit(1)

    dispositivos = []
    lineas = resultado.stdout.strip().split('\n')
    if len(lineas) > 0 and 'List of devices attached' in lineas[0]:
        lineas = lineas[1:]
    
    active_device_lines = []
    for linea in lineas:
        if "device" in linea and "offline" not in linea and linea.strip():
            active_device_lines.append(linea)

    if not active_device_lines:
        print("[-] No se encontraron dispositivos activos. Asegúrate de que tu dispositivo esté conectado, online y autorizado.")
        sys.exit(1)

    for linea in active_device_lines:
        parts = linea.strip().split()
        serial = parts[0]
        device_name_parts = [p.split(':')[1] for p in parts if p.startswith('model:')]
        device_name = device_name_parts[0] if device_name_parts else 'Unknown Device'

        dispositivos.append({
            'serial': serial,
            'nombre_dispositivo': device_name,
        })

    selector_final = None
    if len(dispositivos) == 1:
        selector_final = dispositivos[0]['serial']
        print(f"[*] Solo hay un dispositivo conectado: {dispositivos[0]['nombre_dispositivo']} (Serial: {selector_final})")
    else:
        print('Dispositivos disponibles:')
        for i, dispositivo in enumerate(dispositivos):
            print(f"{i+1}) {dispositivo['nombre_dispositivo']} (Serial: {dispositivo['serial']})")

        while True:
            seleccion = input(f'Selecciona un dispositivo (1-{len(dispositivos)}): ')
            try:
                indice = int(seleccion) - 1
                if 0 <= indice < len(dispositivos):
                    selector_final = dispositivos[indice]['serial']
                    break
            except ValueError:
                pass
            print('Selección no válida.')

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
            print(f"[-] No se pudo obtener toda la información del dispositivo: {e}. Continuando.")
    
    return selector_final

def listar_aplicaciones(palabra_clave, selector_dispositivo, solo_terceros=False):
    """
    Lista las aplicaciones instaladas en un dispositivo que coincidan con una palabra clave.
    Permite filtrar solo aplicaciones de terceros.
    """
    print("\n--- Listado de Aplicaciones ---")
    command_args = ['shell', 'pm', 'list', 'packages']
    if solo_terceros:
        command_args.append('-3')

    salida = ejecutar_comando_adb(command_args, selector_dispositivo)

    paquetes = []
    for linea in salida.strip().split('\n'):
        if 'package:' in linea:
            package_name = linea.split(':')[1].strip()
            if palabra_clave.lower() in package_name.lower():
                paquetes.append(package_name)

    if paquetes:
        print(f"[+] Paquetes encontrados (filtrados por '{palabra_clave}' y {'solo de terceros' if solo_terceros else 'todos'}):")
        for indice, aplicacion in enumerate(paquetes):
            print(f"{indice+1}) {aplicacion}")

        while True:
            try:
                opcion = input("Selecciona un número de paquete para continuar (o '0' para volver): ")
                if opcion == '0':
                    return None
                indice = int(opcion) - 1
                if 0 <= indice < len(paquetes):
                    return paquetes[indice]
            except ValueError:
                pass
            print("[-] Opción no válida. Intenta nuevamente.")
    else:
        print(f"[-] No se encontraron nombres de paquetes que contengan '{palabra_clave}'.")
        return None

def listar_apks(nombre_paquete, selector_dispositivo):
    """Lista las rutas de las APKs instaladas para un nombre de paquete específico."""
    print("\n--- Listado de Rutas APK ---")
    rutas_apk = []
    salida = ejecutar_comando_adb(['shell', 'pm', 'path', nombre_paquete], selector_dispositivo)

    for linea in salida.strip().split('\n'):
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
    """Extrae las APKs en una subcarpeta del directorio actual con el nombre del paquete."""
    print("\n--- Extracción de APKs ---")
    current_dir = os.getcwd()
    
    output_dir = os.path.join(current_dir, f"APKs_{nombre_paquete}")
    os.makedirs(output_dir, exist_ok=True)
    print(f"[*] Las APKs se guardarán en el directorio: {output_dir}")

    for i, ruta in enumerate(rutas_apk):
        original_filename = os.path.basename(ruta)
        output_filepath = os.path.join(output_dir, original_filename)

        print(f"[*] Extrayendo {i+1}/{len(rutas_apk)}: '{original_filename}' desde '{ruta}'...")
        
        ejecutar_comando_adb(['pull', ruta, output_filepath], selector_dispositivo)
        
        print(f"[+] '{output_filepath}' extraído correctamente.")
    print("\n[+] ¡Todos los archivos APK han sido extraídos exitosamente!")

def instalar_apk(ruta_apk, selector_dispositivo):
    """Instala un APK en el dispositivo seleccionado."""
    print("\n--- Instalación de APK ---")
    ejecutar_comando_adb(['install', ruta_apk], selector_dispositivo)
    print("[+] APK instalado correctamente.")


# --- Funciones de Descompilación/Compilación/Conversión/Firma ---
def seleccionar_opciones_jadx():
    opciones = {
        '1': '--no-src',
        '2': '--no-res',
        '3': '--deobf',
        '4': '--no-imports',
        '5': '--no-debug-info',
        '6': '--show-bad-code'
    }

    seleccionadas = []
    print("\nSelecciona las opciones de descompilación con JADX (puedes elegir varias, separadas por comas):")
    for key, value in opciones.items():
        print(f"{key}. {value}")

    eleccion = input("Ingresa los números de las opciones elegidas (ejemplo: 1,2,3): ")
    for num in eleccion.split(','):
        num = num.strip()
        if num in opciones:
            seleccionadas.append(opciones[num])
    
    return seleccionadas

def descompilar_apk_jadx(ruta_archivo):
    """Descompila un APK usando JADX."""
    print("\n--- Descompilación con JADX ---")
    if not os.path.isfile(ruta_archivo) or not ruta_archivo.endswith('.apk'):
        print('[-] Error: Solo se admite archivos con extensión .apk')
        return

    output_dir = os.path.join(os.path.dirname(ruta_archivo), os.path.basename(ruta_archivo).replace('.apk', '') + "_jadx_output")
    os.makedirs(output_dir, exist_ok=True)

    jadx_cmd_path = os.path.abspath(os.path.join(CONFIG['tools'][3]['unzipDir'], 'bin'))
    
    if sys.platform == 'win32':
        jadx_exec = os.path.join(jadx_cmd_path, 'jadx.bat')
    else:
        jadx_exec = os.path.join(jadx_cmd_path, 'jadx')

    if not os.path.isfile(jadx_exec):
        print(f"[-] El ejecutable de JADX no se encontró en: {jadx_exec}")
        print("    Asegúrate de que JADX esté correctamente descargado y extraído, y que el script esté en el PATH correcto.")
        return

    opciones_seleccionadas = seleccionar_opciones_jadx()
    command = [jadx_exec, ruta_archivo, '--output-dir', output_dir] + opciones_seleccionadas
    print(f"Comando a ejecutar: {' '.join(command)}")

    try:
        subprocess.run(command, check=True)
        print(f'[+] Descompilación completada para: {ruta_archivo}. Salida en: {output_dir}')
    except subprocess.CalledProcessError as e:
        print(f"[-] Error al descompilar el APK con JADX. Código de salida: {e.returncode}")
        print(f"    Salida de error: {e.stderr}")
    except FileNotFoundError:
        print("[-] Error de ruta: Asegúrate de que el ejecutable de JADX es accesible.")

def seleccionar_opciones_apktool():
    opciones = {
        '1': '-s',
        '2': '-r',
        '3': '--only-main-classes',
        '4': '--no-debug-info'
    }

    seleccionadas = []
    print("\nSelecciona las opciones de descompilación con ApkTool (puedes elegir varias, separadas por comas):")
    for key, value in opciones.items():
        print(f"{key}. {value}")

    eleccion = input("Ingresa los números de las opciones elegidas (ejemplo: 1,2): ")
    for num in eleccion.split(','):
        num = num.strip()
        if num in opciones:
            seleccionadas.append(opciones[num])
    
    return seleccionadas

def descompilar_apktool(ruta_archivo):
    """Descompila un APK usando ApkTool."""
    print("\n--- Descompilación con ApkTool ---")
    if not os.path.isfile(ruta_archivo) or not ruta_archivo.endswith('.apk'):
        print('[-] Error: Solo se admite archivos con extensión .apk')
        return

    opciones_usuario = seleccionar_opciones_apktool()

    sufijo_opciones = '_'.join([op.replace('-', '') for op in opciones_usuario]).replace(' ', '_')
    if sufijo_opciones:
        output_dir = os.path.join(os.path.dirname(ruta_archivo), os.path.basename(ruta_archivo).replace('.apk', '') + f"_apktool_output_{sufijo_opciones}")
    else:
        output_dir = os.path.join(os.path.dirname(ruta_archivo), os.path.basename(ruta_archivo).replace('.apk', '') + "_apktool_output")
    
    os.makedirs(output_dir, exist_ok=True)

    apktool_jar = CONFIG['tools'][0]['fileName']

    if not os.path.isfile(apktool_jar):
        print(f"[-] El archivo apktool.jar no se encontró en: {apktool_jar}")
        print("    Asegúrate de que ApkTool esté correctamente descargado.")
        return

    command = ['java', '-jar', apktool_jar, 'd', ruta_archivo, '-o', output_dir, '-f'] + opciones_usuario
    print(f"Comando a ejecutar: {' '.join(command)}")

    try:
        subprocess.run(command, check=True)
        print(f'[+] Descompilación completada para: {ruta_archivo}. Salida en: {output_dir}')
    except subprocess.CalledProcessError as e:
        print(f"[-] Error al descompilar el APK con ApkTool. Código de salida: {e.returncode}")
        print(f"    Salida de error: {e.stderr}")
    except FileNotFoundError:
        print("[-] Error: 'java' no se encontró. Asegúrate de tener Java JRE/JDK instalado y en tu PATH.")

def compilar(carpeta_descompilada):
    """Compila una carpeta descompilada usando ApkTool."""
    print("\n--- Compilación con ApkTool ---")
    if not os.path.isdir(carpeta_descompilada):
        print(f"[-] Error: La ruta proporcionada no es un directorio válido: {carpeta_descompilada}")
        return

    apktool_jar = CONFIG['tools'][0]['fileName']
    
    if not os.path.isfile(apktool_jar):
        print(f"[-] El archivo apktool.jar no se encontró en: {apktool_jar}")
        print("    Asegúrate de que ApkTool esté correctamente descargado.")
        return

    fecha_actual = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    base_name = os.path.basename(carpeta_descompilada)
    nuevo_nombre_apk = f"{base_name}_recompiled_{fecha_actual}.apk"
    
    ruta_archivo_apk = os.path.join(os.path.dirname(carpeta_descompilada), nuevo_nombre_apk)

    cmd = ['java', '-jar', apktool_jar, 'b', carpeta_descompilada, '-o', ruta_archivo_apk]
    print(f"Comando a ejecutar: {' '.join(cmd)}")

    try:
        subprocess.run(cmd, check=True)
        print(f'[+] Archivo compilado exitosamente en: {ruta_archivo_apk}')
    except subprocess.CalledProcessError as e:
        print(f"[-] Error al compilar el APK. Código de salida: {e.returncode}")
        print(f"    Salida de error: {e.stderr}")
    except FileNotFoundError:
        print("[-] Error: 'java' no se encontró. Asegúrate de tener Java JRE/JDK instalado y en tu PATH.")

def dex2jar(archivo):
    """Convierte archivos .dex o .apk a .jar usando dex2jar."""
    print("\n--- Conversión DEX/APK a JAR (dex2jar) ---")
    if not os.path.isfile(archivo):
        print(f"[-] Error: Archivo no encontrado en la ruta: {archivo}")
        return
    
    extension = os.path.splitext(archivo)[1].lower()

    if extension not in ['.dex', '.apk']:
        print('[-] Error: Solo se admite archivos con extensión .apk o .dex para dex2jar.')
        return

    dex2jar_dir = CONFIG["tools"][1]["unzipDir"]
    if sys.platform == 'win32':
        dex2jar_exec = os.path.join(dex2jar_dir, 'd2j-dex2jar.bat')
    else:
        dex2jar_exec = os.path.join(dex2jar_dir, 'd2j-dex2jar.sh')
    
    if not os.path.isfile(dex2jar_exec):
        print(f"[-] El ejecutable de dex2jar no se encontró en: {dex2jar_exec}")
        print("    Asegúrate de que dex2jar esté correctamente descargado y extraído.")
        return

    output_dir = os.path.dirname(archivo)
    new_archivo = os.path.join(output_dir, os.path.basename(archivo).replace(extension, '.jar'))
    
    cmd = [dex2jar_exec, archivo, '-o', new_archivo]
    print(f"Comando a ejecutar: {' '.join(cmd)}")

    try:
        subprocess.run(cmd, check=True)
        print(f'[+] Archivo JAR creado exitosamente en: {new_archivo}')
    except subprocess.CalledProcessError as e:
        print(f"[-] Error al convertir a JAR. Código de salida: {e.returncode}")
        print(f"    Salida de error: {e.stderr}")
    except FileNotFoundError:
        print("[-] Error: El script de dex2jar no se encontró o no es ejecutable.")

def jar2dex(archivo):
    """Convierte archivos .jar a .dex usando dex2jar."""
    print("\n--- Conversión JAR a DEX (dex2jar) ---")
    if not os.path.isfile(archivo):
        print(f"[-] Error: Archivo no encontrado en la ruta: {archivo}")
        return

    if not archivo.lower().endswith('.jar'):
        print('[-] Error: Solo se admite archivos con extensión .jar para jar2dex.')
        return

    dex2jar_dir = CONFIG["tools"][1]["unzipDir"]
    if sys.platform == 'win32':
        jar2dex_exec = os.path.join(dex2jar_dir, 'd2j-jar2dex.bat')
    else:
        jar2dex_exec = os.path.join(dex2jar_dir, 'd2j-jar2dex.sh')

    if not os.path.isfile(jar2dex_exec):
        print(f"[-] El ejecutable de jar2dex no se encontró en: {jar2dex_exec}")
        print("    Asegúrate de que dex2jar esté correctamente descargado y extraído.")
        return

    output_dir = os.path.dirname(archivo)
    new_archivo = os.path.join(output_dir, os.path.basename(archivo).replace('.jar', '.dex'))
    
    cmd = [jar2dex_exec, archivo, '-o', new_archivo]
    print(f"Comando a ejecutar: {' '.join(cmd)}")

    try:
        subprocess.run(cmd, check=True)
        print(f'[+] Archivo DEX creado exitosamente en: {new_archivo}')
    except subprocess.CalledProcessError as e:
        print(f"[-] Error al convertir a DEX. Código de salida: {e.returncode}")
        print(f"    Salida de error: {e.stderr}")
    except FileNotFoundError:
        print("[-] Error: El script de jar2dex no se encontró o no es ejecutable.")

def firmar(archivo):
    """Firma un APK usando uber-apk-signer."""
    print("\n--- Firma de APK (uber-apk-signer) ---")
    if not os.path.isfile(archivo) or not archivo.lower().endswith('.apk'):
        print('[-] Error: Solo se admite archivos con extensión .apk')
        return

    uberapksigner_jar = CONFIG["tools"][2]["fileName"]
    
    if not os.path.isfile(uberapksigner_jar):
        print(f"[-] El archivo uber-apk-signer.jar no se encontró en: {uberapksigner_jar}")
        print("    Asegúrate de que uber-apk-signer esté correctamente descargado.")
        return

    output_dir = os.path.join(os.path.dirname(archivo), "signed_apks")
    os.makedirs(output_dir, exist_ok=True)
    
    cmd = ['java', '-jar', uberapksigner_jar, '-a', archivo, '-o', output_dir]
    print(f"Comando a ejecutar: {' '.join(cmd)}")

    try:
        subprocess.run(cmd, check=True)
        print(f'[+] Archivo APK firmado exitosamente en: {output_dir}')
    except subprocess.CalledProcessError as e:
        print(f"[-] Error al firmar el APK. Código de salida: {e.returncode}")
        print(f"    Salida de error: {e.stderr}")
    except FileNotFoundError:
        print("[-] Error: 'java' no se encontró. Asegúrate de tener Java JRE/JDK instalado y en tu PATH.")


# --- Funciones de Wrapper para el Menú ---
global_selector_dispositivo = None # Variable global para almacenar el dispositivo seleccionado

def get_current_device_selector():
    global global_selector_dispositivo
    if global_selector_dispositivo is None:
        print("\n[!] No hay un dispositivo seleccionado actualmente. Por favor, selecciona uno primero.")
        global_selector_dispositivo = seleccionar_dispositivo()
    return global_selector_dispositivo

def seleccionar_dispositivo_accion():
    """Acción del menú para seleccionar un dispositivo."""
    global global_selector_dispositivo
    global_selector_dispositivo = seleccionar_dispositivo()
    if global_selector_dispositivo:
        print(f"\n[*] Dispositivo '{global_selector_dispositivo}' seleccionado y listo para usar.")
    else:
        print("\n[-] No se pudo seleccionar un dispositivo.")

def listar_aplicaciones_usuario_accion():
    selector = get_current_device_selector()
    if not selector: return

    choice = input("¿Listar solo aplicaciones de terceros (usuario)? (s/N): ").strip().lower()
    solo_terceros = (choice == 's')

    palabra_clave = input("Ingresa una palabra clave para buscar aplicaciones (deja en blanco para ver todas): ")
    
    paquete_seleccionado = listar_aplicaciones(palabra_clave, selector, solo_terceros=solo_terceros)
    if paquete_seleccionado:
        print(f"[*] Seleccionaste: {paquete_seleccionado}")
    else:
        print("[*] No se seleccionó ningún paquete.")

def extraer_apks_usuario_accion():
    selector = get_current_device_selector()
    if not selector: return

    choice = input("¿Listar solo aplicaciones de terceros (usuario) para extraer? (s/N): ").strip().lower()
    solo_terceros_para_extraccion = (choice == 's')

    palabra_clave = input("Ingresa una palabra clave para buscar la aplicación a extraer (deja en blanco para ver todas): ")
    
    nombre_paquete = listar_aplicaciones(palabra_clave, selector, solo_terceros=solo_terceros_para_extraccion) 
    
    if nombre_paquete:
        rutas_apk = listar_apks(nombre_paquete, selector)
        extraer_apks(rutas_apk, nombre_paquete, selector)
    else:
        print("[-] Extracción cancelada: No se seleccionó un paquete válido.")

def instalar_apk_usuario_accion():
    selector = get_current_device_selector()
    if not selector: return

    ruta_apk = input("Introduce la ruta completa del archivo APK a instalar: ")
    if not os.path.isfile(ruta_apk) or not ruta_apk.lower().endswith('.apk'):
        print(f"[-] Error: '{ruta_apk}' no es un archivo APK válido o no existe.")
        return
    instalar_apk(ruta_apk, selector)

def descompilar_apktool_usuario_accion():
    ruta_archivo = input("Introduce la ruta completa del archivo APK a descompilar con ApkTool: ")
    descompilar_apktool(ruta_archivo)
    
def compilar_apk_usuario_accion():
    carpeta_descompilada = input("Introduce la ruta completa de la carpeta descompilada con ApkTool: ")
    compilar(carpeta_descompilada)

def dex2jar_usuario_accion():
    archivo = input("Introduce la ruta completa del archivo DEX o APK a convertir a JAR: ")
    dex2jar(archivo)

def jar2dex_usuario_accion():
    archivo = input("Introduce la ruta completa del archivo JAR a convertir a DEX: ")
    jar2dex(archivo)

def firmar_usuario_accion():
    archivo = input("Introduce la ruta completa del archivo APK a firmar: ")
    firmar(archivo)

def descompilar_apk_jadx_usuario_accion():
    ruta_archivo = input("Introduce la ruta completa del archivo APK para descompilar usando Jadx: ")
    descompilar_apk_jadx(ruta_archivo)

def salir():
    print("Saliendo del programa. ¡Hasta luego!")
    sys.exit(0)


# --- Menú Principal ---
def menu():
    opciones = {
        '1': seleccionar_dispositivo_accion,
        '2': listar_aplicaciones_usuario_accion,
        '3': extraer_apks_usuario_accion,
        '4': instalar_apk_usuario_accion,
        '5': descompilar_apktool_usuario_accion,
        '6': compilar_apk_usuario_accion,
        '7': dex2jar_usuario_accion,
        '8': jar2dex_usuario_accion,
        '9': firmar_usuario_accion,
        '10': descompilar_apk_jadx_usuario_accion,
        '0': salir
    }

    while True:
        print("\n" + "="*40)
        print(" Kit Herramienta para Android")
        print("="*40)
        print("Opciones:")
        print("  1. Seleccionar o Re-seleccionar Dispositivo ADB")
        print("  2. Listar Aplicaciones (Todas o Solo de Usuario)")
        print("  3. Extraer APKs de un Dispositivo")
        print("  4. Instalar APK en el Dispositivo")
        print("  5. Descompilar APK con ApkTool")
        print("  6. Compilar APK con ApkTool")
        print("  7. Convertir DEX/APK a JAR (dex2jar)")
        print("  8. Convertir JAR a DEX (dex2jar)")
        print("  9. Firmar APK (uber-apk-signer)")
        print(" 10. Descompilar APK con JADX")
        print("  0. Salir")
        print("="*40)

        opcion = input("Selecciona una opción: ").strip()

        funcion = opciones.get(opcion)
        if funcion:
            funcion()
        else:
            print("[-] Opción no válida. Por favor, selecciona un número del menú.")

def main():
    print("--- Inicializando Herramienta... ---")
    verificar_herramientas()
    menu()

if __name__ == '__main__':
    main()