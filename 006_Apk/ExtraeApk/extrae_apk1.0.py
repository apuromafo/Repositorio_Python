import sys
import subprocess

# Funciones
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
            print('%d)' % (i+1), dispositivo['nombre_dispositivo'], '->', 'transport_id:', dispositivo['transporte'])

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
        print('Solo hay un dispositivo conectado')
        return 0

def listar_aplicaciones(palabra_clave, id_transporte):
    """Lista las aplicaciones instaladas en un dispositivo que coincidan con una palabra clave."""

    if id_transporte == 0:
        cmd = f'adb shell pm list packages'
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
            print("[+] Paquetes encontrados!!!")
            print("[*] Selecciona un nombre de paquete:")
            for indice, aplicacion in enumerate(paquetes):
                print("{}) {}".format(indice+1, aplicacion))

            while True:
                try:
                    opcion = int(input("Selecciona una opción: "))
                    if 1 <= opcion <= len(paquetes):
                        return paquetes[opcion-1]
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
 
def main():
    palabra_clave = input("Ingresa una palabra clave para buscar aplicaciones: ")
    id_transporte = seleccionar_dispositivo()
    nombre_paquete = listar_aplicaciones(palabra_clave, id_transporte)
    rutas_apk = listar_apks(nombre_paquete, id_transporte)
    extraer_apks(rutas_apk)

if __name__ == "__main__":
    main() 
