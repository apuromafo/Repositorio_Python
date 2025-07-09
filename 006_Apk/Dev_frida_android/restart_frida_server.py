import os
import subprocess

def is_frida_server_running(device):
    """Verifica si frida-server está en ejecución en el dispositivo."""
    try:
        result = subprocess.run(
            ['adb', '-s', device, 'shell', 'ps'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        if "frida-server" in result.stdout:
            print(f"[+] frida-server está en ejecución en el dispositivo ({device}).")
            return True
        else:
            print(f"[-] frida-server no está en ejecución en el dispositivo ({device}).")
            return False
    except Exception as e:
        print(f"[-] Error al verificar si frida-server está en ejecución en el dispositivo ({device}): {e}")
        return False

def restart_frida_server(device, remote_path="/data/local/tmp/frida-server"):
    """Reinicia frida-server en el dispositivo."""
    try:
        print(f"[+] Reiniciando frida-server en el dispositivo ({device})...")
        
        # Verificar si el archivo frida-server existe en el dispositivo
        check_file_command = f"adb -s {device} shell '[ -f \"{remote_path}\" ] && echo exists || echo missing'"
        file_status = subprocess.run(check_file_command, stdout=subprocess.PIPE, shell=True, text=True).stdout.strip()
        if file_status == "missing":
            print(f"[-] El archivo {remote_path} no existe en el dispositivo.")
            return
        
        print(f"[+] Archivo frida-server encontrado en: {remote_path}")
        
        # Verificar permisos de ejecución
        print("[+] Verificando permisos de ejecución...")
        chmod_command = f"adb -s {device} shell chmod 755 \"{remote_path}\""
        subprocess.run(chmod_command, shell=True, check=True)
        print("[+] Permisos de ejecución asignados correctamente.")
        
        # Paso 1: Detener el proceso actual de frida-server
        print("[+] Deteniendo el proceso actual de frida-server...")
        ps_command = f"adb -s {device} shell ps"
        process_list = subprocess.run(ps_command, stdout=subprocess.PIPE, text=True).stdout
        frida_process = [line for line in process_list.splitlines() if "frida-server" in line]
        
        if frida_process:
            pid = frida_process[0].split()[1]
            kill_command = f"adb -s {device} shell kill {pid}"
            subprocess.run(kill_command, shell=True, check=True)
            print("[+] Proceso de frida-server detenido correctamente.")
        else:
            print("[-] No se encontró ningún proceso de frida-server en ejecución.")
        
        # Paso 2: Iniciar frida-server nuevamente
        print("[+] Iniciando frida-server nuevamente...")
        start_command = f"adb -s {device} shell \"nohup {remote_path} > /dev/null 2>&1 &\""
        subprocess.run(start_command, shell=True, check=True)
        print("[+] frida-server iniciado correctamente.")
        
        # Esperar unos segundos para que el proceso inicie
        print("[+] Esperando unos segundos para que frida-server inicie...")
        import time
        time.sleep(5)
        
        # Paso 3: Verificar que frida-server esté en ejecución
        if is_frida_server_running(device):
            print("[+] frida-server está en ejecución correctamente.")
        else:
            print("[-] No se pudo verificar que frida-server esté en ejecución.")
    except Exception as e:
        print(f"[-] Error al reiniciar frida-server en el dispositivo ({device}): {e}")

def list_and_select_device():
    """Lista los dispositivos conectados y permite al usuario seleccionar uno."""
    try:
        result = subprocess.run(['adb', 'devices'], stdout=subprocess.PIPE, text=True)
        lines = result.stdout.strip().split('\n')[1:]
        devices = [line.split('\t')[0] for line in lines if 'device' in line]
        
        if not devices:
            print("[-] No hay dispositivos conectados.")
            return None
        
        print("[+] Dispositivos conectados:")
        for i, device in enumerate(devices):
            print(f"    [{i + 1}] {device}")
        
        while True:
            choice = input("[?] Ingresa el número del dispositivo (o 'q' para salir): ").strip().lower()
            if choice == 'q':
                return None
            if choice.isdigit() and 1 <= int(choice) <= len(devices):
                selected_device = devices[int(choice) - 1]
                print(f"[+] Dispositivo seleccionado: {selected_device}")
                return selected_device
            print("[-] Selección inválida. Inténtalo de nuevo.")
    except Exception as e:
        print(f"[-] Error al listar dispositivos: {e}")
        return None

def validate_device(device):
    """Valida que el dispositivo seleccionado esté disponible y funcione correctamente."""
    try:
        result = subprocess.run(['adb', '-s', device, 'shell', 'echo', 'test'], 
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode == 0 and "test" in result.stdout:
            print(f"[+] El dispositivo ({device}) está disponible y listo para usar.")
            return True
        else:
            print(f"[-] El dispositivo ({device}) no responde correctamente.")
            return False
    except Exception as e:
        print(f"[-] Error al validar el dispositivo ({device}): {e}")
        return False

if __name__ == "__main__":
    remote_path = "/data/local/tmp/frida-server"  # Ruta donde está instalado frida-server
    
    # Paso 1: Listar y seleccionar dispositivo
    device = list_and_select_device()
    if not device:
        print("[-] No se seleccionó ningún dispositivo. Saliendo...")
        exit(1)
    
    # Paso 2: Validar el dispositivo seleccionado
    if not validate_device(device):
        print("[-] El dispositivo no está disponible. Saliendo...")
        exit(1)
    
    # Paso 3: Reiniciar frida-server
    restart_frida_server(device, remote_path)