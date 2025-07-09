import subprocess

def get_device_info(device_id):
    """Obtiene información detallada del dispositivo."""
    try:
        print(f"[+] Recopilando información del dispositivo {device_id}...")
        info = {}

        # Versión de Android
        android_version = subprocess.run(
            ["adb", "-s", device_id, "shell", "getprop", "ro.build.version.release"],
            capture_output=True,
            text=True,
            check=True
        ).stdout.strip()
        info["Android Version"] = android_version

        # Arquitectura del sistema
        architecture = subprocess.run(
            ["adb", "-s", device_id, "shell", "getprop", "ro.product.cpu.abi"],
            capture_output=True,
            text=True,
            check=True
        ).stdout.strip()
        info["Architecture"] = architecture

        # Modelo del dispositivo
        model = subprocess.run(
            ["adb", "-s", device_id, "shell", "getprop", "ro.product.model"],
            capture_output=True,
            text=True,
            check=True
        ).stdout.strip()
        info["Model"] = model

        # Nombre del dispositivo
        device_name = subprocess.run(
            ["adb", "-s", device_id, "shell", "getprop", "ro.product.name"],
            capture_output=True,
            text=True,
            check=True
        ).stdout.strip()
        info["Device Name"] = device_name

        # Fabricante del dispositivo
        manufacturer = subprocess.run(
            ["adb", "-s", device_id, "shell", "getprop", "ro.product.manufacturer"],
            capture_output=True,
            text=True,
            check=True
        ).stdout.strip()
        info["Manufacturer"] = manufacturer

        # Nivel de SDK
        sdk_level = subprocess.run(
            ["adb", "-s", device_id, "shell", "getprop", "ro.build.version.sdk"],
            capture_output=True,
            text=True,
            check=True
        ).stdout.strip()
        info["SDK Level"] = sdk_level

        # Dirección IP del dispositivo
        ip_address = get_device_ip(device_id)
        info["IP Address"] = ip_address if ip_address else "No disponible"

        # Verificar si el dispositivo está en modo root
        is_rooted = is_device_rooted(device_id)
        info["Root Access"] = "Yes" if is_rooted else "No"

        return info

    except Exception as e:
        print(f"[-] Error al obtener la información del dispositivo {device_id}: {e}")
        return None

def get_device_ip(device_id):
    """Obtiene la dirección IP del dispositivo."""
    try:
        result = subprocess.run(
            ["adb", "-s", device_id, "shell", "ip", "route"],
            capture_output=True,
            text=True,
            check=True
        )
        for line in result.stdout.split("\n"):
            if "src" in line:
                ip = line.split("src")[1].strip().split()[0]
                return ip
        return None
    except Exception as e:
        print(f"[-] Error al obtener la IP del dispositivo {device_id}: {e}")
        return None

def is_device_rooted(device_id):
    """Verifica si el dispositivo está en modo root."""
    try:
        result = subprocess.run(
            ["adb", "-s", device_id, "shell", "su -c 'id'"],
            capture_output=True,
            text=True
        )
        if "uid=0(root)" in result.stdout:
            return True
        return False
    except Exception as e:
        print(f"[-] Error al verificar el modo root del dispositivo {device_id}: {e}")
        return False

def list_devices():
    """Lista todos los dispositivos/emuladores disponibles."""
    try:
        print("[+] Listando dispositivos/emuladores disponibles...")
        result = subprocess.run(
            ["adb", "devices"],
            capture_output=True,
            text=True,
            check=True
        )
        lines = result.stdout.strip().split("\n")[1:]  # Ignorar la primera línea ("List of devices attached")
        devices = [line.split("\t")[0] for line in lines if line.strip()]
        if not devices:
            print("[-] No hay dispositivos/emuladores disponibles.")
            return []
        print("[+] Dispositivos/emuladores disponibles:")
        for idx, device in enumerate(devices, start=1):
            print(f"{idx}. {device}")
        return devices
    except Exception as e:
        print(f"[-] Error al listar dispositivos/emuladores: {e}")
        return []

def main():
    devices = list_devices()
    if not devices:
        print("[-] No hay dispositivos/emuladores disponibles.")
        return

    print("[+] Recopilando información de todos los dispositivos...")
    for device in devices:
        print(f"\n[+] Información del dispositivo {device}:")
        info = get_device_info(device)
        if info:
            for key, value in info.items():
                print(f"  {key}: {value}")
        else:
            print(f"[-] No se pudo obtener información del dispositivo {device}.")

if __name__ == "__main__":
    main()