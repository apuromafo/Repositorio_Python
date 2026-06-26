
# =============================================================================
# AVISO LEGAL / LEGAL NOTICE
# -----------------------------------------------------------------------------
# Esta herramienta es unicamente para fines educativos y de auditoria de
# seguridad autorizada. El uso no autorizado contra sistemas sin el
# consentimiento explicito del propietario es ilegal.
# El usuario asume toda responsabilidad por el uso indebido.
#
# This tool is for educational and authorized security auditing purposes only.
# Unauthorized use against systems without the owner's explicit consent is
# illegal. The user assumes all responsibility for misuse.
# =============================================================================

import subprocess
import re
import sys 

# =====================================================================
# 🌐 1. CENTRALIZACIÓN DE STRINGS (Para Multi-idioma / i18n)
# =====================================================================

# Al cambiar solo los valores de este diccionario, puedes traducir todo el script.
MESSAGES = {
    # Títulos y encabezados
    "TITLE_LISTING": "Listando dispositivos/emuladores disponibles...",
    "TITLE_FOUND": "Dispositivos/emuladores activos encontrados:",
    "TITLE_INFO": "Información del dispositivo",
    
    # Etiquetas de datos
    "LABEL_ANDROID_VERSION": "Android Version",
    "LABEL_ARCHITECTURE": "Architecture",
    "LABEL_MODEL": "Model",
    "LABEL_DEVICE_NAME": "Device Name",
    "LABEL_MANUFACTURER": "Manufacturer",
    "LABEL_SDK_LEVEL": "SDK Level",
    "LABEL_IP_ADDRESS": "IP Address",
    "LABEL_ROOT_ACCESS": "Root Access",

    # Valores de datos
    "VALUE_NOT_AVAILABLE": "No disponible",
    "VALUE_YES": "Yes",
    "VALUE_NO": "No",

    # Mensajes de error/estado
    "MSG_NO_DEVICES": "No hay dispositivos/emuladores activos.",
    "MSG_ADB_ERROR": "Error al ejecutar 'adb devices'. Asegúrate de que ADB esté instalado y en tu PATH.",
    "MSG_LIST_ERROR": "Error inesperado al listar dispositivos: ",
    "MSG_INFO_ERROR": "No se pudo obtener información: ",
    "MSG_ADB_FAIL": "Fallo al ejecutar ADB: ",
    "MSG_TIMEOUT": "Comando ADB ha expirado (timeout).",
    "MSG_UNEXPECTED_ERROR": "Error inesperado: ",
}

# =====================================================================
# ⚙️ 2. LÓGICA DE OBTENCIÓN DE DATOS
# =====================================================================

def get_device_info(device_id):
    """Obtiene información detallada del dispositivo."""
    
    info = {}
    
    # Usamos las etiquetas centralizadas para construir la lista de propiedades a obtener
    properties_to_fetch = [
        ("ro.build.version.release", MESSAGES["LABEL_ANDROID_VERSION"]),
        ("ro.product.cpu.abi", MESSAGES["LABEL_ARCHITECTURE"]),
        ("ro.product.model", MESSAGES["LABEL_MODEL"]),
        ("ro.product.name", MESSAGES["LABEL_DEVICE_NAME"]),
        ("ro.product.manufacturer", MESSAGES["LABEL_MANUFACTURER"]),
        ("ro.build.version.sdk", MESSAGES["LABEL_SDK_LEVEL"]),
    ]

    try:
        for prop, display_name in properties_to_fetch:
            result = subprocess.run(
                ["adb", "-s", device_id, "shell", "getprop", prop],
                capture_output=True,
                text=True,
                check=True,
                timeout=5
            )
            info[display_name] = result.stdout.strip()

        # Dirección IP del dispositivo
        ip_address = get_device_ip(device_id)
        info[MESSAGES["LABEL_IP_ADDRESS"]] = ip_address if ip_address else MESSAGES["VALUE_NOT_AVAILABLE"]

        # Verificar si el dispositivo está en modo root
        is_rooted = is_device_rooted(device_id)
        info[MESSAGES["LABEL_ROOT_ACCESS"]] = MESSAGES["VALUE_YES"] if is_rooted else MESSAGES["VALUE_NO"]

        return info

    except subprocess.CalledProcessError as e:
        info["Error"] = f"{MESSAGES['MSG_ADB_FAIL']}{e.cmd}"
        return info
    except subprocess.TimeoutExpired:
        info["Error"] = MESSAGES["MSG_TIMEOUT"]
        return info
    except Exception as e:
        info["Error"] = f"{MESSAGES['MSG_UNEXPECTED_ERROR']}{e}"
        return info

def get_device_ip(device_id):
    """Obtiene la dirección IP del dispositivo probando múltiples comandos."""
    
    commands = [
        ("ip route", r"src\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"),
        ("ifconfig wlan0", r"inet\s+(addr:)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"),
        ("ifconfig eth0", r"inet\s+(addr:)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"),
    ]
    
    ipv4_pattern = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"

    for command_str, pattern_str in commands:
        try:
            result = subprocess.run(
                ["adb", "-s", device_id, "shell", command_str],
                capture_output=True,
                text=True,
                timeout=3
            )
            
            if result.returncode == 0 and result.stdout:
                match = re.search(pattern_str, result.stdout, re.IGNORECASE)
                if match:
                    ip_candidate = match.group(2) if len(match.groups()) >= 2 and match.group(2) else match.group(1) if len(match.groups()) >= 1 and match.group(1) else match.group(0)
                    
                    clean_ip_match = re.search(ipv4_pattern, ip_candidate)
                    if clean_ip_match:
                        return clean_ip_match.group(0)
            
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, Exception):
            continue 

    return None

def is_device_rooted(device_id):
    """Verifica si el dispositivo está en modo root buscando el binario 'su'."""
    try:
        result = subprocess.run(
            ["adb", "-s", device_id, "shell", "which su"],
            capture_output=True,
            text=True,
            timeout=3
        )
        return result.returncode == 0 and len(result.stdout.strip()) > 0
    
    except Exception:
        return False

# =====================================================================
# 💻 3. LÓGICA DE SALIDA Y MAIN
# =====================================================================

def list_devices():
    """Lista todos los dispositivos/emuladores disponibles."""
    print(MESSAGES["TITLE_LISTING"])
    try:
        result = subprocess.run(
            ["adb", "devices"],
            capture_output=True,
            text=True,
            check=True
        )
        lines = result.stdout.strip().split("\n")[1:]
        devices = [line.split("\t")[0] for line in lines if line.strip() and "device" in line.split("\t")[-1]]
        
        if not devices:
            print(MESSAGES["MSG_NO_DEVICES"])
            return []
        
        print(MESSAGES["TITLE_FOUND"])
        for idx, device in enumerate(devices, start=1):
            print(f"  {idx}. {device}")
        return devices
        
    except subprocess.CalledProcessError:
        print(MESSAGES["MSG_ADB_ERROR"])
        sys.exit(1)
    except Exception as e:
        print(f"{MESSAGES['MSG_LIST_ERROR']}{e}")
        sys.exit(1)

def main():
    devices = list_devices()
    if not devices:
        return

     
    for device in devices:
        
        # Eliminamos ** para el nombre del dispositivo
        print(f"\n--- {MESSAGES['TITLE_INFO']} {device} ---")
        
        info = get_device_info(device)
        
        if info and "Error" not in info:
            # Encontrar la longitud máxima de las claves
            max_len = max(len(key) for key in info.keys())
            
            for key, value in info.items():
                # Eliminamos ** en el valor
                print(f"  {key:<{max_len}}: {value}") 
        else:
            error_msg = info.get("Error", MESSAGES["MSG_UNEXPECTED_ERROR"])
            # Usamos el mensaje de error centralizado
            print(f"  {MESSAGES['MSG_INFO_ERROR']}{error_msg}")


print("\n[!] AVISO LEGAL: Use solo con autorizacion. / LEGAL NOTICE: Authorized use only.\n")
if __name__ == "__main__":
    main()