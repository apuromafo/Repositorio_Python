import os
import subprocess
import sys
import json

# Carpeta para almacenar los certificados
CERT_FOLDER = "certificates"
CONFIG_FILE = "config.json"

def show_menu():
    """Muestra el menú principal."""
    print("\n[+] Menú principal:")
    print("1. Convertir certificado .crt a .pem")
    print("2. Generar hash del certificado")
    print("3. Instalar certificado (Android 9)")
    print("4. Instalar certificado (Android 11)")
    print("5. Validar instalación del certificado")
    print("6. Salir")

def ensure_cert_folder():
    """Crea la carpeta de certificados si no existe."""
    if not os.path.exists(CERT_FOLDER):
        print(f"[+] Creando carpeta '{CERT_FOLDER}' para organizar los certificados...")
        os.makedirs(CERT_FOLDER)

def load_config():
    """Carga la configuración desde el archivo JSON."""
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    return {}

def save_config(config):
    """Guarda la configuración en el archivo JSON."""
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=4)

def is_openssl_installed():
    """Verifica si OpenSSL está instalado."""
    try:
        result = subprocess.run(["openssl", "version"], capture_output=True, text=True)
        return result.returncode == 0
    except FileNotFoundError:
        return False

def install_openssl():
    """Instala OpenSSL ejecutando el script openssl_setup.py."""
    print("[+] OpenSSL no está instalado. Iniciando proceso de instalación...")
    try:
        # Ejecutar el script de instalación de OpenSSL
        subprocess.run([sys.executable, "openssl_setup.py"], check=True)
        print("[+] OpenSSL instalado correctamente.")
    except Exception as e:
        print(f"[-] Error al instalar OpenSSL: {e}")
        sys.exit(1)

def is_adb_installed():
    """Verifica si ADB está instalado."""
    try:
        result = subprocess.run(["adb", "version"], capture_output=True, text=True)
        return result.returncode == 0
    except FileNotFoundError:
        return False

def install_adb():
    """Instala ADB ejecutando el script adb_setup.py."""
    print("[+] ADB no está instalado. Iniciando proceso de instalación...")
    try:
        # Ejecutar el script de instalación de ADB
        subprocess.run([sys.executable, "adb_setup.py"], check=True)
        print("[+] ADB instalado correctamente.")
    except Exception as e:
        print(f"[-] Error al instalar ADB: {e}")
        sys.exit(1)

def convert_cert_to_pem(cert_path, config):
    """Convierte un certificado .crt a .pem."""
    ensure_cert_folder()
    pem_path = os.path.join(CERT_FOLDER, os.path.basename(cert_path).replace(".crt", ".pem"))
    
    # Verificar si el archivo PEM ya existe
    if os.path.exists(pem_path):
        use_existing = input(f"[?] El archivo PEM ya existe en '{pem_path}'. ¿Deseas usarlo? (s/n): ").strip().lower()
        if use_existing == "s":
            print(f"[+] Usando el archivo PEM existente: {pem_path}")
            config["pem_path"] = pem_path
            save_config(config)
            return pem_path
        elif use_existing != "n":
            print("[-] Entrada inválida. Intenta nuevamente.")
            return None

    # Convertir el certificado CRT a PEM
    try:
        print(f"[+] Convirtiendo {cert_path} a {pem_path}...")
        subprocess.run(["openssl", "x509", "-inform", "DER", "-in", cert_path, "-out", pem_path], check=True)
        print(f"[+] Certificado convertido exitosamente: {pem_path}")
        config["pem_path"] = pem_path
        save_config(config)
        return pem_path
    except Exception as e:
        print(f"[-] Error al convertir el certificado: {e}")
        return None

def generate_cert_hash(pem_path, config):
    """Genera el hash del certificado PEM usando -subject_hash_old."""
    try:
        print(f"[+] Generando hash para {pem_path}...")
        result = subprocess.run(
            ["openssl", "x509", "-inform", "PEM", "-subject_hash_old", "-in", pem_path],
            capture_output=True,
            text=True,
            check=True
        )
        cert_hash = result.stdout.strip().split("\n")[0]
        print(f"[+] Hash generado: {cert_hash}")
        config["cert_hash"] = cert_hash
        save_config(config)
        return cert_hash
    except Exception as e:
        print(f"[-] Error al generar el hash: {e}")
        return None

def install_cert_android_9(cert_path, cert_hash, device_id):
    """Instala el certificado en Android 9."""
    try:
        cert_name = f"{cert_hash}.0"
        remote_path = f"/system/etc/security/cacerts/{cert_name}"
        print(f"[+] Iniciando instalación del certificado {cert_name} en el dispositivo {device_id}...")

        # Comandos ADB para Android 9
        subprocess.run(["adb", "-s", device_id, "root"], check=True)
        subprocess.run(["adb", "-s", device_id, "remount"], check=True)
        subprocess.run(["adb", "-s", device_id, "push", cert_path, remote_path], check=True)
        subprocess.run(["adb", "-s", device_id, "shell", f"chmod 644 {remote_path}"], check=True)

        print(f"[+] Certificado instalado exitosamente en {remote_path}")
    except Exception as e:
        print(f"[-] Error al instalar el certificado: {e}")

def install_cert_android_11(cert_path, cert_hash, device_id):
    """Instala el certificado en Android 11."""
    try:
        cert_name = f"{cert_hash}.0"
        remote_path = f"/system/etc/security/cacerts/{cert_name}"
        print(f"[+] Iniciando instalación del certificado {cert_name} en el dispositivo {device_id}...")

        # Desactivar verificación AVB y verity
        print("[+] Desactivando verificación AVB y verity...")
        subprocess.run(["adb", "-s", device_id, "root"], check=True)
        subprocess.run(["adb", "-s", device_id, "shell", "avbctl disable-verification"], check=True)
        subprocess.run(["adb", "-s", device_id, "disable-verity"], check=True)
        subprocess.run(["adb", "-s", device_id, "reboot"], check=True)

        # Esperar a que el dispositivo se reinicie
        input("[!] Reinicia el dispositivo y presiona Enter cuando esté listo...")

        # Remontar /system como escribible
        print("[+] Remontando /system como escribible...")
        subprocess.run(["adb", "-s", device_id, "root"], check=True)
        subprocess.run(["adb", "-s", device_id, "remount"], check=True)

        # Copiar el certificado
        print(f"[+] Copiando el certificado {cert_path} a {remote_path}...")
        subprocess.run(["adb", "-s", device_id, "push", cert_path, remote_path], check=True)
        subprocess.run(["adb", "-s", device_id, "shell", f"chmod 644 {remote_path}"], check=True)

        print(f"[+] Certificado instalado exitosamente en {remote_path}")
    except Exception as e:
        print(f"[-] Error al instalar el certificado: {e}")

def validate_cert_installation(cert_hash, device_id):
    """Valida si el certificado está instalado en el emulador."""
    try:
        cert_name = f"{cert_hash}.0"
        remote_path = f"/system/etc/security/cacerts/{cert_name}"
        print(f"[+] Validando instalación del certificado {cert_name} en el dispositivo {device_id}...")

        result = subprocess.run(
            ["adb", "-s", device_id, "shell", f"ls {remote_path}"],
            capture_output=True,
            text=True
        )
        if "No such file or directory" in result.stderr:
            print(f"[-] Certificado no encontrado en {remote_path}")
        else:
            print(f"[+] Certificado validado exitosamente en {remote_path}")
    except Exception as e:
        print(f"[-] Error al validar el certificado: {e}")

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

def select_device(devices):
    """Permite al usuario seleccionar un dispositivo."""
    while True:
        choice = input("[?] Selecciona el número del dispositivo/emulador a usar (o 'q' para salir): ").strip()
        if choice.lower() == "q":
            print("[+] Saliendo del programa...")
            return None
        if not choice.isdigit() or int(choice) < 1 or int(choice) > len(devices):
            print("[-] Selección inválida. Intenta nuevamente.")
            continue
        selected_device = devices[int(choice) - 1]
        print(f"[+] Has seleccionado: {selected_device}")
        return selected_device

def main():
    cert_path = "ca.crt"  # Ruta predeterminada del certificado
    config = load_config()
    pem_path = config.get("pem_path")
    cert_hash = config.get("cert_hash")
    device_id = None

    # Verificar si ADB está instalado
    if not is_adb_installed():
        install_adb()

    # Verificar si OpenSSL está instalado
    if not is_openssl_installed():
        install_openssl()

    while True:
        show_menu()
        choice = input("[?] Selecciona una opción (1-6): ").strip()

        if choice == "1":
            pem_path = convert_cert_to_pem(cert_path, config)
        elif choice == "2":
            if pem_path:
                cert_hash = generate_cert_hash(pem_path, config)
            else:
                print("[-] Primero convierte el certificado a .pem.")
        elif choice in ("3", "4"):
            if not cert_hash or not pem_path:
                print("[-] No se encontraron datos previos del certificado. Genera el PEM y el hash primero.")
                continue
            if not device_id:
                device_id = select_device(list_devices())
            if device_id:
                if choice == "3":
                    install_cert_android_9(pem_path, cert_hash, device_id)
                elif choice == "4":
                    install_cert_android_11(pem_path, cert_hash, device_id)
        elif choice == "5":
            if cert_hash:
                if not device_id:
                    device_id = select_device(list_devices())
                if device_id:
                    validate_cert_installation(cert_hash, device_id)
            else:
                print("[-] Primero genera el hash del certificado.")
        elif choice == "6":
            print("[+] Saliendo del programa...")
            break
        else:
            print("[-] Opción no válida. Intenta nuevamente.")

if __name__ == "__main__":
    main()