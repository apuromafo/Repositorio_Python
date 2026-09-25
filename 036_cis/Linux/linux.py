
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

import os
import shlex
import argparse
import json
import subprocess
import platform
import datetime

# Colores para output
class Colors:
    """Clase para manejar los códigos de color en la salida de la terminal."""
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[1;34m'
    CYAN = '\033[1;36m'
    NC = '\033[0m' # No Color

# Lista global para almacenar los hallazgos de seguridad
# Cada hallazgo será un diccionario con detalles como:
# {'control': 'CIS 1.1', 'description': 'Descripción del hallazgo', 'severity': 'warning/critical', 'recommendation_key': 'un_id_unico_de_recomendacion'}
SECURITY_FINDINGS = []

def print_preflight():
    """Buenas prácticas, disclaimer y autoría. Se muestra antes de auditar."""
    print(f"{Colors.CYAN}--- Antes de ejecutar ---{Colors.NC}")
    print("Buenas prácticas:")
    print("  1. Ejecute SOLO en sistemas propios o con autorización escrita del propietario.")
    print("  2. Use los privilegios mínimos necesarios (root/sudo solo si el chequeo lo requiere).")
    print("  3. Pruebe primero en un entorno no productivo (VM/Vagrant).")
    print("  4. Esta herramienta es de SOLO LECTURA: no modifica el sistema; revise cada")
    print("     recomendación con su equipo antes de aplicar cambios.")
    print("Autores: apuromafo (https://github.com/apuromafo) - Sugerencias y reportes:")
    print("  https://github.com/apuromafo/Repositorio_Python/issues")
    print(f"{Colors.YELLOW}AVISO LEGAL: uso educativo y auditoría autorizada únicamente.{Colors.NC}")

# Funciones de logging
def log_info(message):
    """Imprime un mensaje informativo en verde."""
    print(f"{Colors.GREEN}[INFO]{Colors.NC} {message}")

def log_warning(message, control=None, safeguard=None, recommendation_key=None):
    """
    Imprime un mensaje de advertencia en amarillo y registra el hallazgo.
    :param message: Mensaje de la advertencia.
    :param control: Número del Control CIS (ej. "CIS 1").
    :param safeguard: Número de la salvaguarda CIS (ej. "1.1").
    :param recommendation_key: Clave para identificar la recomendación específica.
    """
    print(f"{Colors.YELLOW}[WARNING]{Colors.NC} {message}")
    finding_detail = {'message': message, 'severity': 'warning'}
    if control:
        finding_detail['control'] = control
    if safeguard:
        finding_detail['safeguard'] = safeguard
    if recommendation_key:
        finding_detail['recommendation_key'] = recommendation_key
    SECURITY_FINDINGS.append(finding_detail)

def log_error(message, control=None, safeguard=None, recommendation_key=None):
    """
    Imprime un mensaje de error en rojo y registra el hallazgo crítico.
    :param message: Mensaje del error.
    :param control: Número del Control CIS (ej. "CIS 1").
    :param safeguard: Número de la salvaguarda CIS (ej. "1.1").
    :param recommendation_key: Clave para identificar la recomendación específica.
    """
    print(f"{Colors.RED}[ERROR]{Colors.NC} {message}")
    finding_detail = {'message': message, 'severity': 'error'}
    if control:
        finding_detail['control'] = control
    if safeguard:
        finding_detail['safeguard'] = safeguard
    if recommendation_key:
        finding_detail['recommendation_key'] = recommendation_key
    SECURITY_FINDINGS.append(finding_detail)

def log_section(title):
    """Imprime un encabezado de sección en cian."""
    print(f"\n{Colors.CYAN}=== {title} ==={Colors.NC}")

def run_command(command, shell=False, capture_output=True, text=True):
    """
    Ejecuta un comando del sistema y devuelve su salida estándar.
    Maneja excepciones para comandos no encontrados o errores de ejecución.
    Retorna None si el comando falla o no produce salida.
    """
    try:
        result = subprocess.run(command, shell=shell, capture_output=capture_output, text=text, check=True, encoding='utf-8', errors='ignore', timeout=30)
        return result.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return None

def check_command_exists(command):
    """Verifica si un comando existe en el PATH del sistema."""
    return run_command(f"command -v {shlex.quote(command)}", shell=True) is not None

def get_linux_distribution_name():
    """
    Intenta obtener el nombre de la distribución de Linux de forma robusta.
    Reemplaza platform.dist() deprecado.
    """
    if hasattr(platform, 'freedesktop_os_release'):
        os_release = platform.freedesktop_os_release()
        return os_release.get('ID', '').lower()
    elif os.path.exists("/etc/os-release"):
        with open("/etc/os-release", "r") as f:
            for line in f:
                if line.startswith("ID="):
                    return line.split('=', 1)[1].strip().strip('"').lower()
    return ""

def check_hardware_inventory_enhanced():
    """
    Control 1: Inventario y Control de Activos de Hardware (Mejorado)
    Incluye IP de interfaces activas y un intento de identificar fabricante/modelo.
    """
    log_section("Control 1: Inventario de Hardware (Mejorado)")

    # Información del sistema operativo (existente)
    if os.path.exists("/etc/os-release"):
        with open("/etc/os-release") as f:
            for line in f:
                if line.startswith("PRETTY_NAME="):
                    log_info(f"Sistema: {line.split('=')[1].strip().strip('\"')}")
                    break
    log_info(f"Kernel: {platform.release()}")
    log_info(f"Arquitectura: {platform.machine()}")

    # Información de memoria RAM (existente)
    if os.path.exists("/proc/meminfo"):
        meminfo = run_command("grep MemTotal /proc/meminfo", shell=True)
        if meminfo:
            try:
                total_mem_kb = int(meminfo.split()[1])
                total_mem_gb = round(total_mem_kb / (1024 * 1024), 2)
                log_info(f"RAM Total: {total_mem_gb} GB")
            except (ValueError, IndexError):
                log_warning("No se pudo parsear la información de RAM de /proc/meminfo.", control="CIS 1", safeguard="1.1", recommendation_key="hardware_ram_parse_fail")

    # Direcciones IP de interfaces activas (Nuevo/Mejorado)
    log_info("Direcciones IP de Interfaces Activas:")
    if check_command_exists("ip"):
        ip_addresses = run_command("ip -4 a show scope global | grep inet | awk '{print $2, $NF}'", shell=True)
        if ip_addresses:
            for line in ip_addresses.splitlines():
                print(f"  - {line}")
        else:
            log_info("  No se encontraron direcciones IPv4 activas con ámbito global.")
            log_warning("No se detectaron interfaces de red activas con IPv4.", control="CIS 1", safeguard="1.1", recommendation_key="hardware_no_ipv4_interfaces")
    else:
        log_warning("Comando 'ip' no disponible. No se pueden listar las direcciones IP.", control="CIS 1", safeguard="1.1", recommendation_key="hardware_ip_command_missing")

    # Dispositivos USB (existente)
    log_info("Dispositivos USB conectados:")
    if check_command_exists("lsusb"):
        usb_devices = run_command("lsusb", shell=True)
        if usb_devices:
            for line in usb_devices.splitlines():
                print(f"  - {line}")
        else:
            log_info("  No se detectaron dispositivos USB.")
    else:
        log_warning("lsusb no disponible. Instálelo (ej: sudo apt install usbutils) para obtener información de dispositivos USB.", control="CIS 1", safeguard="1.1", recommendation_key="hardware_lsusb_missing")

    # Dispositivos PCI (existente)
    log_info("Dispositivos PCI principales:")
    if check_command_exists("lspci"):
        pci_devices = run_command("lspci", shell=True)
        if pci_devices:
            found_pci = False
            for line in pci_devices.splitlines():
                if any(keyword in line for keyword in ["VGA", "Audio", "Network", "Ethernet"]):
                    print(f"  - {line}")
                    found_pci = True
            if not found_pci:
                log_info("  No se encontraron dispositivos PCI principales (VGA, Audio, Red).")
        else:
            log_info("  No se detectaron dispositivos PCI.")
            log_warning("lspci disponible pero no detectó dispositivos PCI. Puede ser un entorno virtualizado sin emulación PCI completa.", control="CIS 1", safeguard="1.1", recommendation_key="hardware_no_pci_devices")
    else:
        log_warning("lspci no disponible. Instálelo (ej: sudo apt install pciutils) para obtener información de dispositivos PCI.", control="CIS 1", safeguard="1.1", recommendation_key="hardware_lspci_missing")

    # Intentar identificar fabricante/modelo (Control 1.1)
    log_info("Información del sistema base (fabricante/modelo si disponible):")
    if check_command_exists("dmidecode"):
        system_info_manufacturer = run_command("sudo dmidecode -s system-manufacturer", shell=True)
        system_info_product = run_command("sudo dmidecode -s system-product-name", shell=True)
        system_info_version = run_command("sudo dmidecode -s system-version", shell=True)

        if system_info_manufacturer or system_info_product or system_info_version:
            print(f"  - Fabricante: {system_info_manufacturer if system_info_manufacturer else 'N/A'}")
            print(f"  - Producto: {system_info_product if system_info_product else 'N/A'}")
            print(f"  - Versión: {system_info_version if system_info_version else 'N/A'}")
        else:
            log_warning("dmidecode disponible pero no pudo obtener la información del sistema (¿permisos? o no disponible en virtualización completa).", control="CIS 1", safeguard="1.1", recommendation_key="hardware_dmidecode_info_missing")
    else:
        log_warning("dmidecode no disponible. Instálelo (ej: sudo apt install dmidecode) para más detalles del sistema.", control="CIS 1", safeguard="1.1", recommendation_key="hardware_dmidecode_missing")


def check_software_inventory_enhanced():
    """
    Control 2: Inventario y Control de Activos de Software (Mejorado)
    Incluye los últimos paquetes instalados/actualizados.
    """
    log_section("Control 2: Inventario de Software (Mejorado)")

    # Paquetes instalados según el gestor de paquetes (existente)
    package_manager_found = False
    if check_command_exists("dpkg"):
        package_count = run_command("dpkg -l | grep -c '^ii'", shell=True)
        if package_count:
            log_info(f"Paquetes instalados (dpkg): {package_count}")
            package_manager_found = True
    elif check_command_exists("rpm"):
        package_count = run_command("rpm -qa | wc -l", shell=True)
        if package_count:
            log_info(f"Paquetes instalados (rpm): {package_count}")
            package_manager_found = True
    elif check_command_exists("pacman"):
        package_count = run_command("pacman -Q | wc -l", shell=True)
        if package_count:
            log_info(f"Paquetes instalados (pacman): {package_count}")
            package_manager_found = True

    if not package_manager_found:
        log_warning("Ningún gestor de paquetes (dpkg, rpm, pacman) común encontrado o accesible. Esto dificulta el control de software.", control="CIS 2", safeguard="2.1", recommendation_key="software_no_package_manager")

    # Paquetes instalados/actualizados recientemente (Mejorado para compatibilidad)
    log_info("Últimos 10 paquetes instalados/actualizados:")
    linux_distro_id = get_linux_distribution_name()
    recent_packages_found = False

    if "ubuntu" in linux_distro_id or "debian" in linux_distro_id:
        if os.path.exists("/var/log/dpkg.log") and check_command_exists("grep"):
            recent_packages = run_command("grep -E 'status installed|status half-installed|status unpacked' /var/log/dpkg.log | tail -n 10 | awk '{print $1, $2, $4}'", shell=True)
            if recent_packages:
                for line in recent_packages.splitlines():
                    print(f"  - {line}")
                recent_packages_found = True
            else:
                log_info("  No se encontraron registros de paquetes recientes en /var/log/dpkg.log.")
        else:
            log_warning("No se pudo obtener la lista de paquetes recientes (dpkg.log no disponible).", control="CIS 2", safeguard="2.1", recommendation_key="software_dpkg_log_missing")
    elif linux_distro_id:
        if check_command_exists("journalctl") and check_command_exists("grep"):
            recent_packages_journal = run_command("journalctl _COMM=dnf _COMM=yum _COMM=packagekit _COMM=pacman _COMM=apt | tail -n 10", shell=True)
            if recent_packages_journal:
                for line in recent_packages_journal.splitlines():
                    print(f"  - {line}")
                recent_packages_found = True
            else:
                log_info("  No se encontraron registros de paquetes recientes en el journal.")
        else:
            log_warning("No se pudo obtener la lista de paquetes recientes (journalctl no disponible).", control="CIS 2", safeguard="2.1", recommendation_key="software_journalctl_missing")
    else:
        log_warning("No se pudo determinar la distribución de Linux para obtener la lista de paquetes recientes.", control="CIS 2", safeguard="2.1", recommendation_key="software_distro_detection_fail")

    if not recent_packages_found:
        log_info("  No se pudieron listar paquetes recientes.") # Mensaje más neutral si no se encuentran

    # Servicios en ejecución (existente)
    if check_command_exists("systemctl"):
        running_services = run_command("systemctl list-units --type=service --state=running --no-pager | grep -c '\\.service'", shell=True)
        if running_services:
            log_info(f"Servicios systemd en ejecución: {running_services}")
        else:
            log_info("  No se pudieron determinar la cantidad de servicios systemd en ejecución.")
    else:
        log_warning("systemctl no disponible. No se puede obtener el estado de los servicios systemd.", control="CIS 2", safeguard="2.4", recommendation_key="software_systemctl_missing")

    # Procesos sospechosos (existente)
    log_info("Procesos que requieren revisión (ej: netcat, socat, telnet):")
    suspicious_processes = run_command("ps aux | grep -E '(nc|netcat|ncat|socat|telnet)' | grep -v grep", shell=True)
    if suspicious_processes:
        for line in suspicious_processes.splitlines():
            log_warning(f"  - {line}", control="CIS 2", safeguard="2.4", recommendation_key="software_suspicious_process_found")
    else:
        log_info("  No se encontraron procesos sospechosos comunes en ejecución.")


def check_data_protection():
    """
    Control 3: Protección de Datos
    Verifica el uso de cifrado en reposo (LUKS).
    """
    log_section("Control 3: Protección de Datos")
    log_info("Verificando cifrado de particiones de disco (LUKS):")

    if check_command_exists("lsblk") and check_command_exists("grep"):
        luks_devices = run_command("lsblk -o NAME,FSTYPE | grep crypto_LUKS", shell=True)
        if luks_devices:
            log_info("  Se detectaron los siguientes dispositivos cifrados con LUKS:")
            for line in luks_devices.splitlines():
                print(f"    - {line.strip()}")
            log_info("  El uso de cifrado de disco completo (LUKS) es una buena práctica de seguridad para datos en reposo.")
        else:
            log_warning("  No se detectaron particiones cifradas con LUKS. Considere implementar cifrado para datos sensibles en reposo.", control="CIS 3", safeguard="3.5", recommendation_key="data_no_luks_encryption")
    else:
        log_warning("  Comandos 'lsblk' o 'grep' no disponibles. No se pudo verificar el cifrado de particiones.", control="CIS 3", safeguard="3.5", recommendation_key="data_luks_check_tools_missing")

    # Verificación simplificada de directorios home cifrados con eCryptfs (ejemplo)
    log_info("Verificando cifrado de directorios home con eCryptfs:")
    if os.path.ismount("/home/.ecryptfs"):
        log_info("  Se detectó que el directorio '/home/.ecryptfs' está montado, lo que sugiere el uso de eCryptfs para el cifrado de directorios home.")
    else:
        log_warning("  No se detectó un punto de montaje común de eCryptfs para directorios home. Considere cifrar directorios home para proteger datos de usuario.", control="CIS 3", safeguard="3.5", recommendation_key="data_no_ecryptfs_home")


def check_network_security():
    """Realiza el Control 4."""
    log_section("Control 4: Seguridad de Red")
    log_info("Puertos TCP en escucha:")
    open_ports_output = None
    if check_command_exists("ss"):
        open_ports_output = run_command("ss -tlnp | grep LISTEN", shell=True)
    elif check_command_exists("netstat"):
        open_ports_output = run_command("netstat -tlnp | grep LISTEN", shell=True)

    if open_ports_output:
        for line in open_ports_output.splitlines():
            print(f"  - {line}")
        # Simplificación: si hay puertos escuchando en 0.0.0.0, advertir
        if "0.0.0.0" in open_ports_output:
            log_warning("Se detectaron servicios escuchando en 0.0.0.0 (todas las interfaces). Asegúrese de que esto sea intencional y que los firewalls estén configurados.", control="CIS 4", safeguard="4.6", recommendation_key="network_open_to_all_interfaces")
    else:
        log_warning("No se pudieron obtener los puertos en escucha (ss o netstat no disponibles o sin permisos).", control="CIS 4", safeguard="4.6", recommendation_key="network_ports_check_failed")

    log_info("Estado del Firewall:")
    firewall_configured = False
    if check_command_exists("ufw"):
        ufw_status = run_command("ufw status | head -1", shell=True)
        print(f"  - UFW: {ufw_status}")
        if "inactive" in ufw_status:
            log_warning("UFW está inactivo. Habilite el firewall para proteger el sistema.", control="CIS 4", safeguard="4.1", recommendation_key="network_ufw_inactive")
        firewall_configured = True
    elif check_command_exists("iptables"):
        iptables_rules = run_command("iptables -L | wc -l", shell=True)
        print(f"  - iptables: {iptables_rules.strip()} reglas configuradas")
        if int(iptables_rules.strip()) <= 5: # Un número arbitrario bajo de reglas para indicar poca configuración
            log_warning("Pocas reglas de iptables configuradas. Revise la configuración del firewall.", control="CIS 4", safeguard="4.1", recommendation_key="network_iptables_minimal")
        firewall_configured = True
    elif check_command_exists("firewall-cmd"):
        firewalld_status = run_command("firewall-cmd --state", shell=True)
        print(f"  - firewalld: {firewalld_status if firewalld_status else 'not running'}")
        if firewalld_status and "not running" in firewalld_status:
            log_warning("Firewalld no está en ejecución. Habilite el firewall para proteger el sistema.", control="CIS 4", safeguard="4.1", recommendation_key="network_firewalld_inactive")
        firewall_configured = True

    if not firewall_configured:
        log_warning("Ningún firewall (ufw, iptables, firewalld) común reconocido o configurado. Se recomienda encarecidamente instalar y configurar uno.", control="CIS 4", safeguard="4.1", recommendation_key="network_no_firewall")

    log_info("Interfaces de red activas:")
    if check_command_exists("ip"):
        network_interfaces = run_command("ip addr show | grep -E '^[0-9]+:'", shell=True)
        if network_interfaces:
            for line in network_interfaces.splitlines():
                print(f"  - {line}")
        else:
            log_warning("No se encontraron interfaces de red activas.", control="CIS 4", safeguard="4.5", recommendation_key="network_no_active_interfaces")
    else:
        log_warning("Comando 'ip' no disponible. No se pueden listar las interfaces de red.", control="CIS 4", safeguard="4.5", recommendation_key="network_ip_command_missing_interfaces")


def check_account_management():
    """Realiza el Control 5."""
    log_section("Control 5: Gestión de Cuentas")
    log_info("Cuentas de usuario del sistema (con shell interactiva):")
    if os.path.exists("/etc/passwd"):
        with open("/etc/passwd") as f:
            found_users = False
            for line in f:
                parts = line.strip().split(':')
                if len(parts) >= 7 and parts[6] in ["/bin/bash", "/bin/sh", "/bin/zsh", "/bin/fish"]:
                    username = parts[0]
                    uid = parts[2]
                    last_login_raw = run_command(f"last -1 {shlex.quote(username)}", shell=True)
                    last_login_info = "Nunca accedió o no disponible"
                    if last_login_raw:
                        last_login_parts = last_login_raw.split()
                        for i in range(len(last_login_parts)):
                            if i + 3 < len(last_login_parts):
                                potential_date_str = f"{last_login_parts[i]} {last_login_parts[i+1]} {last_login_parts[i+2]} {last_login_parts[i+3]}"
                                try:
                                    datetime.datetime.strptime(potential_date_str, "%b %d %H:%M %Y")
                                    last_login_info = potential_date_str
                                    break
                                except ValueError:
                                    pass
                    print(f"  - {username} (UID: {uid}) - Último acceso: {last_login_info}")
                    found_users = True
            if not found_users:
                log_info("No se encontraron cuentas de usuario con shells interactivas.")
    else:
        log_error("/etc/passwd no encontrado. No se pueden listar las cuentas de usuario.", control="CIS 5", safeguard="5.1", recommendation_key="accounts_passwd_missing")

    log_info("Cuentas con privilegios de root (UID 0):")
    if os.path.exists("/etc/passwd"):
        with open("/etc/passwd") as f:
            root_accounts = [line.split(':')[0] for line in f if line.strip().split(':')[2] == '0']
            if root_accounts:
                for account in root_accounts:
                    print(f"  - {account}")
                    if account != "root":
                        log_warning(f"Cuenta '{account}' tiene UID 0. Solo la cuenta 'root' debería tener UID 0.", control="CIS 5", safeguard="5.5", recommendation_key="accounts_multiple_uid0")
            else:
                log_info("No se encontraron cuentas con UID 0 (aparte de root).")
    else:
        log_error("/etc/passwd no encontrado.", control="CIS 5", safeguard="5.5", recommendation_key="accounts_passwd_missing_uid0_check")

    log_info("Verificando cuentas sin contraseña:")
    if os.path.exists("/etc/shadow") and os.access("/etc/shadow", os.R_OK):
        with open("/etc/shadow") as f:
            found_no_pass = False
            for line in f:
                parts = line.strip().split(':')
                if len(parts) >= 2 and (parts[1] == "" or parts[1] == "*"):
                    log_warning(f"  - {parts[0]} (sin contraseña). Todas las cuentas deben tener contraseñas fuertes.", control="CIS 5", safeguard="5.4", recommendation_key="accounts_no_password")
                    found_no_pass = True
            if not found_no_pass:
                log_info("No se encontraron cuentas sin contraseña.")
    else:
        log_warning("No se puede acceder a /etc/shadow o no existe. No se pueden verificar cuentas sin contraseña.", control="CIS 5", safeguard="5.4", recommendation_key="accounts_shadow_unreadable")

    log_info("Miembros del grupo sudo/wheel:")
    if check_command_exists("getent"):
        sudo_members = run_command("getent group sudo | cut -d: -f4", shell=True)
        if sudo_members:
            print(f"  - sudo: {sudo_members}")
        else:
            log_info("No se encontraron miembros en el grupo 'sudo'.")

        wheel_members = run_command("getent group wheel | cut -d: -f4", shell=True)
        if wheel_members:
            print(f"  - wheel: {wheel_members}")
        else:
            log_info("No se encontraron miembros en el grupo 'wheel'.")
    else:
        log_warning("getent no disponible. No se pueden obtener los miembros de los grupos.", control="CIS 5", safeguard="5.6", recommendation_key="accounts_getent_missing_groups")


def check_access_control():
    """Realiza el Control 6."""
    log_section("Control 6: Control de Acceso")

    if os.path.exists("/etc/ssh/sshd_config"):
        log_info("Configuración SSH crítica:")
        with open("/etc/ssh/sshd_config") as f:
            sshd_config_content = f.read()

        found_ssh_config = False
        for line in sshd_config_content.splitlines():
            line_stripped = line.strip()
            if not line_stripped.startswith("#") and any(keyword in line_stripped for keyword in ["PermitRootLogin", "PasswordAuthentication", "Port", "Protocol"]):
                print(f"  - {line_stripped}")
                found_ssh_config = True
        if not found_ssh_config:
            log_info("No se encontraron configuraciones SSH críticas explícitas.")

        if "PermitRootLogin yes" in sshd_config_content.lower().replace(" ", ""):
            log_warning("SSH permite login directo como root. Esto no es recomendado.", control="CIS 6", safeguard="6.1", recommendation_key="access_ssh_root_login")
        if "PasswordAuthentication yes" in sshd_config_content.lower().replace(" ", ""):
            log_warning("SSH permite autenticación por contraseña. Considere usar claves SSH.", control="CIS 6", safeguard="6.1", recommendation_key="access_ssh_password_auth")
    else:
        log_warning("/etc/ssh/sshd_config no encontrado. No se puede verificar la configuración de SSH.", control="CIS 6", safeguard="6.1", recommendation_key="access_ssh_config_missing")

    if os.path.exists("/etc/login.defs"):
        log_info("Políticas de contraseña (de /etc/login.defs):")
        with open("/etc/login.defs") as f:
            login_defs_content = f.read()

        found_pass_policy = False
        min_len = 0
        max_days = 99999
        warn_age = 7

        for line in login_defs_content.splitlines():
            line_stripped = line.strip()
            if not line_stripped.startswith("#"):
                if "PASS_MIN_LEN" in line_stripped:
                    try:
                        min_len = int(line_stripped.split()[1])
                        print(f"  - {line_stripped}")
                        found_pass_policy = True
                    except (ValueError, IndexError): pass
                elif "PASS_MAX_DAYS" in line_stripped:
                    try:
                        max_days = int(line_stripped.split()[1])
                        print(f"  - {line_stripped}")
                        found_pass_policy = True
                    except (ValueError, IndexError): pass
                elif "PASS_WARN_AGE" in line_stripped:
                    try:
                        warn_age = int(line_stripped.split()[1])
                        print(f"  - {line_stripped}")
                        found_pass_policy = True
                    except (ValueError, IndexError): pass
        
        if min_len < 14: # CIS recomienda mínimo 14 caracteres
            log_warning(f"La longitud mínima de contraseña (PASS_MIN_LEN) es {min_len}. CIS recomienda 14.", control="CIS 6", safeguard="6.3", recommendation_key="access_password_min_len_low")
        if max_days == 99999: # Indefinido
            log_warning("La caducidad de contraseñas (PASS_MAX_DAYS) está establecida en 99999 (nunca). Considere establecer una política de caducidad.", control="CIS 6", safeguard="6.3", recommendation_key="access_password_no_expiry")
        if warn_age < 7: # Aviso con poca antelación
            log_warning(f"La advertencia de caducidad (PASS_WARN_AGE) es {warn_age} días. Considere un valor mayor (ej. 7 días).", control="CIS 6", safeguard="6.3", recommendation_key="access_password_warn_age_low")

        if not found_pass_policy:
            log_info("No se encontraron políticas de contraseña explícitas en /etc/login.defs.")
    else:
        log_warning("/etc/login.defs no encontrado. No se pueden verificar las políticas de contraseña del sistema.", control="CIS 6", safeguard="6.3", recommendation_key="access_login_defs_missing")

    log_info("Verificando permisos de archivos críticos:")
    critical_files = ["/etc/passwd", "/etc/shadow", "/etc/group", "/etc/sudoers"]
    for file in critical_files:
        if os.path.exists(file):
            perms = run_command(f"ls -l {shlex.quote(file)} | awk '{{print $1, $3, $4}}'", shell=True)
            if perms:
                print(f"  - {file}: {perms}")
                # Verificaciones específicas de permisos
                if file == "/etc/passwd" and ("-rw-r--r--" not in perms):
                    log_warning(f"Permisos de {file} no son los esperados (-rw-r--r--). Revisar.", control="CIS 6", safeguard="6.5", recommendation_key="access_passwd_permissions")
                elif file == "/etc/shadow" and ("-rw-r-----" not in perms and "-r--------" not in perms):
                    log_warning(f"Permisos de {file} no son los esperados (-rw-r----- o -r--------). Revisar.", control="CIS 6", safeguard="6.5", recommendation_key="access_shadow_permissions")
                elif file == "/etc/sudoers" and ("-r--r-----" not in perms and "-r--------" not in perms):
                    log_warning(f"Permisos de {file} no son los esperados (-r--r----- o -r--------). Revisar.", control="CIS 6", safeguard="6.5", recommendation_key="access_sudoers_permissions")
            else:
                log_warning(f"No se pudieron obtener los permisos de {file}.", control="CIS 6", safeguard="6.5", recommendation_key="access_critical_file_perms_check_failed")
        else:
            log_error(f"Archivo crítico no encontrado: {file}", control="CIS 6", safeguard="6.5", recommendation_key="access_critical_file_missing")


def check_audit_logs():
    """Realiza el Control 8."""
    log_section("Control 8: Gestión de Logs")

    log_info("Estado de servicios de logging:")
    logging_services = ["rsyslog", "syslog-ng", "journald", "auditd"]
    active_loggers = []
    if check_command_exists("systemctl"):
        for service in logging_services:
            status = run_command(f"systemctl is-active {shlex.quote(service)}", shell=True)
            print(f"  - {service}: {status if status else 'inactive'}")
            if status == "active":
                active_loggers.append(service)
        
        if not active_loggers:
            log_warning("Ningún servicio de logging común (rsyslog, syslog-ng, journald, auditd) está activo. Los logs son críticos para la seguridad.", control="CIS 8", safeguard="8.1", recommendation_key="logs_no_logger_active")
        
        if "auditd" not in active_loggers:
             log_warning("El servicio auditd no está activo. Considere habilitarlo para una auditoría de eventos de sistema más detallada.", control="CIS 8", safeguard="8.6", recommendation_key="logs_auditd_inactive")

    else:
        log_warning("systemctl no disponible. No se pueden obtener el estado de los servicios de logging.", control="CIS 8", safeguard="8.1", recommendation_key="logs_systemctl_missing")

    log_info("Tamaño de logs principales en /var/log (top 10):")
    log_dirs = "/var/log"
    if os.path.isdir(log_dirs):
        du_output = run_command(f"du -sh {shlex.quote(log_dirs)}/* 2>/dev/null | sort -hr | head -10", shell=True)
        if du_output:
            for line in du_output.splitlines():
                print(f"  - {line}")
        else:
            log_warning("No se pudieron determinar los tamaños de los logs en /var/log (¿problemas de permisos?).", control="CIS 8", safeguard="8.2", recommendation_key="logs_var_log_unreadable")
    else:
        log_error(f"Directorio de logs {log_dirs} no encontrado.", control="CIS 8", safeguard="8.2", recommendation_key="logs_var_log_missing")

    if os.path.exists("/etc/audit/auditd.conf"):
        log_info("Configuración de Auditd:")
        with open("/etc/audit/auditd.conf") as f:
            auditd_config_content = f.read()
        
        found_auditd_config = False
        for line in auditd_config_content.splitlines():
            line_stripped = line.strip()
            if not line_stripped.startswith("#") and any(keyword in line_stripped for keyword in ["log_file", "max_log_file", "num_logs", "flush"]):
                print(f"  - {line_stripped}")
                found_auditd_config = True
        if not found_auditd_config:
            log_warning("No se encontraron configuraciones clave de auditd en /etc/audit/auditd.conf. Revise su configuración.", control="CIS 8", safeguard="8.6", recommendation_key="logs_auditd_config_missing_details")
    else:
        log_warning("/etc/audit/auditd.conf no encontrado. Auditd podría no estar configurado o instalado, limitando la visibilidad de eventos.", control="CIS 8", safeguard="8.6", recommendation_key="logs_auditd_conf_file_missing")


def check_secure_configuration_management():
    """
    Control 11: Gestión de Configuración Segura
    Verifica directorios con permisos 777 y busca cuentas por defecto.
    """
    log_section("Control 11: Gestión de Configuración Segura")

    log_info("Buscando directorios con permisos globales de escritura (777) en ubicaciones clave:")
    search_paths = ["/tmp", "/var/tmp", "/dev/shm"]
    found_world_writable = False
    for path in search_paths:
        if os.path.isdir(path):
            world_writable_dirs = run_command(f"find {shlex.quote(path)} -xdev -type d -perm 0777 2>/dev/null", shell=True)
            if world_writable_dirs:
                for d in world_writable_dirs.splitlines():
                    log_warning(f"  - Directorio con permisos 777: {d}. Cambie permisos a 755 o 700 si no es necesario.", control="CIS 11", safeguard="11.2", recommendation_key="config_world_writable_dir")
                    found_world_writable = True
    if not found_world_writable:
        log_info("  No se encontraron directorios con permisos 777 en las ubicaciones clave.")
    else:
        log_warning("  Los directorios con permisos 777 pueden ser un riesgo de seguridad.", control="CIS 11", safeguard="11.2", recommendation_key="config_world_writable_overall")

    log_info("Verificando cuentas por defecto comunes:")
    common_default_users = ["guest", "admin", "test", "ftpuser"] # 'ubuntu' handled dynamically
    found_default_user_issue = False
    
    current_distro_id = get_linux_distribution_name()

    for user in common_default_users:
        # Verificar si el usuario existe
        if run_command(f"id -u {shlex.quote(user)}", shell=True):
            log_warning(f"  - Posible cuenta por defecto activa: {user}. Considere deshabilitarla o eliminarla si no es necesaria, o cambiar la contraseña fuerte.", control="CIS 11", safeguard="11.6", recommendation_key="config_default_user_active")
            found_default_user_issue = True
    
    # Manejo específico para la cuenta 'ubuntu' en sistemas Ubuntu
    if "ubuntu" in current_distro_id:
        if run_command(f"id -u ubuntu", shell=True):
            log_info(f"  - La cuenta 'ubuntu' existe (esperado en sistemas Ubuntu). Asegúrese de que tenga una contraseña fuerte o use autenticación por clave.")
        else:
            log_warning("  Sistema Ubuntu pero la cuenta 'ubuntu' no fue encontrada. Esto es inusual.", control="CIS 11", safeguard="11.6", recommendation_key="config_ubuntu_user_missing")
    else: # Si no es Ubuntu, y la cuenta 'ubuntu' existe
        if run_command(f"id -u ubuntu", shell=True):
            log_warning(f"  - Se encontró la cuenta 'ubuntu' en un sistema que no es Ubuntu. Considere deshabilitarla o eliminarla.", control="CIS 11", safeguard="11.6", recommendation_key="config_ubuntu_user_non_ubuntu_system")


    if not found_default_user_issue and not ("ubuntu" in current_distro_id and run_command(f"id -u ubuntu", shell=True)):
        log_info(f"  No se encontraron cuentas por defecto comunes activas.")


def check_malware_defense():
    """Realiza el Control 10."""
    log_section("Control 10: Defensa contra Malware")

    antivirus_tools = ["clamav", "rkhunter", "chkrootkit"]
    log_info("Herramientas de defensa contra malware instaladas:")
    found_tool = False
    for tool in antivirus_tools:
        if check_command_exists(tool):
            log_info(f"  - {tool} está instalado.")
            found_tool = True
    if not found_tool:
        log_warning("No se encontraron herramientas de defensa contra malware comunes (ClamAV, Rkhunter, Chkrootkit). Considere instalar y configurar al menos una.", control="CIS 10", safeguard="10.1", recommendation_key="malware_no_antivirus_tools")

    if os.path.exists("/etc/apt/apt.conf.d/20auto-upgrades"):
        log_info("Actualizaciones automáticas (APT) configuradas:")
        with open("/etc/apt/apt.conf.d/20auto-upgrades") as f:
            auto_upgrades_content = f.read()
        
        found_auto_upgrade_config = False
        for line in auto_upgrades_content.splitlines():
            line_stripped = line.strip()
            if not line_stripped.startswith("#") and line_stripped.startswith("APT::"):
                print(f"  - {line_stripped}")
                found_auto_upgrade_config = True
        if not found_auto_upgrade_config:
            log_warning("No se encontraron configuraciones explícitas de actualizaciones automáticas APT. Asegúrese de que las actualizaciones de seguridad se apliquen de forma regular.", control="CIS 10", safeguard="10.2", recommendation_key="malware_no_auto_updates_config")
    else:
        log_warning("/etc/apt/apt.conf.d/20auto-upgrades no encontrado. Las actualizaciones automáticas APT pueden no estar configuradas. Verifique la política de parches.", control="CIS 10", safeguard="10.2", recommendation_key="malware_auto_updates_file_missing")

    if os.path.isdir("/etc/apt/sources.list.d"):
        log_info("Repositorios de software adicionales (no estándar):")
        found_repo = False
        for root, _, files in os.walk("/etc/apt/sources.list.d"):
            for file in files:
                if file.endswith(".list"):
                    print(f"  - {os.path.join(root, file)}")
                    log_warning(f"Repositorio adicional detectado: {os.path.join(root, file)}. Asegúrese de que sean fuentes confiables.", control="CIS 10", safeguard="10.3", recommendation_key="malware_third_party_repo")
                    found_repo = True
        if not found_repo:
            log_info("No se encontraron repositorios adicionales en /etc/apt/sources.list.d.")
    else:
        log_info("Directorio /etc/apt/sources.list.d no encontrado (no basado en Debian/APT).")


def check_network_vulnerabilities():
    """Realiza el Control 12."""
    log_section("Control 12: Vulnerabilidades de Red")
    log_info("Verificando protocolos inseguros:")

    if check_command_exists("telnet"):
        log_warning("Telnet está instalado. Es un protocolo inseguro para acceso remoto. Considere desinstalarlo.", control="CIS 12", safeguard="12.1", recommendation_key="network_telnet_installed")
    else:
        log_info("Telnet no está instalado.")

    ftp_servers = run_command("pgrep -x 'vsftpd|proftpd|pure-ftpd'", shell=True)
    if ftp_servers:
        log_warning("Servidor FTP (vsftpd, proftpd, pure-ftpd) en ejecución. Considere usar SFTP/FTPS para la transferencia segura de archivos.", control="CIS 12", safeguard="12.1", recommendation_key="network_ftp_server_running")
    else:
        log_info("No se encontraron servidores FTP comunes en ejecución.")

    if check_command_exists("openssl"):
        log_info("Verificando certificados SSL locales (antiguos):")
        old_certs = run_command("find /etc/ssl/certs -name '*.pem' -mtime +365 2>/dev/null", shell=True)
        if old_certs:
            for cert in old_certs.splitlines():
                log_warning(f"  - Certificado antiguo o caducado (>1 año): {cert}. Renueve o reemplace certificados antiguos.", control="CIS 12", safeguard="12.2", recommendation_key="network_old_ssl_cert")
        else:
            log_info("No se encontraron certificados SSL antiguos en /etc/ssl/certs.")
    else:
        log_warning("openssl no disponible. No se puede verificar la antigüedad de los certificados SSL.", control="CIS 12", safeguard="12.2", recommendation_key="network_openssl_missing_cert_check")

    log_info("Configuración de red (IP Forwarding):")
    ip_forward_path = "/proc/sys/net/ipv4/ip_forward"
    if os.path.exists(ip_forward_path):
        with open(ip_forward_path) as f:
            ip_forward = f.read().strip()
            if ip_forward == "1":
                log_warning("IP forwarding habilitado. Puede ser un riesgo si no es intencional (ej: router). Desactívelo si el sistema no es un router.", control="CIS 12", safeguard="12.3", recommendation_key="network_ip_forwarding_enabled")
            else:
                log_info("IP forwarding deshabilitado.")
    else:
        log_warning("Archivo /proc/sys/net/ipv4/ip_forward no encontrado.", control="CIS 12", safeguard="12.3", recommendation_key="network_ip_forwarding_file_missing")


def check_system_integrity():
    """Realiza el Control Adicional (existente)."""
    log_section("Control Adicional: Integridad del Sistema")

    log_info("Archivos con permisos SUID/SGID (primeros 20):")
    suid_sgid_files = run_command("find /usr /bin /sbin -type f -perm /6000 2>/dev/null | head -20", shell=True)
    if suid_sgid_files:
        for file in suid_sgid_files.splitlines():
            perms = run_command(f"ls -l {shlex.quote(file)} | awk '{{print $1}}'", shell=True)
            log_warning(f"  - Archivo SUID/SGID: {file} ({perms if perms else 'permisos no obtenidos'}). Revise estos archivos cuidadosamente.", control="CIS Adicional", safeguard="Integridad", recommendation_key="integrity_suid_sgid_file")
    else:
        log_info("No se encontraron archivos SUID/SGID en los directorios comunes o el comando falló.")

    log_info("Trabajos cron del sistema (/etc/cron.d/ y crontab de usuarios):")
    cron_d_path = "/etc/cron.d"
    if os.path.isdir(cron_d_path):
        cron_files = run_command(f"ls -la {shlex.quote(cron_d_path)}/ 2>/dev/null | grep -v '^total'", shell=True)
        if cron_files:
            log_info(f"  Archivos en {cron_d_path}:")
            for line in cron_files.splitlines():
                print(f"    - {line}")
        else:
            log_info(f"  No se encontraron archivos cron en {cron_d_path}.")
    else:
        log_warning(f"Directorio {cron_d_path} no encontrado.", control="CIS Adicional", safeguard="Integridad", recommendation_key="integrity_cron_d_missing")
    
    log_info("  Crontab de usuarios (no vacíos):")
    if check_command_exists("getent") and check_command_exists("crontab"):
        users = run_command("getent passwd | cut -d: -f1", shell=True)
        if users:
            found_user_crontabs = False
            for user in users.splitlines():
                user_crontab = run_command(f"sudo crontab -l -u {shlex.quote(user)} 2>/dev/null", shell=True)
                if user_crontab and "no crontab for" not in user_crontab.lower():
                    log_warning(f"    - Crontab para usuario '{user}':\n{user_crontab.strip()}. Revise las tareas programadas de usuarios.", control="CIS Adicional", safeguard="Integridad", recommendation_key="integrity_user_crontab_found")
                    found_user_crontabs = True
            if not found_user_crontabs:
                log_info("    - No se encontraron crontabs personalizados para usuarios.")
        else:
            log_warning("  No se pudieron obtener la lista de usuarios para verificar crontabs.", control="CIS Adicional", safeguard="Integridad", recommendation_key="integrity_getent_missing_for_crontab")
    else:
        log_warning("  Comandos 'getent' o 'crontab' no disponibles. No se pueden verificar crontabs de usuarios.", control="CIS Adicional", safeguard="Integridad", recommendation_key="integrity_crontab_tools_missing")


    log_info("Procesos con alta utilización de CPU (top 10):")
    high_cpu_processes = run_command("ps aux --sort=-%cpu | head -11 | tail -10", shell=True)
    if high_cpu_processes:
        for line in high_cpu_processes.splitlines():
            print(f"  - {line}")
        # Advertir si algún proceso consume más del X% (ej. 80%) y no es 'kworker' o 'systemd'
        for line in high_cpu_processes.splitlines():
            parts = line.split()
            try:
                cpu_usage = float(parts[2])
                process_name = parts[10] if len(parts) > 10 else parts[9] # CMD
                if cpu_usage > 80.0 and "kworker" not in process_name and "systemd" not in process_name and "python3" not in process_name: # Excluir el propio script
                    log_warning(f"Proceso '{process_name}' consume alta CPU ({cpu_usage}%). Investigue si es un proceso malicioso o descontrolado.", control="CIS Adicional", safeguard="Integridad", recommendation_key="integrity_high_cpu_process")
            except (ValueError, IndexError):
                pass
    else:
        log_info("No se pudieron obtener los procesos con alta utilización de CPU.")


def _parse_config_last_wins(path):
    """
    Parsea un archivo de configuración estilo clave-valor (sshd_config,
    login.defs): ignora líneas vacías y comentarios (#) y devuelve un dict
    {clave_en_minusculas: valor} donde la última directiva gana.
    Soporta separadores por espacio y 'clave = valor'. Solo lectura.
    Retorna None si el archivo no se puede leer.
    """
    values = {}
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for raw_line in f:
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                code = line.split("#", 1)[0].strip()
                if not code:
                    continue
                tokens = code.replace("=", " ").split()
                if len(tokens) >= 2:
                    values[tokens[0].lower()] = tokens[1]
    except OSError:
        return None
    return values


def check_ssh_hardening_scap():
    """
    Endurecimiento SSH inspirado en SCAP/ComplianceAsCode (solo lectura).
    Parsea /etc/ssh/sshd_config ignorando comentarios; la última directiva
    gana. Nota: los bloques 'Match' e 'Include' pueden alterar la
    configuración efectiva; verifíquela con 'sudo sshd -T'.
    """
    log_section("Endurecimiento SSH (SCAP/CCA, solo lectura)")
    sshd_path = "/etc/ssh/sshd_config"
    if not os.path.exists(sshd_path):
        log_warning(f"{sshd_path} no encontrado. No se puede auditar el endurecimiento SSH.", control="CIS 6", safeguard="6.1", recommendation_key="scap_ssh_config_missing")
        return
    config = _parse_config_last_wins(sshd_path)
    if config is None:
        log_warning(f"No se pudo leer {sshd_path} (¿permisos? reejecute con sudo).", control="CIS 6", safeguard="6.1", recommendation_key="scap_ssh_config_missing")
        return
    log_info("Nota: auditoría sobre el archivo; la configuración efectiva puede variar por bloques Match/Include (verifique con 'sudo sshd -T').")

    permit_root = config.get("permitrootlogin")
    if permit_root is None:
        log_info("PermitRootLogin no definido en sshd_config (por defecto 'prohibit-password'). Se recomienda 'no'.")
    elif permit_root.lower() != "no":
        log_warning(f"SSH PermitRootLogin es '{permit_root}'. El login directo como root por SSH no es recomendado.", control="CIS 6", safeguard="6.1", recommendation_key="scap_ssh_permit_root")
    else:
        log_info("SSH PermitRootLogin: no (correcto).")

    password_auth = config.get("passwordauthentication")
    if password_auth is None:
        log_warning("SSH PasswordAuthentication no definido (por defecto 'yes'). Considere usar solo claves SSH.", control="CIS 6", safeguard="6.2", recommendation_key="scap_ssh_password_auth")
    elif password_auth.lower() != "no":
        log_warning(f"SSH PasswordAuthentication es '{password_auth}'. Considere usar autenticación por claves SSH.", control="CIS 6", safeguard="6.2", recommendation_key="scap_ssh_password_auth")
    else:
        log_info("SSH PasswordAuthentication: no (correcto).")

    x11 = config.get("x11forwarding")
    if x11 is None:
        log_info("X11Forwarding no definido (por defecto 'no').")
    elif x11.lower() != "no":
        log_warning(f"SSH X11Forwarding es '{x11}'. Desactívelo si no necesita reenvío gráfico.", control="CIS 4", safeguard="4.8", recommendation_key="scap_ssh_x11_forward")
    else:
        log_info("SSH X11Forwarding: no (correcto).")

    max_tries = config.get("maxauthtries")
    if max_tries is None:
        log_warning("SSH MaxAuthTries no definido (por defecto 6). Se recomienda 4 o menos.", control="CIS 6", safeguard="6.2", recommendation_key="scap_ssh_max_auth_tries")
    else:
        try:
            if int(max_tries) > 4:
                log_warning(f"SSH MaxAuthTries es {max_tries}. Se recomienda 4 o menos para limitar ataques de fuerza bruta.", control="CIS 6", safeguard="6.2", recommendation_key="scap_ssh_max_auth_tries")
            else:
                log_info(f"SSH MaxAuthTries: {max_tries} (correcto).")
        except ValueError:
            log_warning(f"SSH MaxAuthTries tiene un valor no numérico: '{max_tries}'. Revise sshd_config.", control="CIS 6", safeguard="6.2", recommendation_key="scap_ssh_max_auth_tries")

    empty_pw = config.get("permitemptypasswords")
    if empty_pw is None:
        log_info("PermitEmptyPasswords no definido (por defecto 'no').")
    elif empty_pw.lower() != "no":
        log_warning(f"SSH PermitEmptyPasswords es '{empty_pw}'. Nunca permita cuentas sin contraseña por SSH.", control="CIS 6", safeguard="6.1", recommendation_key="scap_ssh_empty_passwords")
    else:
        log_info("SSH PermitEmptyPasswords: no (correcto).")


def check_kernel_sysctl_hardening():
    """
    Parámetros sysctl de kernel/red inspirados en SCAP/CCA (solo lectura).
    Usa 'sysctl -n <clave>' sin modificar nada.
    """
    log_section("Parámetros sysctl de kernel/red (SCAP/CCA, solo lectura)")

    aslr = run_command("sysctl -n kernel.randomize_va_space", shell=True)
    if aslr is None:
        log_warning("No se pudo leer kernel.randomize_va_space (¿permisos? reejecute con sudo).", control="CIS 4", safeguard="4.8", recommendation_key="scap_sysctl_read_failed")
    elif aslr.strip() != "2":
        log_warning(f"kernel.randomize_va_space es '{aslr.strip()}' (ASLR incompleto). Se recomienda 2 (aleatorización completa).", control="CIS 4", safeguard="4.8", recommendation_key="scap_sysctl_aslr")
    else:
        log_info("kernel.randomize_va_space = 2 (ASLR completo, correcto).")

    kptr = run_command("sysctl -n kernel.kptr_restrict", shell=True)
    if kptr is None:
        log_warning("No se pudo leer kernel.kptr_restrict.", control="CIS 4", safeguard="4.8", recommendation_key="scap_sysctl_read_failed")
    else:
        try:
            if int(kptr.strip()) < 1:
                log_warning(f"kernel.kptr_restrict es {kptr.strip()}. Se recomienda >= 1 para ocultar punteros del kernel.", control="CIS 4", safeguard="4.8", recommendation_key="scap_sysctl_kptr_restrict")
            else:
                log_info(f"kernel.kptr_restrict = {kptr.strip()} (correcto).")
        except ValueError:
            log_warning(f"kernel.kptr_restrict tiene un valor inesperado: '{kptr.strip()}'.", control="CIS 4", safeguard="4.8", recommendation_key="scap_sysctl_read_failed")

    dmesg = run_command("sysctl -n kernel.dmesg_restrict", shell=True)
    if dmesg is None:
        log_warning("No se pudo leer kernel.dmesg_restrict.", control="CIS 4", safeguard="4.8", recommendation_key="scap_sysctl_read_failed")
    elif dmesg.strip() != "1":
        log_warning(f"kernel.dmesg_restrict es '{dmesg.strip()}'. Se recomienda 1 para que solo root lea el buffer del kernel.", control="CIS 4", safeguard="4.8", recommendation_key="scap_sysctl_dmesg_restrict")
    else:
        log_info("kernel.dmesg_restrict = 1 (correcto).")

    ptrace = run_command("sysctl -n kernel.yama.ptrace_scope", shell=True)
    if ptrace is None:
        log_info("No se pudo leer kernel.yama.ptrace_scope (YAMA puede no estar disponible en este kernel).")
    else:
        try:
            if int(ptrace.strip()) < 1:
                log_warning(f"kernel.yama.ptrace_scope es {ptrace.strip()}. Se recomienda >= 1 para restringir ptrace.", control="CIS 4", safeguard="4.8", recommendation_key="scap_sysctl_ptrace_scope")
            else:
                log_info(f"kernel.yama.ptrace_scope = {ptrace.strip()} (correcto).")
        except ValueError:
            log_warning(f"kernel.yama.ptrace_scope tiene un valor inesperado: '{ptrace.strip()}'.", control="CIS 4", safeguard="4.8", recommendation_key="scap_sysctl_read_failed")

    ip_forward = run_command("sysctl -n net.ipv4.ip_forward", shell=True)
    if ip_forward is None:
        log_warning("No se pudo leer net.ipv4.ip_forward.", control="CIS 4", safeguard="4.4", recommendation_key="scap_sysctl_read_failed")
    elif ip_forward.strip() != "0":
        # Excepción router: con >1 interfaz con IP global, solo informativo.
        global_count_raw = run_command("ip -4 a show scope global | grep -c inet", shell=True)
        try:
            n_ifaces = int(global_count_raw.strip()) if global_count_raw else 0
        except (ValueError, AttributeError):
            n_ifaces = 0
        if n_ifaces > 1:
            log_info(f"net.ipv4.ip_forward = {ip_forward.strip()} con {n_ifaces} interfaces con IP global: posible router, solo informativo.")
        else:
            log_warning(f"net.ipv4.ip_forward es {ip_forward.strip()}. Desactívelo (= 0) si el sistema no es un router.", control="CIS 4", safeguard="4.4", recommendation_key="scap_sysctl_ip_forward")
    else:
        log_info("net.ipv4.ip_forward = 0 (correcto).")

    rp_filter = run_command("sysctl -n net.ipv4.conf.all.rp_filter", shell=True)
    if rp_filter is None:
        log_warning("No se pudo leer net.ipv4.conf.all.rp_filter.", control="CIS 4", safeguard="4.4", recommendation_key="scap_sysctl_read_failed")
    elif rp_filter.strip() != "1":
        log_warning(f"net.ipv4.conf.all.rp_filter es '{rp_filter.strip()}'. Se recomienda 1 (filtrado de ruta inversa).", control="CIS 4", safeguard="4.4", recommendation_key="scap_sysctl_rp_filter")
    else:
        log_info("net.ipv4.conf.all.rp_filter = 1 (correcto).")


def check_suid_sgid_scap():
    """
    Binarios SUID/SGID en el sistema de archivos (solo lectura).
    Cuenta el total por separado y advierte por binarios fuera de una lista
    base conocida de utilidades legítimas.
    """
    log_section("Binarios SUID/SGID (SCAP/CCA, solo lectura)")
    known_suid = {
        "/usr/bin/sudo", "/usr/bin/su", "/usr/bin/mount", "/usr/bin/umount",
        "/usr/bin/passwd", "/usr/bin/chsh", "/usr/bin/chfn", "/usr/bin/newgrp",
        "/usr/bin/gpasswd", "/usr/bin/pkexec", "/usr/bin/sudoedit",
    }
    total_raw = run_command("find / -xdev \\( -perm -4000 -o -perm -2000 \\) -type f 2>/dev/null | wc -l", shell=True)
    if total_raw is None:
        log_warning("No se pudo contar los binarios SUID/SGID (reejecute con sudo).", control="CIS 4", safeguard="4.8", recommendation_key="scap_suid_scan_failed")
        return
    try:
        total = int(total_raw.strip())
    except ValueError:
        log_warning(f"Salida inesperada al contar binarios SUID/SGID: '{total_raw.strip()}'.", control="CIS 4", safeguard="4.8", recommendation_key="scap_suid_scan_failed")
        return
    log_info(f"Total de archivos SUID/SGID en / (mismo sistema de archivos): {total}.")

    listing = run_command("find / -xdev \\( -perm -4000 -o -perm -2000 \\) -type f 2>/dev/null | head -30", shell=True)
    if listing is None:
        log_warning("No se pudo listar los binarios SUID/SGID (reejecute con sudo).", control="CIS 4", safeguard="4.8", recommendation_key="scap_suid_scan_failed")
        return
    listed = [p.strip() for p in listing.splitlines() if p.strip()]
    unexpected = [p for p in listed if p not in known_suid]
    if unexpected:
        log_info(f"Primeros {len(listed)} resultados (lista truncada a 30):")
        for path in unexpected:
            log_warning(f"Binario SUID/SGID fuera de la lista base conocida: {path}. Verifique si es legítimo.", control="CIS 4", safeguard="4.8", recommendation_key="scap_suid_unexpected")
    else:
        log_info("Todos los binarios SUID/SGID listados pertenecen a la lista base conocida.")
    if total > 30:
        log_info(f"La lista se truncó a 30 de {total} resultados; audite el resto con: find / -xdev ( -perm -4000 -o -perm -2000 ) -type f 2>/dev/null")


def check_login_defs_scap():
    """
    Política de contraseñas y UMASK en /etc/login.defs (solo lectura).
    """
    log_section("Política login.defs (SCAP/CCA, solo lectura)")
    login_defs_path = "/etc/login.defs"
    if not os.path.exists(login_defs_path):
        log_warning(f"{login_defs_path} no encontrado. No se puede auditar la política de contraseñas.", control="CIS 5", safeguard="5.4", recommendation_key="scap_logindefs_missing")
        return
    config = _parse_config_last_wins(login_defs_path)
    if config is None:
        log_warning(f"No se pudo leer {login_defs_path} (¿permisos? reejecute con sudo).", control="CIS 5", safeguard="5.4", recommendation_key="scap_logindefs_missing")
        return

    max_days_raw = config.get("pass_max_days")
    if max_days_raw is None:
        log_info("PASS_MAX_DAYS no definido en /etc/login.defs.")
    else:
        try:
            max_days = int(max_days_raw)
            if max_days <= 0:
                log_warning("PASS_MAX_DAYS <= 0: las contraseñas nunca caducan. Se recomienda 90 (máx. 365).", control="CIS 5", safeguard="5.4", recommendation_key="scap_logindefs_max_days")
            elif max_days > 365:
                log_warning(f"PASS_MAX_DAYS es {max_days} (> 365). Se recomienda 90 (máx. 365).", control="CIS 5", safeguard="5.4", recommendation_key="scap_logindefs_max_days")
            else:
                log_info(f"PASS_MAX_DAYS = {max_days} (correcto, <= 365).")
        except ValueError:
            log_warning(f"PASS_MAX_DAYS tiene un valor no numérico: '{max_days_raw}'.", control="CIS 5", safeguard="5.4", recommendation_key="scap_logindefs_max_days")

    min_days_raw = config.get("pass_min_days")
    if min_days_raw is None:
        log_warning("PASS_MIN_DAYS no definido (por defecto 0: se permite cambiar la contraseña de inmediato). Se recomienda >= 1.", control="CIS 5", safeguard="5.4", recommendation_key="scap_logindefs_min_days")
    else:
        try:
            if int(min_days_raw) < 1:
                log_warning(f"PASS_MIN_DAYS es {min_days_raw}. Se recomienda >= 1 para evitar cambios cíclicos inmediatos.", control="CIS 5", safeguard="5.4", recommendation_key="scap_logindefs_min_days")
            else:
                log_info(f"PASS_MIN_DAYS = {min_days_raw} (correcto).")
        except ValueError:
            log_warning(f"PASS_MIN_DAYS tiene un valor no numérico: '{min_days_raw}'.", control="CIS 5", safeguard="5.4", recommendation_key="scap_logindefs_min_days")

    warn_age_raw = config.get("pass_warn_age")
    if warn_age_raw is None:
        log_info("PASS_WARN_AGE no definido en /etc/login.defs.")
    else:
        try:
            if int(warn_age_raw) < 7:
                log_warning(f"PASS_WARN_AGE es {warn_age_raw}. Se recomienda >= 7 días de aviso.", control="CIS 5", safeguard="5.4", recommendation_key="scap_logindefs_warn_age")
            else:
                log_info(f"PASS_WARN_AGE = {warn_age_raw} (correcto).")
        except ValueError:
            log_warning(f"PASS_WARN_AGE tiene un valor no numérico: '{warn_age_raw}'.", control="CIS 5", safeguard="5.4", recommendation_key="scap_logindefs_warn_age")

    umask = config.get("umask")
    if umask is None:
        log_info("UMASK no definido en /etc/login.defs.")
    elif umask.strip() in ("027", "077"):
        log_info(f"UMASK = {umask.strip()} (correcto).")
    else:
        log_warning(f"UMASK es '{umask.strip()}'. Se recomienda 027 o 077 para evitar archivos legibles por otros.", control="CIS 5", safeguard="5.4", recommendation_key="scap_logindefs_umask")


def check_sudo_nopasswd_scap():
    """
    Entradas NOPASSWD en sudoers (solo lectura). Ignora líneas comentadas.
    """
    log_section("sudo NOPASSWD (SCAP/CCA, solo lectura)")
    output = run_command("grep -r NOPASSWD /etc/sudoers /etc/sudoers.d/ 2>/dev/null", shell=True)
    if output is None:
        if not os.path.exists("/etc/sudoers") and not os.path.isdir("/etc/sudoers.d"):
            log_info("No existe /etc/sudoers ni /etc/sudoers.d (sudo podría no estar instalado).")
        else:
            log_info("Sin coincidencias de NOPASSWD o sin permiso de lectura (reejecute con sudo para confirmar).")
        return
    if not output.strip():
        log_info("No se encontraron entradas NOPASSWD en sudoers (correcto).")
        return
    found = False
    for line in output.splitlines():
        content = line.split(":", 1)[1] if ":" in line else line
        stripped = content.strip()
        if not stripped or stripped.startswith("#"):
            continue
        code = stripped.split("#", 1)[0]
        if "NOPASSWD" in code:
            found = True
            log_warning(f"Entrada NOPASSWD en sudoers: {line.strip()}. Exija contraseña salvo excepciones justificadas.", control="CIS 5", safeguard="5.4", recommendation_key="scap_sudo_nopasswd")
    if not found:
        log_info("Las menciones de NOPASSWD encontradas estaban comentadas (sin efecto).")


def check_pam_pwquality_faillock():
    """
    Calidad de contraseñas (pwquality minlen >= 12) y bloqueo por intentos
    fallidos (pam_faillock) (solo lectura, solo informativo).
    """
    log_section("PAM pwquality/faillock (SCAP/CCA, solo lectura)")
    pwquality_path = "/etc/security/pwquality.conf"
    if os.path.exists(pwquality_path):
        minlen = None
        try:
            with open(pwquality_path, "r", encoding="utf-8", errors="ignore") as f:
                for raw_line in f:
                    line = raw_line.strip()
                    if not line or line.startswith("#"):
                        continue
                    code = line.split("#", 1)[0].replace("=", " ").split()
                    for i, token in enumerate(code):
                        if token.lower() == "minlen" and i + 1 < len(code):
                            try:
                                minlen = int(code[i + 1])
                            except ValueError:
                                pass
            if minlen is None:
                log_info("pwquality.conf existe pero no define minlen. Se recomienda minlen >= 12.")
            elif minlen >= 12:
                log_info(f"pwquality minlen = {minlen} (correcto, >= 12).")
            else:
                log_info(f"pwquality minlen = {minlen}. Se recomienda minlen >= 12 para contraseñas robustas.")
        except OSError:
            log_info(f"No se pudo leer {pwquality_path} (¿permisos? reejecute con sudo).")
    else:
        log_info(f"{pwquality_path} no existe. Considere instalar libpam-pwquality y fijar minlen >= 12.")

    faillock_found = False
    for pam_file in ("/etc/pam.d/common-auth", "/etc/pam.d/system-auth"):
        if os.path.exists(pam_file):
            try:
                with open(pam_file, "r", encoding="utf-8", errors="ignore") as f:
                    for raw_line in f:
                        line = raw_line.strip()
                        if not line or line.startswith("#"):
                            continue
                        if "pam_faillock.so" in line.split("#", 1)[0]:
                            faillock_found = True
                            log_info(f"pam_faillock configurado en {pam_file} (correcto).")
                            break
            except OSError:
                log_info(f"No se pudo leer {pam_file} (¿permisos? reejecute con sudo).")
    if not faillock_found:
        log_info("No se detectó pam_faillock en /etc/pam.d/common-auth ni system-auth. Considere habilitarlo para bloquear cuentas tras intentos fallidos.")


def check_unattended_upgrades_scap():
    """
    Actualizaciones desatendidas: APT (20auto-upgrades con Unattended-Upgrade
    "1") o dnf-automatic.timer (solo lectura, aviso leve).
    """
    log_section("Actualizaciones desatendidas (SCAP/CCA, solo lectura)")
    apt_conf = "/etc/apt/apt.conf.d/20auto-upgrades"
    if os.path.exists(apt_conf):
        try:
            with open(apt_conf, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            enabled = any(
                "unattended-upgrade" in line.split("#", 1)[0].lower() and '"1"' in line
                for line in content.splitlines()
            )
            if enabled:
                log_info("Actualizaciones desatendidas APT activas (Unattended-Upgrade \"1\", correcto).")
            else:
                log_warning(f"{apt_conf} no activa Unattended-Upgrade \"1\". Active los parches de seguridad automáticos.", control="CIS 7", safeguard="7.3", recommendation_key="scap_patch_apt_unattended")
        except OSError:
            log_info(f"No se pudo leer {apt_conf} (¿permisos? reejecute con sudo).")
    elif check_command_exists("dnf") or check_command_exists("yum"):
        timer = run_command("systemctl is-enabled dnf-automatic.timer", shell=True)
        if timer and timer.strip() == "enabled":
            log_info("dnf-automatic.timer habilitado (correcto).")
        else:
            log_warning("dnf-automatic.timer no está habilitado. Active los parches automáticos.", control="CIS 7", safeguard="7.3", recommendation_key="scap_patch_dnf_automatic")
    else:
        log_info("Sistema sin APT ni DNF/YUM detectables; verifique manualmente la política de parches automáticos.")


def check_core_dumps_scap():
    """
    Volcados de memoria (core dumps): kernel.core_pattern y fs.suid_dumpable
    (solo lectura). fs.suid_dumpable = 0 correcto, = 2 advertencia.
    """
    log_section("Volcados core (SCAP/CCA, solo lectura)")
    pattern = run_command("sysctl -n kernel.core_pattern", shell=True)
    if pattern is None:
        log_info("No se pudo leer kernel.core_pattern (¿permisos? reejecute con sudo).")
    else:
        log_info(f"kernel.core_pattern = {(pattern.strip() or '(vacío)')}. Restrinja los volcados si contienen datos sensibles.")

    dumpable = run_command("sysctl -n fs.suid_dumpable", shell=True)
    if dumpable is None:
        log_info("No se pudo leer fs.suid_dumpable (¿permisos? reejecute con sudo).")
    elif dumpable.strip() == "0":
        log_info("fs.suid_dumpable = 0 (correcto: los binarios setuid no generan core).")
    elif dumpable.strip() == "2":
        log_warning("fs.suid_dumpable = 2: los binarios setuid generan volcados. Fije fs.suid_dumpable = 0.", control="CIS 4", safeguard="4.8", recommendation_key="scap_core_suid_dumpable")
    else:
        log_warning(f"fs.suid_dumpable = {dumpable.strip()}. Se recomienda 0.", control="CIS 4", safeguard="4.8", recommendation_key="scap_core_suid_dumpable")


def check_dependencies():
    """Verifica si las herramientas básicas necesarias están disponibles."""
    missing_deps = []
    basic_tools = ["grep", "awk", "ps", "ls", "cat", "find"] # Ya se chequea dmidecode, ss/netstat, etc. en las funciones específicas

    for tool in basic_tools:
        if not check_command_exists(tool):
            missing_deps.append(tool)

    if missing_deps:
        log_error(f"Herramientas básicas faltantes: {', '.join(missing_deps)}. Por favor, asegúrese de que estén instaladas y accesibles en el PATH.", recommendation_key="dependency_missing_basic_tools")
        exit(1)


# Diccionario de recomendaciones basadas en las claves de hallazgos
RECOMMENDATIONS_MAP = {
    "hardware_ram_parse_fail": "Asegúrese de que el sistema pueda reportar correctamente la memoria RAM.",
    "hardware_no_ipv4_interfaces": "Verifique la configuración de red y asegúrese de que las interfaces IPv4 estén activas y configuradas correctamente.",
    "hardware_ip_command_missing": "Instale el paquete 'iproute2' (que provee el comando 'ip') para obtener información de red detallada.",
    "hardware_lsusb_missing": "Instale 'usbutils' (sudo apt install usbutils / sudo yum install usbutils) para auditar dispositivos USB.",
    "hardware_no_pci_devices": "Si este no es un entorno virtualizado, investigue por qué no se detectan dispositivos PCI.",
    "hardware_lspci_missing": "Instale 'pciutils' (sudo apt install pciutils / sudo yum install pciutils) para auditar dispositivos PCI.",
    "hardware_dmidecode_info_missing": "Asegúrese de que 'dmidecode' se ejecute con privilegios suficientes y que el BIOS/UEFI proporcione los datos DMI.",
    "hardware_dmidecode_missing": "Instale 'dmidecode' (sudo apt install dmidecode / sudo yum install dmidecode) para obtener detalles del sistema.",

    "software_no_package_manager": "Instale un gestor de paquetes (ej. `apt` para Debian/Ubuntu, `dnf`/`yum` para RedHat/CentOS) y utilícelo para gestionar el software.",
    "software_dpkg_log_missing": "Asegúrese de que el registro de paquetes (dpkg.log) esté disponible y legible para auditar instalaciones recientes.",
    "software_journalctl_missing": "Asegúrese de que systemd-journald esté en ejecución y que `journalctl` esté disponible para auditar logs de paquetes.",
    "software_distro_detection_fail": "Verifique la integridad de '/etc/os-release' o actualice Python si es una versión antigua.",
    "software_systemctl_missing": "Instale `systemd` y `systemctl` para gestionar y auditar servicios del sistema.",
    "software_suspicious_process_found": "Investigue los procesos señalados (netcat, socat, telnet) para asegurarse de que no son maliciosos y son necesarios.",

    "data_no_luks_encryption": "Considere implementar el cifrado de disco completo (LUKS) en particiones que contengan datos sensibles.",
    "data_luks_check_tools_missing": "Instale 'cryptsetup' para LUKS, que incluye herramientas como `lsblk` que ayudan a detectar el cifrado.",
    "data_no_ecryptfs_home": "Para proteger los datos de usuario en reposo, considere implementar cifrado de directorios home con eCryptfs o un método similar.",

    "network_open_to_all_interfaces": "Limite los servicios que escuchan en '0.0.0.0' a interfaces específicas, especialmente si no es un servidor público.",
    "network_ports_check_failed": "Asegúrese de que `ss` o `netstat` estén instalados y el script tenga permisos para ejecutarlos (ejecute con `sudo`).",
    "network_ufw_inactive": "Habilite UFW (sudo ufw enable) y configure las reglas para permitir solo el tráfico necesario.",
    "network_iptables_minimal": "Revise la configuración de iptables. Una política de firewall más robusta es recomendada.",
    "network_firewalld_inactive": "Habilite Firewalld (sudo systemctl start firewalld && sudo systemctl enable firewalld) y configure sus zonas y servicios.",
    "network_no_firewall": "Instale y configure una solución de firewall (UFW, Firewalld, o reglas iptables directas) para controlar el tráfico de red.",
    "network_no_active_interfaces": "Verifique la conectividad de red del sistema y la configuración de las interfaces.",
    "network_ip_command_missing_interfaces": "Instale 'iproute2' para gestionar y listar interfaces de red.",

    "accounts_passwd_missing": "/etc/passwd es un archivo crítico del sistema. Su ausencia o inaccesibilidad es una falla grave. Revise la integridad del sistema.",
    "accounts_multiple_uid0": "Solo la cuenta 'root' debe tener UID 0. Cambie el UID de otras cuentas con UID 0 o elimínelas.",
    "accounts_no_password": "Todas las cuentas deben tener contraseñas. Configure contraseñas fuertes o deshabilite las cuentas no utilizadas.",
    "accounts_shadow_unreadable": "Asegúrese de que /etc/shadow exista y que el script se ejecute con privilegios suficientes para leerlo (solo root).",
    "accounts_getent_missing_groups": "Instale 'getent' (parte de libc-bin en Debian/Ubuntu, glibc en RedHat) para auditar la pertenencia a grupos.",

    "access_ssh_root_login": "Deshabilite el inicio de sesión directo de 'root' por SSH. Utilice 'sudo' para la administración o cambie a un usuario no privilegiado.",
    "access_ssh_password_auth": "Deshabilite la autenticación por contraseña en SSH y use autenticación basada en claves SSH para mayor seguridad.",
    "access_ssh_config_missing": "Asegúrese de que el servicio SSH esté instalado y configurado correctamente, y que 'sshd_config' sea accesible.",
    "access_password_min_len_low": "Aumente 'PASS_MIN_LEN' a al menos 14 caracteres en /etc/login.defs para forzar contraseñas más seguras.",
    "access_password_no_expiry": "Establezca una política de caducidad de contraseñas (ej. `PASS_MAX_DAYS 90`) en /etc/login.defs.",
    "access_password_warn_age_low": "Aumente 'PASS_WARN_AGE' en /etc/login.defs para dar a los usuarios más tiempo para cambiar sus contraseñas antes de que expiren.",
    "access_login_defs_missing": "Asegúrese de que el archivo /etc/login.defs exista para definir políticas de contraseña del sistema.",
    "access_passwd_permissions": "Ajuste los permisos de /etc/passwd a `-rw-r--r--` (644).",
    "access_shadow_permissions": "Ajuste los permisos de /etc/shadow a `-rw-r-----` (640) o más restrictivos (ej. `000` si solo root lee).",
    "access_sudoers_permissions": "Ajuste los permisos de /etc/sudoers a `-r--r-----` (440) o más restrictivos (ej. `000` si solo root lee).",
    "access_critical_file_perms_check_failed": "Revise los permisos del archivo manualmente o asegúrese de que el script tenga permisos adecuados.",
    "access_critical_file_missing": "Archivo crítico del sistema faltante. Esto es una falla grave. Reinstale o repare el sistema.",

    "logs_no_logger_active": "Habilite al menos un servicio de logging (rsyslog, syslog-ng, journald) para registrar eventos del sistema.",
    "logs_auditd_inactive": "Habilite y configure el servicio `auditd` para un seguimiento detallado de los eventos de seguridad del sistema.",
    "logs_systemctl_missing": "Instale `systemd` y `systemctl` para gestionar y auditar servicios del sistema.",
    "logs_var_log_unreadable": "Asegúrese de que el directorio /var/log y sus contenidos sean legibles por el usuario que ejecuta el script (con sudo).",
    "logs_var_log_missing": "El directorio /var/log es fundamental para la gestión de logs. Su ausencia es una falla grave.",
    "logs_auditd_config_missing_details": "Revise y complete la configuración de `auditd` en /etc/audit/auditd.conf para asegurar una auditoría completa.",
    "logs_auditd_conf_file_missing": "Instale el paquete `auditd` y configure su archivo de configuración para auditorías de seguridad.",

    "config_world_writable_dir": "Cambie los permisos de los directorios con 777 (escritura global) a permisos más restrictivos (ej. 755 o 700) si no es estrictamente necesario.",
    "config_world_writable_overall": "Reduzca la exposición a directorios con permisos de escritura globales, ya que pueden ser puntos de entrada para atacantes.",
    "config_default_user_active": "Deshabilite o elimine las cuentas de usuario por defecto que no se utilizan para reducir la superficie de ataque.",
    "config_ubuntu_user_missing": "En sistemas Ubuntu, la ausencia de la cuenta 'ubuntu' es inusual. Verifique la instalación del sistema.",
    "config_ubuntu_user_non_ubuntu_system": "La cuenta 'ubuntu' no debería existir en sistemas que no sean Ubuntu. Desactívela o elimínela.",

    "malware_no_antivirus_tools": "Instale y configure una solución de defensa contra malware (ej. ClamAV, Rkhunter) para detectar amenazas.",
    "malware_no_auto_updates_config": "Configure actualizaciones de seguridad automáticas o establezca un proceso de parcheo regular.",
    "malware_auto_updates_file_missing": "Verifique la configuración de actualizaciones automáticas o configure un proceso de parcheo regular.",
    "malware_third_party_repo": "Revise todos los repositorios de software de terceros y asegúrese de que sean confiables y seguros.",

    "network_telnet_installed": "Desinstale el cliente Telnet si no es necesario, ya que es un protocolo inseguro.",
    "network_ftp_server_running": "Si el servidor FTP es necesario, asegure su configuración o migre a SFTP/FTPS para la transferencia segura de archivos.",
    "network_old_ssl_cert": "Renueve o reemplace los certificados SSL/TLS caducados o próximos a caducar para mantener la seguridad de las comunicaciones.",
    "network_openssl_missing_cert_check": "Instale `openssl` para verificar el estado de los certificados SSL/TLS.",
    "network_ip_forwarding_enabled": "Deshabilite el reenvío IP (`net.ipv4.ip_forward = 0` en `sysctl.conf`) si el sistema no está diseñado para ser un router.",
    "network_ip_forwarding_file_missing": "Revise la configuración de red. La ausencia de este archivo es inusual.",

    "integrity_suid_sgid_file": "Audite los archivos SUID/SGID para asegurarse de que solo los programas legítimos los utilicen y no presenten riesgos de escalada de privilegios.",
    "integrity_cron_d_missing": "Asegúrese de que el directorio /etc/cron.d/ exista y contenga solo trabajos cron autorizados.",
    "integrity_user_crontab_found": "Revise los crontabs de los usuarios para detectar tareas programadas maliciosas o no autorizadas.",
    "integrity_getent_missing_for_crontab": "Instale 'getent' para obtener la lista de usuarios y auditar sus crontabs.",
    "integrity_crontab_tools_missing": "Asegúrese de que 'crontab' y 'getent' estén instalados para una auditoría completa de los trabajos programados.",
    "integrity_high_cpu_process": "Investigue los procesos que consumen alta CPU para identificar malware, scripts maliciosos o problemas de rendimiento.",

    "scap_ssh_permit_root": "Fije 'PermitRootLogin no' en /etc/ssh/sshd_config (edite con sudo) y reinicie SSH: sudo systemctl restart ssh (o sshd). Administre con un usuario no privilegiado + sudo.",
    "scap_ssh_password_auth": "Deshabilite la autenticación por contraseña con 'PasswordAuthentication no' en /etc/ssh/sshd_config, distribuya claves SSH (ssh-copy-id) y reinicie: sudo systemctl restart ssh.",
    "scap_ssh_x11_forward": "Deshabilite el reenvío X11 con 'X11Forwarding no' en /etc/ssh/sshd_config y reinicie: sudo systemctl restart ssh.",
    "scap_ssh_max_auth_tries": "Limite los intentos con 'MaxAuthTries 4' (o menos) en /etc/ssh/sshd_config y reinicie: sudo systemctl restart ssh.",
    "scap_ssh_empty_passwords": "Fije 'PermitEmptyPasswords no' en /etc/ssh/sshd_config y reinicie: sudo systemctl restart ssh. Además, asigne o bloquee contraseñas vacías (sudo passwd -l <usuario>).",
    "scap_ssh_config_missing": "Instale OpenSSH Server (sudo apt install openssh-server / sudo dnf install openssh-server) y asegúrese de que /etc/ssh/sshd_config exista con permisos 600.",
    "scap_sysctl_aslr": "Active ASLR completo: sudo sysctl -w kernel.randomize_va_space=2 y fíjelo con: echo 'kernel.randomize_va_space = 2' | sudo tee /etc/sysctl.d/99-seguridad.conf.",
    "scap_sysctl_kptr_restrict": "Oculte punteros del kernel: sudo sysctl -w kernel.kptr_restrict=1 (o 2) y fíjelo en /etc/sysctl.d/99-seguridad.conf.",
    "scap_sysctl_dmesg_restrict": "Restrinja dmesg a root: sudo sysctl -w kernel.dmesg_restrict=1 y fíjelo en /etc/sysctl.d/99-seguridad.conf.",
    "scap_sysctl_ptrace_scope": "Restrinja ptrace: sudo sysctl -w kernel.yama.ptrace_scope=1 (o mayor) y fíjelo en /etc/sysctl.d/99-seguridad.conf.",
    "scap_sysctl_ip_forward": "Desactive el reenvío IP si no es router: sudo sysctl -w net.ipv4.ip_forward=0 y fíjelo con: echo 'net.ipv4.ip_forward = 0' | sudo tee /etc/sysctl.d/99-seguridad.conf.",
    "scap_sysctl_rp_filter": "Active el filtrado de ruta inversa: sudo sysctl -w net.ipv4.conf.all.rp_filter=1 (y default.rp_filter=1) y fíjelo en /etc/sysctl.d/99-seguridad.conf.",
    "scap_sysctl_read_failed": "Reejecute con sudo y verifique la clave con: sysctl -n <clave>. Si la clave no existe, el kernel podría no soportarla.",
    "scap_suid_unexpected": "Audite el binario señalado; si no necesita privilegios elevados, quite el bit: sudo chmod u-s,g-s <ruta>. Nunca deje SUID en editores/intérpretes (vim, less, python, find).",
    "scap_suid_scan_failed": "Reejecute con sudo: sudo find / -xdev ( -perm -4000 -o -perm -2000 ) -type f 2>/dev/null | sort.",
    "scap_logindefs_max_days": "Fije 'PASS_MAX_DAYS 90' (máximo 365) en /etc/login.defs y aplíquelo a usuarios existentes con: sudo chage -M 90 <usuario>.",
    "scap_logindefs_min_days": "Fije 'PASS_MIN_DAYS 1' (o mayor) en /etc/login.defs para impedir cambios cíclicos inmediatos.",
    "scap_logindefs_warn_age": "Fije 'PASS_WARN_AGE 7' (o mayor) en /etc/login.defs para avisar antes de la caducidad.",
    "scap_logindefs_umask": "Fije 'UMASK 027' (o 077 en sistemas estrictos) en /etc/login.defs.",
    "scap_logindefs_missing": "Restaure /etc/login.defs reinstalando el paquete login (sudo apt install --reinstall login) y revise la integridad del sistema.",
    "scap_sudo_nopasswd": "Elimine 'NOPASSWD' de /etc/sudoers y /etc/sudoers.d/ editando solo con 'sudo visudo'. Si alguna tarea lo requiere, limítelo a un comando exacto y un usuario concreto.",
    "scap_patch_apt_unattended": "Instale unattended-upgrades (sudo apt install unattended-upgrades) y active: APT::Periodic::Unattended-Upgrade \"1\"; en /etc/apt/apt.conf.d/20auto-upgrades.",
    "scap_patch_dnf_automatic": "Active parches automáticos con: sudo systemctl enable --now dnf-automatic.timer.",
    "scap_core_suid_dumpable": "Desactive volcados setuid: sudo sysctl -w fs.suid_dumpable=0 y fíjelo con: echo 'fs.suid_dumpable = 0' | sudo tee /etc/sysctl.d/99-suid-dumpable.conf."
}

def generate_dynamic_recommendations():
    """Genera recomendaciones basadas en los hallazgos registrados."""
    log_section("RECOMENDACIONES BASADAS EN HALLAZGOS")

    if not SECURITY_FINDINGS:
        log_info("No se encontraron hallazgos críticos. ¡El sistema parece bien configurado según los controles auditados!")
        return

    # Usar un set para evitar recomendaciones duplicadas
    unique_recommendations = set()

    for finding in SECURITY_FINDINGS:
        rec_key = finding.get('recommendation_key')
        control_info = f"({finding.get('control', 'N/A')}{f' - {finding.get("safeguard")}' if finding.get('safeguard') else ''})"
        
        if rec_key and rec_key in RECOMMENDATIONS_MAP:
            recommendation_text = f"[{finding['severity'].upper()}] {RECOMMENDATIONS_MAP[rec_key]} {control_info}"
            unique_recommendations.add(recommendation_text)
        else:
            # Si no hay una clave de recomendación específica, usar el mensaje del hallazgo
            generic_rec_text = f"[{finding['severity'].upper()}] Revise el hallazgo: {finding['message']} {control_info}"
            unique_recommendations.add(generic_rec_text)

    if unique_recommendations:
        print("\nLas siguientes recomendaciones se basan en los hallazgos específicos de esta auditoría:")
        for i, rec in enumerate(sorted(list(unique_recommendations))):
            print(f"{i+1}. {rec}")
    else:
        log_info("No se generaron recomendaciones específicas basadas en los hallazgos.")

def main(json_output=None):
    """Función principal que orquesta la ejecución de todos los controles."""
    print(f"{Colors.CYAN}Iniciando auditoría de Controles CIS v8.1 para Linux{Colors.NC}")
    print(f"{Colors.CYAN}Fecha: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.NC}")
    print(f"{Colors.CYAN}Sistema: {platform.node()}{Colors.NC}")
    
    current_user = os.getenv('USER') or os.getenv('LOGNAME')
    if not current_user:
        try:
            current_user = os.getlogin()
        except OSError:
            current_user = "Desconocido"
    
    print(f"{Colors.CYAN}Usuario: {current_user}{Colors.NC}")
    print("==================================================")
    print_preflight()
    print("==================================================")
    
    if os.geteuid() != 0:
        log_warning("Algunos controles pueden requerir privilegios root para obtener información completa. Se recomienda ejecutar con sudo.", recommendation_key="run_as_root_recommendation")
    
    check_hardware_inventory_enhanced()
    check_software_inventory_enhanced()
    check_data_protection()
    check_network_security()
    check_account_management()
    check_access_control()
    check_audit_logs()
    check_secure_configuration_management()
    check_malware_defense()
    check_network_vulnerabilities()
    check_system_integrity()
    check_ssh_hardening_scap()
    check_kernel_sysctl_hardening()
    check_suid_sgid_scap()
    check_login_defs_scap()
    check_sudo_nopasswd_scap()
    check_pam_pwquality_faillock()
    check_unattended_upgrades_scap()
    check_core_dumps_scap()
    
    print("\n==================================================")
    log_info("Auditoría completada exitosamente.")
    
    generate_dynamic_recommendations() # Llamada a la nueva función de recomendaciones dinámicas

    if json_output:
        with open(json_output, "w", encoding="utf-8") as f:
            json.dump(SECURITY_FINDINGS, f, indent=2, ensure_ascii=False)

# Punto de entrada del script

print("\n[!] AVISO LEGAL: Use solo con autorizacion. / LEGAL NOTICE: Authorized use only.\n")
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Auditoría de Controles CIS v8.1 para Linux")
    parser.add_argument("--json", dest="json_output", metavar="RUTA", default=None, help="Vuelca la lista SECURITY_FINDINGS a RUTA en formato JSON")
    args = parser.parse_args()
    check_dependencies()
    main(json_output=args.json_output)