import os
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



# Funciones de logging
def log_info(message):
    """Imprime un mensaje informativo en verde."""
    print(f"{Colors.GREEN}[INFO]{Colors.NC} {message}")

def log_warning(message):
    """Imprime un mensaje de advertencia en amarillo."""
    print(f"{Colors.YELLOW}[WARNING]{Colors.NC} {message}")

def log_error(message):
    """Imprime un mensaje de error en rojo."""
    print(f"{Colors.RED}[ERROR]{Colors.NC} {message}")

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
        result = subprocess.run(command, shell=shell, capture_output=capture_output, text=text, check=True, encoding='utf-8', errors='ignore')
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        # print(f"DEBUG: Comando '{command}' falló con error: {e.stderr.strip()}") # Descomentar para depuración
        return None
    except FileNotFoundError:
        # print(f"DEBUG: Comando no encontrado: {command.split()[0] if isinstance(command, str) else command[0]}") # Descomentar para depuración
        return None

def check_command_exists(command):
    """Verifica si un comando existe en el PATH del sistema."""
    return run_command(f"command -v {command}", shell=True) is not None

def check_hardware_inventory():
    """Realiza el inventario de hardware del sistema."""
    log_section("Control 1: Inventario de Hardware")

    # Información del sistema operativo
    if os.path.exists("/etc/os-release"):
        with open("/etc/os-release") as f:
            for line in f:
                if line.startswith("PRETTY_NAME="):
                    log_info(f"Sistema: {line.split('=')[1].strip().strip('\"')}")
                    break
    else:
        log_warning("Archivo /etc/os-release no encontrado. Información detallada del SO limitada.")

    log_info(f"Kernel: {platform.release()}")
    log_info(f"Arquitectura: {platform.machine()}")

    # Información de memoria RAM
    if os.path.exists("/proc/meminfo"):
        meminfo = run_command("grep MemTotal /proc/meminfo", shell=True)
        if meminfo:
            try:
                total_mem_kb = int(meminfo.split()[1])
                total_mem_gb = round(total_mem_kb / (1024 * 1024), 2)
                log_info(f"RAM Total: {total_mem_gb} GB")
            except (ValueError, IndexError):
                log_warning("No se pudo parsear la información de RAM de /proc/meminfo.")
        else:
            log_warning("No se encontró 'MemTotal' en /proc/meminfo.")
    else:
        log_warning("Archivo /proc/meminfo no encontrado. No se puede obtener información de RAM.")

    # Dispositivos USB
    log_info("Dispositivos USB conectados:")
    if check_command_exists("lsusb"):
        usb_devices = run_command("lsusb", shell=True)
        if usb_devices:
            for line in usb_devices.splitlines():
                print(f"  - {line}")
        else:
            log_info("No se detectaron dispositivos USB.")
    else:
        log_warning("lsusb no disponible. Instálelo (ej: sudo apt install usbutils) para obtener información de dispositivos USB.")

    # Dispositivos PCI
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
                log_info("No se encontraron dispositivos PCI principales (VGA, Audio, Red).")
        else:
            log_info("No se detectaron dispositivos PCI.")
    else:
        log_warning("lspci no disponible. Instálelo (ej: sudo apt install pciutils) para obtener información de dispositivos PCI.")


def check_software_inventory():
    """Realiza el inventario de software del sistema."""
    log_section("Control 2: Inventario de Software")

    # Paquetes instalados según el gestor de paquetes
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
        log_warning("Ningún gestor de paquetes (dpkg, rpm, pacman) común encontrado o accesible.")

    # Servicios en ejecución
    if check_command_exists("systemctl"):
        running_services = run_command("systemctl list-units --type=service --state=running --no-pager | grep -c '\\.service'", shell=True)
        if running_services:
            log_info(f"Servicios systemd en ejecución: {running_services}")
        else:
            log_info("No se pudieron determinar la cantidad de servicios systemd en ejecución.")
    else:
        log_warning("systemctl no disponible. No se puede obtener el estado de los servicios systemd.")

    # Procesos sospechosos
    log_info("Procesos que requieren revisión (ej: netcat, socat, telnet):")
    suspicious_processes = run_command("ps aux | grep -E '(nc|netcat|ncat|socat|telnet)' | grep -v grep", shell=True)
    if suspicious_processes:
        for line in suspicious_processes.splitlines():
            log_warning(f"  - {line}")
    else:
        log_info("No se encontraron procesos sospechosos comunes en ejecución.")


def check_network_security():
    """Verifica la configuración de seguridad de red."""
    log_section("Control 4: Seguridad de Red")

    # Puertos abiertos
    log_info("Puertos TCP en escucha:")
    open_ports_output = None
    if check_command_exists("ss"):
        open_ports_output = run_command("ss -tlnp | grep LISTEN", shell=True)
    elif check_command_exists("netstat"):
        open_ports_output = run_command("netstat -tlnp | grep LISTEN", shell=True)

    if open_ports_output:
        for line in open_ports_output.splitlines():
            print(f"  - {line}")
    else:
        log_warning("No se pudieron obtener los puertos en escucha (ss o netstat no disponibles o sin permisos).")

    # Estado del firewall
    log_info("Estado del Firewall:")
    if check_command_exists("ufw"):
        ufw_status = run_command("ufw status | head -1", shell=True)
        print(f"  - UFW: {ufw_status}")
    elif check_command_exists("iptables"):
        iptables_rules = run_command("iptables -L | wc -l", shell=True)
        print(f"  - iptables: {iptables_rules.strip()} reglas configuradas")
    elif check_command_exists("firewall-cmd"):
        firewalld_status = run_command("firewall-cmd --state", shell=True)
        print(f"  - firewalld: {firewalld_status if firewalld_status else 'not running'}")
    else:
        log_warning("Ningún firewall (ufw, iptables, firewalld) común reconocido o configurado.")

    # Interfaces de red
    log_info("Interfaces de red activas:")
    if check_command_exists("ip"):
        network_interfaces = run_command("ip addr show | grep -E '^[0-9]+:'", shell=True)
        if network_interfaces:
            for line in network_interfaces.splitlines():
                print(f"  - {line}")
        else:
            log_info("No se encontraron interfaces de red activas.")
    else:
        log_warning("Comando 'ip' no disponible. No se pueden listar las interfaces de red.")


def check_account_management():
    """Revisa la gestión de cuentas de usuario."""
    log_section("Control 5: Gestión de Cuentas")

    # Cuentas de usuario
    log_info("Cuentas de usuario del sistema (con shell interactiva):")
    if os.path.exists("/etc/passwd"):
        with open("/etc/passwd") as f:
            found_users = False
            for line in f:
                parts = line.strip().split(':')
                if len(parts) >= 7 and parts[6] in ["/bin/bash", "/bin/sh", "/bin/zsh", "/bin/fish"]:
                    username = parts[0]
                    uid = parts[2]
                    last_login_raw = run_command(f"last -1 {username}", shell=True)
                    last_login_info = "Nunca accedió o no disponible"
                    if last_login_raw:
                        # Extraer la fecha y hora del output de 'last'
                        last_login_parts = last_login_raw.split()
                        # Buscar la primera secuencia de mes, día, hora y año
                        for i in range(len(last_login_parts)):
                            if len(last_login_parts[i]) == 3 and last_login_parts[i].isalpha(): # month
                                if i+3 < len(last_login_parts):
                                    try:
                                        # Check if it looks like a date/time (e.g., 'May 20 10:30')
                                        datetime.datetime.strptime(f"{last_login_parts[i]} {last_login_parts[i+1]} {last_login_parts[i+2]} {last_login_parts[i+3]}", "%b %d %H:%M %Y")
                                        last_login_info = f"{last_login_parts[i]} {last_login_parts[i+1]} {last_login_parts[i+2]} {last_login_parts[i+3]}"
                                        break
                                    except ValueError:
                                        pass
                    print(f"  - {username} (UID: {uid}) - Último acceso: {last_login_info}")
                    found_users = True
            if not found_users:
                log_info("No se encontraron cuentas de usuario con shells interactivas.")
    else:
        log_error("/etc/passwd no encontrado. No se pueden listar las cuentas de usuario.")

    # Cuentas con UID 0 (root)
    log_info("Cuentas con privilegios de root (UID 0):")
    if os.path.exists("/etc/passwd"):
        with open("/etc/passwd") as f:
            root_accounts = [line.split(':')[0] for line in f if line.strip().split(':')[2] == '0']
            if root_accounts:
                for account in root_accounts:
                    print(f"  - {account}")
            else:
                log_info("No se encontraron cuentas con UID 0 (aparte de root).")
    else:
        log_error("/etc/passwd no encontrado.")

    # Cuentas sin contraseña
    log_info("Verificando cuentas sin contraseña:")
    if os.path.exists("/etc/shadow") and os.access("/etc/shadow", os.R_OK):
        with open("/etc/shadow") as f:
            found_no_pass = False
            for line in f:
                parts = line.strip().split(':')
                if len(parts) >= 2 and (parts[1] == "" or parts[1] == "*"):
                    print(f"  - {parts[0]} (sin contraseña)")
                    found_no_pass = True
            if not found_no_pass:
                log_info("No se encontraron cuentas sin contraseña.")
    else:
        log_warning("No se puede acceder a /etc/shadow o no existe. No se pueden verificar cuentas sin contraseña.")

    # Grupos administrativos (sudo/wheel)
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
        log_warning("getent no disponible. No se pueden obtener los miembros de los grupos.")


def check_access_control():
    """Examina las configuraciones de control de acceso."""
    log_section("Control 6: Control de Acceso")

    # Configuración de SSH
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

        if "PermitRootLogin yes" in sshd_config_content.lower().replace(" ", ""): # Normalize for case and spaces
            log_warning("SSH permite login directo como root. Esto no es recomendado.")
        if "PasswordAuthentication yes" in sshd_config_content.lower().replace(" ", ""):
            log_warning("SSH permite autenticación por contraseña. Considere usar claves SSH.")
    else:
        log_warning("/etc/ssh/sshd_config no encontrado. No se puede verificar la configuración de SSH.")

    # Políticas de contraseña
    if os.path.exists("/etc/login.defs"):
        log_info("Políticas de contraseña (de /etc/login.defs):")
        with open("/etc/login.defs") as f:
            login_defs_content = f.read()

        found_pass_policy = False
        for line in login_defs_content.splitlines():
            line_stripped = line.strip()
            if not line_stripped.startswith("#") and any(keyword in line_stripped for keyword in ["PASS_MAX_DAYS", "PASS_MIN_DAYS", "PASS_MIN_LEN", "PASS_WARN_AGE"]):
                print(f"  - {line_stripped}")
                found_pass_policy = True
        if not found_pass_policy:
            log_info("No se encontraron políticas de contraseña explícitas en /etc/login.defs.")
    else:
        log_warning("/etc/login.defs no encontrado. No se pueden verificar las políticas de contraseña del sistema.")

    # Permisos de archivos críticos
    log_info("Verificando permisos de archivos críticos:")
    critical_files = ["/etc/passwd", "/etc/shadow", "/etc/group", "/etc/sudoers"]
    for file in critical_files:
        if os.path.exists(file):
            perms = run_command(f"ls -l {file} | awk '{{print $1, $3, $4}}'", shell=True)
            if perms:
                print(f"  - {file}: {perms}")
            else:
                log_warning(f"No se pudieron obtener los permisos de {file}.")
        else:
            log_warning(f"Archivo crítico no encontrado: {file}")


def check_audit_logs():
    """Verifica la configuración y estado de los logs de auditoría."""
    log_section("Control 8: Gestión de Logs")

    # Servicios de logging
    log_info("Estado de servicios de logging:")
    logging_services = ["rsyslog", "syslog-ng", "journald", "auditd"]
    if check_command_exists("systemctl"):
        for service in logging_services:
            status = run_command(f"systemctl is-active {service}", shell=True)
            print(f"  - {service}: {status if status else 'inactive'}")
    else:
        log_warning("systemctl no disponible. No se pueden obtener el estado de los servicios de logging.")

    # Tamaño de logs principales
    log_info("Tamaño de logs principales en /var/log (top 10):")
    log_dirs = "/var/log"
    if os.path.isdir(log_dirs):
        du_output = run_command(f"du -sh {log_dirs}/* 2>/dev/null | sort -hr | head -10", shell=True)
        if du_output:
            for line in du_output.splitlines():
                print(f"  - {line}")
        else:
            log_info("No se pudieron determinar los tamaños de los logs en /var/log.")
    else:
        log_warning(f"Directorio de logs {log_dirs} no encontrado.")

    # Configuración de auditd
    if os.path.exists("/etc/audit/auditd.conf"):
        log_info("Configuración de Auditd:")
        with open("/etc/audit/auditd.conf") as f:
            auditd_config_content = f.read()
        
        found_auditd_config = False
        for line in auditd_config_content.splitlines():
            line_stripped = line.strip()
            if not line_stripped.startswith("#") and any(keyword in line_stripped for keyword in ["log_file", "max_log_file", "num_logs"]):
                print(f"  - {line_stripped}")
                found_auditd_config = True
        if not found_auditd_config:
            log_info("No se encontraron configuraciones clave de auditd en /etc/audit/auditd.conf.")
    else:
        log_warning("/etc/audit/auditd.conf no encontrado. Auditd podría no estar configurado o instalado.")


def check_malware_defense():
    """Verifica las herramientas y configuraciones de defensa contra malware."""
    log_section("Control 10: Defensa contra Malware")

    # Verificar antivirus/herramientas de seguridad instaladas
    antivirus_tools = ["clamav", "rkhunter", "chkrootkit"]
    log_info("Herramientas de defensa contra malware instaladas:")
    found_tool = False
    for tool in antivirus_tools:
        if check_command_exists(tool):
            log_info(f"  - {tool} está instalado.")
            found_tool = True
    if not found_tool:
        log_warning("No se encontraron herramientas de defensa contra malware comunes (ClamAV, Rkhunter, Chkrootkit).")

    # Verificar actualizaciones automáticas
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
            log_info("No se encontraron configuraciones explícitas de actualizaciones automáticas APT.")
    else:
        log_warning("/etc/apt/apt.conf.d/20auto-upgrades no encontrado. Las actualizaciones automáticas APT pueden no estar configuradas.")

    # Verificar repositorios no estándar (solo APT/Debian-based)
    if os.path.isdir("/etc/apt/sources.list.d"):
        log_info("Repositorios de software adicionales (no estándar):")
        found_repo = False
        for root, _, files in os.walk("/etc/apt/sources.list.d"):
            for file in files:
                if file.endswith(".list"):
                    print(f"  - {os.path.join(root, file)}")
                    found_repo = True
        if not found_repo:
            log_info("No se encontraron repositorios adicionales en /etc/apt/sources.list.d.")
    else:
        log_info("Directorio /etc/apt/sources.list.d no encontrado (no basado en Debian/APT).")


def check_network_vulnerabilities():
    """Identifica posibles vulnerabilidades de red."""
    log_section("Control 12: Vulnerabilidades de Red")

    log_info("Verificando protocolos inseguros:")

    # Telnet
    if check_command_exists("telnet"):
        log_warning("Telnet está instalado. Es un protocolo inseguro para acceso remoto.")
    else:
        log_info("Telnet no está instalado.")

    # FTP
    ftp_servers = run_command("pgrep -x 'vsftpd|proftpd|pure-ftpd'", shell=True)
    if ftp_servers:
        log_warning("Servidor FTP (vsftpd, proftpd, pure-ftpd) en ejecución. Considere usar SFTP/FTPS.")
    else:
        log_info("No se encontraron servidores FTP comunes en ejecución.")

    # Verificar SSL/TLS en servicios web (ej. certificados caducados o cercanos a caducar)
    if check_command_exists("openssl"):
        log_info("Verificando certificados SSL locales (antiguos):")
        # Buscar certificados .pem modificados hace más de 365 días en /etc/ssl/certs
        old_certs = run_command("find /etc/ssl/certs -name '*.pem' -mtime +365 2>/dev/null", shell=True)
        if old_certs:
            for cert in old_certs.splitlines():
                log_warning(f"  - Certificado antiguo o caducado (>1 año): {cert}")
        else:
            log_info("No se encontraron certificados SSL antiguos en /etc/ssl/certs.")
    else:
        log_warning("openssl no disponible. No se puede verificar la antigüedad de los certificados SSL.")

    # Configuración de red insegura (IP forwarding)
    log_info("Configuración de red (IP Forwarding):")
    ip_forward_path = "/proc/sys/net/ipv4/ip_forward"
    if os.path.exists(ip_forward_path):
        with open(ip_forward_path) as f:
            ip_forward = f.read().strip()
            if ip_forward == "1":
                log_warning("IP forwarding habilitado. Puede ser un riesgo si no es intencional (ej: router).")
            else:
                log_info("IP forwarding deshabilitado.")
    else:
        log_warning("Archivo /proc/sys/net/ipv4/ip_forward no encontrado.")


def check_system_integrity():
    """Realiza verificaciones adicionales de integridad del sistema."""
    log_section("Control Adicional: Integridad del Sistema")

    # Verificar archivos SUID/SGID
    log_info("Archivos con permisos SUID/SGID (primeros 20):")
    # Limitar a los primeros 20 para evitar salidas excesivamente largas
    suid_sgid_files = run_command("find /usr /bin /sbin -type f -perm /6000 2>/dev/null | head -20", shell=True)
    if suid_sgid_files:
        for file in suid_sgid_files.splitlines():
            perms = run_command(f"ls -l '{file}' | awk '{{print $1}}'", shell=True)
            print(f"  - {file} ({perms if perms else 'permisos no obtenidos'})")
    else:
        log_info("No se encontraron archivos SUID/SGID en los directorios comunes o el comando falló.")

    # Verificar trabajos cron
    log_info("Trabajos cron del sistema (/etc/cron.d/):")
    cron_d_path = "/etc/cron.d"
    if os.path.isdir(cron_d_path):
        cron_files = run_command(f"ls -la {cron_d_path}/ 2>/dev/null | grep -v '^total'", shell=True)
        if cron_files:
            for line in cron_files.splitlines():
                print(f"  - {line}")
        else:
            log_info(f"No se encontraron archivos cron en {cron_d_path}.")
    else:
        log_warning(f"Directorio {cron_d_path} no encontrado.")

    # Procesos con alta prioridad (top 10 CPU)
    log_info("Procesos con alta utilización de CPU (top 10):")
    # Excluye la línea de encabezado de ps aux
    high_cpu_processes = run_command("ps aux --sort=-%cpu | head -11 | tail -10", shell=True)
    if high_cpu_processes:
        for line in high_cpu_processes.splitlines():
            print(f"  - {line}")
    else:
        log_info("No se pudieron obtener los procesos con alta utilización de CPU.")


def check_dependencies():
    """Verifica si las herramientas básicas necesarias están disponibles."""
    missing_deps = []
    basic_tools = ["grep", "awk", "ps", "ls", "cat"] # Agregado 'cat'

    for tool in basic_tools:
        if not check_command_exists(tool):
            missing_deps.append(tool)

    if missing_deps:
        log_error(f"Herramientas básicas faltantes: {', '.join(missing_deps)}")
        log_error("Por favor, asegúrese de que estas herramientas estén instaladas y accesibles en el PATH.")
        exit(1)

 
def main():
    """Función principal que orquesta la ejecución de todos los controles."""
    print(f"{Colors.CYAN}Iniciando auditoría de Controles CIS v8.1 para Linux{Colors.NC}")
    print(f"{Colors.CYAN}Fecha: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.NC}")
    print(f"{Colors.CYAN}Sistema: {platform.node()}{Colors.NC}")
    
    # Get the current username more robustly
    current_user = os.getenv('USER') or os.getenv('LOGNAME')
    if not current_user:
        try:
            current_user = os.getlogin() # Fallback, might still fail in some environments
        except OSError:
            current_user = "Unknown" # If all else fails
    
    print(f"{Colors.CYAN}Usuario: {current_user}{Colors.NC}")
    print("==================================================")
    
    # Verificar si se ejecuta como root
    if os.geteuid() != 0:
        log_warning("Algunos controles pueden requerir privilegios root para obtener información completa. Se recomienda ejecutar con sudo.")
    
    # Ejecutar todos los controles
    check_hardware_inventory()
    check_software_inventory()
    check_network_security()
    check_account_management()
    check_access_control()
    check_audit_logs()
    check_malware_defense()
    check_network_vulnerabilities()
    check_system_integrity()
    
    print("\n==================================================")
    log_info("Auditoría completada exitosamente.")
    log_warning("Revise los resultados y tome las acciones correctivas necesarias.")
    
    # Generar resumen de recomendaciones
    log_section("Resumen de Recomendaciones Generales")
    print("1. Revise cuidadosamente las cuentas sin contraseña o con privilegios elevados (UID 0).")
    print("2. Verifique y configure el firewall (UFW/iptables/firewalld) para cerrar puertos innecesarios.")
    print("3. Asegúrese de que los servicios de logging (rsyslog, journald, auditd) estén activos y configurados correctamente.")
    print("4. Considere instalar y configurar herramientas adicionales de seguridad (antivirus, rootkit detectors).")
    print("5. Mantenga el sistema y todo el software actualizado regularmente para protegerse contra vulnerabilidades conocidas.")
    print("6. Deshabilite el login directo de root por SSH y la autenticación por contraseña si usa claves SSH.")
    print("7. Revise periódicamente los archivos con permisos SUID/SGID y los trabajos cron inusuales.")

# Punto de entrada del script
if __name__ == "__main__":
    check_dependencies()
    main()