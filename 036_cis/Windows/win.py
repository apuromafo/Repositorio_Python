import platform
import wmi
import psutil
import winreg
import subprocess
import datetime
import math
import ctypes
import sys
import socket # Required for net_if_addrs family check

# --- Utilidades y Configuración Global ---

# Colores ANSI para una salida más legible
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_section_header(title):
    """Prints a formatted section header."""
    print(f"\n{Colors.BOLD}=== {title} ==={Colors.ENDC}")

def is_admin():
    """Checks if the script is running with administrative privileges."""
    try:
        return ctypes.windll.shell32.IsUserAdmin()
    except:
        return False

# Initialize WMI connection (can be reused across functions)
# This handles potential connection errors more gracefully
c = None
if is_admin():
    try:
        c = wmi.WMI()
    except wmi.WMIConnectionError as e:
        print(f"{Colors.FAIL}Error al conectar con WMI: {e}. Asegúrese de que el servicio WMI esté en ejecución y tenga permisos suficientes.{Colors.ENDC}")
    except Exception as e:
        print(f"{Colors.FAIL}Error inesperado al inicializar WMI: {e}{Colors.ENDC}")
else:
    print(f"{Colors.WARNING}Advertencia: El script no se está ejecutando como administrador. Algunas verificaciones pueden fallar o mostrar información incompleta.{Colors.ENDC}")
    print(f"{Colors.WARNING}Se recomienda ejecutar el script como administrador para obtener resultados completos.{Colors.ENDC}")

# Global list to store recommendations
RECOMMENDATIONS = []

def add_recommendation(control_id, description):
    """Adds a recommendation to the global list."""
    RECOMMENDATIONS.append(f"Control {control_id}: {description}")


# --- Implementación de Controles CIS v8.1 ---

def get_hardware_inventory():
    """
    Control 1: Inventory and Control of Enterprise Assets
    Gathers basic system information and lists connected USB devices.
    """
    print_section_header("Control 1: Inventario de Hardware y Activos Empresariales")

    if not c:
        print(f"{Colors.WARNING}Conexión WMI no disponible. Saltando inventario de hardware.{Colors.ENDC}")
        return

    try:
        # System Information
        for os_info in c.Win32_OperatingSystem():
            print(f"Sistema Operativo: {os_info.Caption} - {os_info.Version} (Build: {os_info.BuildNumber})")
            print(f"Arquitectura: {os_info.OSArchitecture}")
            print(f"Último Arranque: {datetime.datetime.strptime(os_info.LastBootUpTime.split('.')[0], '%Y%m%d%H%M%S')}")
            break

        total_ram_gb = round(psutil.virtual_memory().total / (1024**3), 2)
        print(f"RAM Total: {total_ram_gb} GB")

        # Processors
        for cpu in c.Win32_Processor():
            print(f"Procesador: {cpu.Name} (Núcleos: {cpu.NumberOfCores}, Lógicos: {cpu.NumberOfLogicalProcessors})")
            break

        # Disks
        print("\nUnidades de Disco:")
        disks_found = False
        for disk in c.Win32_LogicalDisk(DriveType=3): # DriveType=3 for Local Disk
            disks_found = True
            size_gb = round(int(disk.Size) / (1024**3), 2) if disk.Size else "N/A"
            free_gb = round(int(disk.FreeSpace) / (1024**3), 2) if disk.FreeSpace else "N/A"
            print(f"- {disk.Caption} (Tamaño: {size_gb} GB, Espacio Libre: {free_gb} GB)")
        if not disks_found:
            print("- No se encontraron unidades de disco.")

        # USB Devices (Salvaguarda 1.1)
        print("\nDispositivos USB detectados:")
        usb_devices = []
        for usb_controller_device in c.Win32_USBControllerDevice():
            try:
                dependent_path = usb_controller_device.Dependent
                device_id_part = dependent_path.split('DeviceID="')[1].split('"')[0]
                for pnp_entity in c.Win32_PnPEntity(DeviceID=device_id_part):
                    if "Root Hub" not in pnp_entity.Description: # Filter out root hubs
                        usb_devices.append(pnp_entity.Description)
            except Exception:
                pass # Silently ignore parsing errors

        if usb_devices:
            for device in sorted(list(set(usb_devices))): # Remove duplicates and sort
                print(f"- {device}")
        else:
            print("- No se detectaron dispositivos USB no-Root Hub.")
            add_recommendation("1.2", "Revise periódicamente los activos no autorizados. Considere implementar el control de puertos USB (USB Device Control).")

    except wmi.WMIConnectionError:
        print(f"{Colors.FAIL}Error WMI. Asegúrese de tener permisos de administrador.{Colors.ENDC}")
    except Exception as e:
        print(f"{Colors.FAIL}Error durante el inventario de hardware: {e}{Colors.ENDC}")

def get_software_inventory():
    """
    Control 2: Inventory and Control of Software Assets
    Lists installed software, running services, and checks for suspicious processes.
    """
    print_section_header("Control 2: Inventario de Software y Control")

    try:
        # Installed Software (Salvaguarda 2.1) - More robust way via Registry
        installed_software_count = 0
        print("Programas instalados (vía Registro):")
        # Paths to check for installed software
        uninstall_paths = [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" # For 32-bit apps on 64-bit systems
        ]

        def get_software_from_registry(hive, subkey):
            software_list = []
            try:
                reg_key = winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ)
                i = 0
                while True:
                    try:
                        sub_key_name = winreg.EnumKey(reg_key, i)
                        with winreg.OpenKey(reg_key, sub_key_name) as program_key:
                            try:
                                display_name = winreg.QueryValueEx(program_key, "DisplayName")[0]
                                display_version = winreg.QueryValueEx(program_key, "DisplayVersion")[0] if "DisplayVersion" in winreg.EnumValue(program_key, 0) else "N/A"
                                publisher = winreg.QueryValueEx(program_key, "Publisher")[0] if "Publisher" in winreg.EnumValue(program_key, 0) else "N/A"
                                software_list.append({"Name": display_name, "Version": display_version, "Publisher": publisher})
                            except OSError: # DisplayName might not exist for some entries
                                pass
                    except OSError: # No more subkeys
                        break
                    i += 1
            except FileNotFoundError:
                pass # Path not found, perfectly normal for some systems
            except Exception as e:
                print(f"{Colors.FAIL}Error leyendo registro de software: {e}{Colors.ENDC}")
            return software_list

        all_installed_software = []
        for path in uninstall_paths:
            all_installed_software.extend(get_software_from_registry(winreg.HKEY_LOCAL_MACHINE, path))
        
        # Also check current user's uninstall key
        all_installed_software.extend(get_software_from_registry(winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"))

        installed_software_count = len(all_installed_software)
        print(f"Total de programas instalados (vía Registro): {installed_software_count}")
        # print("Aquí se listan, pero la salida completa es extensa. Se pueden descomentar si es necesario:")
        # for app in sorted(all_installed_software, key=lambda x: x['Name']):
        #     print(f"  - {app['Name']} v{app['Version']} ({app['Publisher']})")


        # Running Services
        running_services_count = 0
        for service in psutil.win_service_iter():
            if service.status() == 'running':
                running_services_count += 1
        print(f"\nServicios en ejecución: {running_services_count}")

        # Suspicious Processes (basic example for Salvaguarda 2.2, 2.7)
        suspicious_processes = []
        current_pid = psutil.Process().pid
        common_scripting_executables = ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "pwsh.exe"]
        
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'username']):
            try:
                process_name = proc.info['name'].lower()
                process_exe_path = proc.info['exe']
                
                # Flag common scripting shells if they are not the current process
                if process_name in common_scripting_executables and proc.info['pid'] != current_pid:
                    suspicious_processes.append(f"{proc.info['name']} (PID: {proc.info['pid']}, Usuario: {proc.info['username']}, Ruta: {process_exe_path})")
                
                # Basic check for unsigned executables in suspicious paths (requires admin to get exe path for many processes)
                if process_exe_path and "temp" in process_exe_path.lower():
                    # More advanced check would involve verifying digital signature
                    pass # Not implemented for brevity and complexity
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue # Process no longer exists or access denied

        if suspicious_processes:
            print(f"\n{Colors.WARNING}Procesos que requieren revisión (posibles scripts o ejecutables no autorizados):{Colors.ENDC}")
            for sp in suspicious_processes:
                print(f"- {sp}")
            add_recommendation("2.5, 2.7", "Considere implementar políticas de Allowlisting (AppLocker/WDAC) para ejecutar solo software y scripts autorizados.")
        else:
            print("No se encontraron procesos sospechosos básicos.")

    except Exception as e:
        print(f"{Colors.FAIL}Error durante el inventario de software: {e}{Colors.ENDC}")

def test_network_security():
    """
    Control 4: Secure Configuration of Enterprise Assets and Software
    Checks open TCP ports and firewall status.
    """
    print_section_header("Control 4: Configuración Segura de Activos y Software")

    try:
        # Open Ports (Salvaguarda 4.7 - Least Functionality)
        print("Puertos TCP en escucha:")
        open_ports_info = []
        for conn in psutil.net_connections(kind='tcp'):
            if conn.status == psutil.CONN_LISTEN:
                try:
                    process_name = "N/A"
                    if conn.pid:
                        process = psutil.Process(conn.pid)
                        process_name = process.name()
                    open_ports_info.append(f"- Puerto {conn.laddr.port} ({conn.laddr.ip}) - Proceso: {process_name}")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    open_ports_info.append(f"- Puerto {conn.laddr.port} ({conn.laddr.ip}) - Proceso: Acceso Denegado/No Existe")
                except Exception as e:
                    open_ports_info.append(f"- Puerto {conn.laddr.port} ({conn.laddr.ip}) - Error: {e}")

        if open_ports_info:
            for port_info in sorted(open_ports_info):
                print(port_info)
            add_recommendation("4.7", "Revise los puertos abiertos y desactive los servicios no necesarios para reducir la superficie de ataque.")
        else:
            print(f"{Colors.OKGREEN}✓ No se encontraron puertos TCP en escucha.{Colors.ENDC}")

        # Firewall Status (Salvaguarda 4.3)
        print("\nEstado del Firewall de Windows:")
        try:
            # Check domain, private, public profiles
            profiles = ["Domain Profile", "Private Profile", "Public Profile"]
            firewall_status_ok = True
            for profile_name in profiles:
                cmd = f'netsh advfirewall show {profile_name} state'
                result = subprocess.run(cmd, capture_output=True, text=True, shell=True, check=True, encoding='utf-8', errors='ignore')
                output = result.stdout.strip()
                status = "Desconocido"
                if "State                            ON" in output:
                    status = f"{Colors.OKGREEN}Habilitado{Colors.ENDC}"
                elif "State                            OFF" in output:
                    status = f"{Colors.FAIL}Deshabilitado{Colors.ENDC}"
                    firewall_status_ok = False
                print(f"- {profile_name}: {status}")
            
            if not firewall_status_ok:
                add_recommendation("4.3", "Asegúrese de que todos los perfiles del firewall estén habilitados para proteger el sistema.")
            else:
                print(f"{Colors.OKGREEN}✓ El Firewall de Windows está habilitado en todos los perfiles de red principales.{Colors.ENDC}")

        except subprocess.CalledProcessError as e:
            print(f"{Colors.FAIL}Error al verificar el estado del firewall con netsh: {e.stderr.strip()}{Colors.ENDC}")
            print(f"{Colors.WARNING}Asegúrese de ejecutar el script como administrador.{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}Error al verificar el estado del firewall: {e}{Colors.ENDC}")

        # Device Lockout (Salvaguarda 4.10)
        print("\nConfiguración de Bloqueo Automático de Dispositivos:")
        try:
            key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ)
            # This specific value usually controls the screen saver timeout policy
            # It's more complex to get actual configured screen saver timeout from user policies
            # We'll check the 'Interactive logon: Machine inactivity limit' policy if available
            inactivity_limit_set = False
            try:
                inactivity_limit, _ = winreg.QueryValueEx(key, "InactivityLimit")
                # InactivityLimit is in seconds
                if inactivity_limit > 0 and inactivity_limit <= 900: # 15 minutes = 900 seconds (CIS rec for interactive logon)
                    print(f"{Colors.OKGREEN}✓ Límite de inactividad de la máquina configurado: {inactivity_limit} segundos.{Colors.ENDC}")
                    inactivity_limit_set = True
                else:
                    print(f"{Colors.WARNING}Límite de inactividad de la máquina: {inactivity_limit} segundos. Se recomienda <= 900 segundos (15 min).{Colors.ENDC}")
                    add_recommendation("4.10", "Configure el límite de inactividad de la máquina a 900 segundos (15 minutos) o menos.")
                    inactivity_limit_set = False
            except FileNotFoundError:
                print(f"{Colors.WARNING}No se encontró la política 'Interactive logon: Machine inactivity limit'.{Colors.ENDC}")
                add_recommendation("4.10", "Se recomienda configurar la política 'Interactive logon: Machine inactivity limit'.")
            except Exception as e:
                print(f"{Colors.FAIL}Error al verificar límite de inactividad: {e}{Colors.ENDC}")
                add_recommendation("4.10", "Verifique la configuración del límite de inactividad de la máquina.")
            winreg.CloseKey(key)

            # Check for screen saver password protection
            try:
                user_key_path = r"Control Panel\Desktop"
                user_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, user_key_path, 0, winreg.KEY_READ)
                screensaver_secure, _ = winreg.QueryValueEx(user_key, "ScreenSaverIsSecure")
                if screensaver_secure == "1":
                    print(f"{Colors.OKGREEN}✓ El protector de pantalla requiere contraseña al reanudarse.{Colors.ENDC}")
                else:
                    print(f"{Colors.WARNING}El protector de pantalla NO requiere contraseña al reanudarse. {Colors.ENDC}")
                    add_recommendation("4.10", "Configure el protector de pantalla para que requiera contraseña al reanudarse.")
                winreg.CloseKey(user_key)
            except FileNotFoundError:
                print(f"{Colors.WARNING}No se encontró la configuración del protector de pantalla para el usuario actual.{Colors.ENDC}")
                add_recommendation("4.10", "Verifique y configure el protector de pantalla para que requiera contraseña al reanudarse.")
            except Exception as e:
                print(f"{Colors.FAIL}Error al verificar la seguridad del protector de pantalla: {e}{Colors.ENDC}")
                add_recommendation("4.10", "Verifique la configuración del protector de pantalla para que requiera contraseña al reanudarse.")
        except Exception as e:
            print(f"{Colors.FAIL}Error al verificar el bloqueo automático del dispositivo: {e}{Colors.ENDC}")
            add_recommendation("4.10", "Revise las políticas de bloqueo automático de dispositivos.")


        # Full Disk Encryption (Salvaguarda 4.11)
        print("\nEstado del Cifrado de Disco (BitLocker):")
        if not c:
            print(f"{Colors.WARNING}WMI no disponible para verificar BitLocker.{Colors.ENDC}")
        else:
            try:
                bitlocker_active_count = 0
                total_volumes = 0
                for volume in c.Win32_EncryptableVolume():
                    total_volumes += 1
                    protection_status = "Desconocido"
                    if volume.ProtectionStatus == 0:
                        protection_status = f"{Colors.WARNING}Protección Desactivada{Colors.ENDC}"
                    elif volume.ProtectionStatus == 1:
                        protection_status = f"{Colors.OKGREEN}Protección Activada{Colors.ENDC}"
                        bitlocker_active_count += 1
                    elif volume.ProtectionStatus == 2:
                        protection_status = f"{Colors.WARNING}Protección En pausa{Colors.ENDC}"
                    
                    conversion_status = "Desconocido"
                    if volume.ConversionStatus == 0:
                        conversion_status = "Totalmente Descifrado"
                    elif volume.ConversionStatus == 1:
                        conversion_status = "Totalmente Cifrado"
                    elif volume.ConversionStatus == 2:
                        conversion_status = "Cifrando"
                    elif volume.ConversionStatus == 3:
                        conversion_status = "Descifrando"

                    print(f"- Unidad {volume.DriveLetter}: ({conversion_status}) - Estado de Protección: {protection_status}")
                
                if total_volumes == 0:
                    print(f"{Colors.WARNING}No se detectaron volúmenes cifrables (ej. BitLocker no está habilitado o WMI no lo detecta).{Colors.ENDC}")
                    add_recommendation("4.11", "Se recomienda habilitar el cifrado de disco completo (BitLocker o similar) para todos los activos empresariales.")
                elif bitlocker_active_count < total_volumes:
                    add_recommendation("4.11", "Asegúrese de que el cifrado de disco completo (BitLocker) esté activado en todas las unidades relevantes.")
                else:
                    print(f"{Colors.OKGREEN}✓ BitLocker está activo en todas las unidades cifrables detectadas.{Colors.ENDC}")

            except wmi.WMIError as e:
                print(f"{Colors.FAIL}Error WMI al verificar BitLocker: {e}. Asegúrese de ejecutar como administrador.{Colors.ENDC}")
                add_recommendation("4.11", "Verifique el estado del cifrado de disco completo (BitLocker).")
            except Exception as e:
                print(f"{Colors.FAIL}Error al verificar BitLocker: {e}{Colors.ENDC}")
                add_recommendation("4.11", "Verifique el estado del cifrado de disco completo (BitLocker).")


    except Exception as e:
        print(f"{Colors.FAIL}Error durante la verificación de seguridad de red: {e}{Colors.ENDC}")

def test_account_management():
    """
    Control 5: Account Management
    Lists local user accounts, their status, and members of the Administrators group.
    """
    print_section_header("Control 5: Gestión de Cuentas")

    if not c:
        print(f"{Colors.WARNING}Conexión WMI no disponible. Saltando verificación de gestión de cuentas.{Colors.ENDC}")
        return

    try:
        # Local User Accounts (Salvaguarda 5.1, 5.3)
        print("Cuentas de usuario locales:")
        local_users_found = False
        dormant_accounts_found = False
        default_admin_active = False
        guest_active = False
        
        current_time = datetime.datetime.now()
        
        for user in c.Win32_UserAccount(LocalAccount=True):
            local_users_found = True
            status_text = f"{Colors.OKGREEN}Activa{Colors.ENDC}" if user.Disabled == False else f"{Colors.FAIL}Inactiva/Deshabilitada{Colors.ENDC}"
            
            last_logon_time = "N/A"
            
            # Use Win32_NetworkLoginProfile for LastLogon, more reliable if available
            try:
                for login_profile in c.Win32_NetworkLoginProfile(Name=user.Name):
                    if login_profile.LastLogon:
                        logon_dt = datetime.datetime.strptime(login_profile.LastLogon.split('.')[0], '%Y%m%d%H%M%S')
                        last_logon_time = logon_dt.strftime('%Y-%m-%d %H:%M:%S')
                        if (current_time - logon_dt).days > 90: # CIS recommends disabling dormant accounts (e.g., > 90 days)
                            dormant_accounts_found = True
                            status_text += f" {Colors.WARNING}(Inactiva > 90 días){Colors.ENDC}"
                        break
            except Exception:
                pass # Ignore errors if login profile is not found or datetime conversion fails

            print(f"- {user.Name}: {status_text}, Último acceso: {last_logon_time}")
            if user.PasswordRequired == False:
                print(f"  {Colors.FAIL}⚠️ Sin contraseña requerida{Colors.ENDC}") # Red text
                add_recommendation("5.2", f"La cuenta '{user.Name}' no requiere contraseña. Asegure que todas las cuentas requieran contraseñas complejas.")
            if user.Lockout == True:
                 print(f"  {Colors.WARNING}⚠️ Bloqueada{Colors.ENDC}")
            
            # Check for default accounts (Salvaguarda 4.12 - Manage Default Accounts)
            if user.Name.lower() == "administrator" and user.Disabled == False:
                print(f"  {Colors.WARNING}⚠️ Cuenta 'Administrator' predeterminada activa. Se recomienda renombrarla/deshabilitarla.{Colors.ENDC}")
                default_admin_active = True
            if user.Name.lower() == "guest" and user.Disabled == False:
                print(f"  {Colors.WARNING}⚠️ Cuenta 'Guest' predeterminada activa. Se recomienda deshabilitarla.{Colors.ENDC}")
                guest_active = True

        if not local_users_found:
            print("- No se encontraron cuentas de usuario locales.")
        
        if dormant_accounts_found:
            add_recommendation("5.3", "Revise y deshabilite cuentas inactivas (>90 días) periódicamente.")
        if default_admin_active:
            add_recommendation("4.12", "La cuenta 'Administrator' predeterminada está activa. Renómbrela o deshabilítela.")
        if guest_active:
            add_recommendation("4.12", "La cuenta 'Guest' predeterminada está activa. Deshabítela.")


        # Administrative Accounts (Salvaguarda 5.4)
        print("\nMiembros del grupo Administradores:")
        admin_group_found = False
        admin_members_count = 0
        for group in c.Win32_Group(Name="Administrators"):
            admin_group_found = True
            try:
                admin_members = []
                for member in group.associators(wmi_result_class="Win32_GroupUser"):
                    admin_members.append(member.Caption.split('\\')[-1]) # Get just the username
                
                if admin_members:
                    admin_members_count = len(admin_members)
                    for member_name in admin_members:
                        print(f"- {member_name}")
                else:
                    print("- El grupo de Administradores no tiene miembros.")

            except Exception as e:
                print(f"  {Colors.FAIL}Error al obtener miembros del grupo de administradores: {e}{Colors.ENDC}")
            break # Assume only one Administrators group

        if not admin_group_found:
            print("- No se encontró el grupo de Administradores.")
        
        if admin_members_count > 2: # Arbitrary threshold, but usually few dedicated admins
            add_recommendation("5.4", "El grupo de Administradores tiene múltiples miembros. Restrinja los privilegios de administrador solo a cuentas dedicadas cuando sea necesario.")


        # Password Policy (Salvaguarda 5.2)
        print("\nPolítica de Contraseñas (Local):")
        try:
            # Using 'net accounts' is often the easiest for local policy
            cmd = ['net', 'accounts']
            result = subprocess.run(cmd, capture_output=True, text=True, check=True, encoding='utf-8', errors='ignore')
            output = result.stdout.strip()

            password_policy_details = {}
            for line in output.splitlines():
                if ":" in line:
                    parts = line.split(':', 1)
                    key = parts[0].strip()
                    value = parts[1].strip()
                    password_policy_details[key] = value

            min_len = password_policy_details.get("Longitud mínima de la contraseña", "N/A")
            history = password_policy_details.get("Historial de contraseñas guardado", "N/A")
            max_age = password_policy_details.get("Período de validez de la contraseña (días)", "N/A")
            
            print(f"- Longitud mínima de contraseña: {min_len}")
            print(f"- Historial de contraseñas guardado: {history}")
            print(f"- Vigencia máxima de contraseña: {max_age}")
            
            # Basic recommendations
            password_policy_issues = False
            if min_len == "N/A" or (min_len.isdigit() and int(min_len) < 14): # CIS rec is usually >= 14
                password_policy_issues = True
            if history == "N/A" or (history.isdigit() and int(history) < 24): # CIS rec for history
                password_policy_issues = True
            # For max_age, CIS recommends considering MFA. If no MFA, then enforce periodic change.
            if max_age == "N/A" or (max_age.isdigit() and int(max_age) > 90):
                password_policy_issues = True
            
            if password_policy_issues:
                add_recommendation("5.2", "Asegúrese de que las políticas de contraseña implementen complejidad (mín. 14 caracteres), historial (mín. 24) y vigencia (si no se usa MFA/autenticación robusta).")

        except subprocess.CalledProcessError as e:
            print(f"{Colors.FAIL}Error al consultar políticas de contraseña (net accounts): {e.stderr.strip()}{Colors.ENDC}")
            add_recommendation("5.2", "Verifique manualmente la política de contraseñas del sistema.")
        except Exception as e:
            print(f"{Colors.FAIL}Error al verificar política de contraseñas: {e}{Colors.ENDC}")
            add_recommendation("5.2", "Verifique manualmente la política de contraseñas del sistema.")

    except Exception as e:
        print(f"{Colors.FAIL}Error durante la verificación de gestión de cuentas: {e}{Colors.ENDC}")

def test_access_control():
    """
    Control 6: Access Control Management
    Checks UAC settings and recent successful login events.
    """
    print_section_header("Control 6: Control de Acceso")

    try:
        # UAC Settings (User Account Control - Salvaguarda 6.1)
        print("Control de Cuentas de Usuario (UAC):")
        uac_problem = False
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", 0, winreg.KEY_READ)
            enable_lua_value, _ = winreg.QueryValueEx(key, "EnableLUA")
            prompt_for_consent, _ = winreg.QueryValueEx(key, "ConsentPromptBehaviorAdmin")
            
            if enable_lua_value == 1:
                print(f"  Estado de UAC: {Colors.OKGREEN}Habilitado{Colors.ENDC}")
                if prompt_for_consent == 5: # Prompt for consent on the secure desktop (default, most secure)
                    print(f"  Comportamiento de la solicitud: {Colors.OKGREEN}Mensaje en escritorio seguro (valor 5){Colors.ENDC}")
                elif prompt_for_consent == 2: # Prompt for consent (not on secure desktop)
                    print(f"  Comportamiento de la solicitud: {Colors.WARNING}Mensaje de solicitud de consentimiento (valor 2).{Colors.ENDC}")
                    uac_problem = True
                elif prompt_for_consent == 0: # Elevate without prompting
                    print(f"  Comportamiento de la solicitud: {Colors.FAIL}Elevar sin preguntar (valor 0). ¡Inseguro!{Colors.ENDC}")
                    uac_problem = True
                else:
                    print(f"  Comportamiento de la solicitud: {Colors.WARNING}Valor desconocido ({prompt_for_consent}).{Colors.ENDC}")
                    uac_problem = True
            else:
                print(f"  Estado de UAC: {Colors.FAIL}Deshabilitado{Colors.ENDC}")
                uac_problem = True

            winreg.CloseKey(key)
        except FileNotFoundError:
            print(f"{Colors.FAIL}No se encontró la clave de registro de UAC. {Colors.ENDC}")
            uac_problem = True
        except Exception as e:
            print(f"{Colors.FAIL}Error al verificar UAC: {e}{Colors.ENDC}")
            uac_problem = True
        
        if uac_problem:
            add_recommendation("6.1", "Asegúrese de que UAC esté habilitado y configurado para solicitar consentimiento en el escritorio seguro (ConsentPromptBehaviorAdmin = 5).")

        # Last Successful Logons (Event ID 4624 - for auditing access)
        print("\nÚltimos inicios de sesión exitosos (Event ID 4624 - 10 más recientes):")
        try:
            # Use wevtutil to query the Security log for Event ID 4624 (Successful Logon)
            cmd = ['wevtutil', 'query-events', 'Security', '/rd:true', '/q:*[System[(EventID=4624)]]', '/c:10', '/f:text']
            result = subprocess.run(cmd, capture_output=True, text=True, check=True, encoding='utf-8', errors='ignore')
            log_output = result.stdout.strip()

            logons_found = False
            current_logon_info = {}
            for line in log_output.splitlines():
                if "Event ID:              4624" in line:
                    if current_logon_info: # Process previous entry
                        print(f"- {current_logon_info.get('Date', 'N/A')}: Usuario {current_logon_info.get('Account Name', 'N/A')} ({current_logon_info.get('Logon Type', 'N/A')})")
                    current_logon_info = {} # Reset for new event
                    logons_found = True
                elif "Date:" in line:
                    current_logon_info['Date'] = line.split(':', 1)[1].strip()
                elif "Account Name:" in line:
                    current_logon_info['Account Name'] = line.split(':', 1)[1].strip()
                elif "Logon Type:" in line:
                    current_logon_info['Logon Type'] = line.split(':', 1)[1].strip()
            
            # Print the last collected entry
            if current_logon_info:
                print(f"- {current_logon_info.get('Date', 'N/A')}: Usuario {current_logon_info.get('Account Name', 'N/A')} ({current_logon_info.get('Logon Type', 'N/A')})")
            
            if not logons_found:
                print("- No se encontraron inicios de sesión exitosos recientes (Event ID 4624).")

        except subprocess.CalledProcessError as e:
            print(f"{Colors.FAIL}Error consultando eventos de inicio de sesión (wevtutil): {e.stderr.strip()}{Colors.ENDC}")
            print(f"{Colors.WARNING}Asegúrese de ejecutar el script como administrador para acceder a los registros de seguridad.{Colors.ENDC}")
            add_recommendation("6.5", "Verifique que la auditoría de inicio de sesión exitoso (Event ID 4624) esté habilitada.")
        except Exception as e:
            print(f"{Colors.FAIL}Error al obtener los últimos inicios de sesión: {e}{Colors.ENDC}")
            add_recommendation("6.5", "Verifique que la auditoría de inicio de sesión exitoso (Event ID 4624) esté habilitada.")

        add_recommendation("6.5", "Considere implementar Multi-Factor Authentication (MFA) para accesos críticos y remotos.")

    except Exception as e:
        print(f"{Colors.FAIL}Error durante la verificación de control de acceso: {e}{Colors.ENDC}")


def test_audit_logs():
    """
    Control 8: Audit Log Management
    Checks the status of the Event Log service and the size/event count of main logs.
    Also checks basic audit policies.
    """
    print_section_header("Control 8: Gestión de Registros de Auditoría")

    if not c:
        print(f"{Colors.WARNING}Conexión WMI no disponible. Saltando verificación de logs.{Colors.ENDC}")
        return

    try:
        # Verify Event Log Service (Salvaguarda 8.1)
        event_log_service_status = "Desconocido"
        try:
            for service in c.Win32_Service(Name="EventLog"):
                event_log_service_status = service.State
                break
            if event_log_service_status == "Running":
                print(f"Servicio de Event Log: {Colors.OKGREEN}{event_log_service_status}{Colors.ENDC}")
            else:
                print(f"Servicio de Event Log: {Colors.FAIL}{event_log_service_status}{Colors.ENDC}")
                print(f"{Colors.FAIL}⚠️ El servicio 'EventLog' no está en ejecución. Los logs no se registrarán.{Colors.ENDC}")
                add_recommendation("8.1", "Asegúrese de que el servicio 'EventLog' esté siempre en ejecución.")
        except Exception as e:
            print(f"{Colors.FAIL}Error al verificar el servicio EventLog: {e}{Colors.ENDC}")
            add_recommendation("8.1", "Verifique el estado del servicio 'EventLog'.")
        

        # Main Log Sizes and Event Counts (Salvaguarda 8.3)
        print("\nInformación de los logs principales (Tamaño y Eventos):")
        log_names = ['System', 'Application', 'Security']
        for log_name in log_names:
            try:
                cmd = ['wevtutil', 'get-log', log_name]
                result = subprocess.run(cmd, capture_output=True, text=True, check=True, encoding='utf-8', errors='ignore')
                output = result.stdout.strip()

                file_size_mb = "N/A"
                record_count = "N/A"
                max_size_mb = "N/A"

                for line in output.splitlines():
                    if "FileSize:" in line:
                        size_bytes = int(line.split(':')[1].strip())
                        file_size_mb = round(size_bytes / (1024**2), 2)
                    if "RecordCount:" in line:
                        record_count = int(line.split(':')[1].strip())
                    if "MaxSize:" in line:
                        max_size_bytes = int(line.split(':')[1].strip())
                        max_size_mb = round(max_size_bytes / (1024**2), 2)
                
                print(f"Log {log_name} - Tamaño Actual: {file_size_mb} MB, Eventos: {record_count}, Tamaño Máx: {max_size_mb} MB")

            except subprocess.CalledProcessError as e:
                print(f"{Colors.FAIL}Error consultando log {log_name} (wevtutil): {e.stderr.strip()}{Colors.ENDC}")
                print(f"{Colors.WARNING}Asegúrese de ejecutar el script como administrador para acceder al log '{log_name}'.{Colors.ENDC}")
                add_recommendation("8.3", f"Verifique manualmente la configuración del log '{log_name}'.")
            except Exception as e:
                print(f"{Colors.FAIL}Error al obtener información del log {log_name}: {e}{Colors.ENDC}")
                add_recommendation("8.3", f"Verifique manualmente la configuración del log '{log_name}'.")
        add_recommendation("8.3, 8.9", "Asegúrese de que los logs tengan suficiente espacio para retener eventos importantes y que los eventos se centralicen en un SIEM o sistema de gestión de logs.")

        # Time Synchronization (Salvaguarda 8.4)
        print("\nSincronización Horaria (W32Time):")
        try:
            # Check if Windows Time service is running and configured for external source
            cmd = ['w32tm', '/query', '/status']
            result = subprocess.run(cmd, capture_output=True, text=True, shell=True, check=True, encoding='utf-8', errors='ignore')
            output = result.stdout.strip()
            
            source_problem = False
            for line in output.splitlines():
                if "Fuente:" in line or "Source:" in line:
                    source = line.split(':', 1)[1].strip()
                    print(f"- Fuente de Tiempo: {source}")
                    if "Local CMOS Clock" in source:
                        print(f"  {Colors.WARNING}⚠️ La fuente de tiempo es el reloj CMOS local.{Colors.ENDC}")
                        source_problem = True
                    else:
                        print(f"  {Colors.OKGREEN}✓ Fuente de tiempo configurada.{Colors.ENDC}")
                if "Estado del reloj:" in line or "Clock Status:" in line:
                    status = line.split(':', 1)[1].strip()
                    if "estable" in status.lower() or "synchronized" in status.lower():
                        print(f"- Estado del Reloj: {Colors.OKGREEN}{status}{Colors.ENDC}")
                    else:
                        print(f"- Estado del Reloj: {Colors.WARNING}{status}{Colors.ENDC}")
                        source_problem = True
            
            if source_problem:
                 add_recommendation("8.4", "Configure el sistema para sincronizar con una fuente de tiempo autorizada y fiable (servidor NTP).")
        except subprocess.CalledProcessError as e:
            print(f"{Colors.FAIL}Error al consultar estado de sincronización de tiempo: {e.stderr.strip()}{Colors.ENDC}")
            add_recommendation("8.4", "Verifique manualmente la configuración de sincronización horaria (servicio W32Time).")
        except Exception as e:
            print(f"{Colors.FAIL}Error al verificar sincronización de tiempo: {e}{Colors.ENDC}")
            add_recommendation("8.4", "Verifique manualmente la configuración de sincronización horaria (servicio W32Time).")

        # Detailed Audit Logs (Salvaguarda 8.5) - Process Creation Auditing
        print("\nEstado de Auditoría Detallada (Creación de Procesos y Línea de Comandos):")
        audit_problem = False
        try:
            # Check for Process Creation auditing
            cmd_proc_creation = ['auditpol', '/get', '/subcategory:"Process Creation"']
            result_proc_creation = subprocess.run(cmd_proc_creation, capture_output=True, text=True, check=True, encoding='utf-8', errors='ignore')
            if "Success and Failure" in result_proc_creation.stdout:
                print(f"- Auditoría de Creación de Procesos: {Colors.OKGREEN}Habilitada (Éxito y Fallo){Colors.ENDC}")
            else:
                print(f"- Auditoría de Creación de Procesos: {Colors.WARNING}No habilitada (Éxito y Fallo).{Colors.ENDC}")
                audit_problem = True

            # Check for Command Line Process Auditing (requires specific GPO/registry setting)
            # HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCommandLine (DWORD, 1 for enabled)
            line_cmd_key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, line_cmd_key_path, 0, winreg.KEY_READ)
                value, _ = winreg.QueryValueEx(key, "ProcessCreationIncludeCommandLine")
                if value == 1:
                    print(f"- Auditoría de Línea de Comandos: {Colors.OKGREEN}Habilitada.{Colors.ENDC}")
                else:
                    print(f"- Auditoría de Línea de Comandos: {Colors.WARNING}Deshabilitada.{Colors.ENDC}")
                    audit_problem = True
                winreg.CloseKey(key)
            except FileNotFoundError:
                print(f"- Auditoría de Línea de Comandos: {Colors.WARNING}No configurada (clave de registro no encontrada).{Colors.ENDC}")
                audit_problem = True
            except Exception as e:
                print(f"{Colors.FAIL}Error al verificar auditoría de línea de comandos: {e}{Colors.ENDC}")
                audit_problem = True
            
            if audit_problem:
                add_recommendation("8.5", "Habilite la auditoría detallada de procesos (éxito y fallo) y la inclusión de la línea de comandos en los eventos de creación de procesos.")
        
        except subprocess.CalledProcessError as e:
            print(f"{Colors.FAIL}Error al consultar políticas de auditoría (auditpol): {e.stderr.strip()}{Colors.ENDC}")
            print(f"{Colors.WARNING}Asegúrese de ejecutar el script como administrador para acceder a las políticas de auditoría.{Colors.ENDC}")
            add_recommendation("8.5", "Verifique manualmente las políticas de auditoría avanzadas del sistema.")
        except Exception as e:
            print(f"{Colors.FAIL}Error al verificar auditoría detallada: {e}{Colors.ENDC}")
            add_recommendation("8.5", "Verifique manualmente las políticas de auditoría avanzadas del sistema.")

    except Exception as e:
        print(f"{Colors.FAIL}Error durante la verificación de gestión de logs: {e}{Colors.ENDC}")

def test_malware_defense():
    """
    Control 10: Malware Defense
    Checks Windows Defender status and other detected antivirus solutions.
    """
    print_section_header("Control 10: Defensa contra Malware")

    if not c:
        print(f"{Colors.WARNING}Conexión WMI no disponible. Saltando verificación de defensa contra malware.{Colors.ENDC}")
        return

    try:
        # Windows Defender Status (via WMI root\Microsoft\Windows\Defender)
        print("Windows Defender:")
        defender_problem = False
        defender_found = False
        try:
            # Namespace for Windows Defender WMI is root\Microsoft\Windows\Defender
            defender_wmi = wmi.WMI(namespace="root\\Microsoft\\Windows\\Defender")
            for defender_status in defender_wmi.MSFT_MpComputerStatus():
                defender_found = True
                av_enabled = f"{Colors.OKGREEN}Sí{Colors.ENDC}" if defender_status.AntivirusEnabled else f"{Colors.FAIL}No{Colors.ENDC}"
                rtp_enabled = f"{Colors.OKGREEN}Sí{Colors.ENDC}" if defender_status.RealTimeProtectionEnabled else f"{Colors.FAIL}No{Colors.ENDC}"

                print(f"- Antivirus habilitado: {av_enabled}")
                print(f"- Protección en tiempo real: {rtp_enabled}")
                
                last_update_str = "N/A"
                if defender_status.AntivirusSignatureLastUpdated:
                    try:
                        # WMI datetime format to Python datetime (e.g., 20240101120000.000000-420)
                        last_update_dt = datetime.datetime.strptime(defender_status.AntivirusSignatureLastUpdated.split('.')[0], '%Y%m%d%H%M%S')
                        last_update_str = last_update_dt.strftime('%Y-%m-%d %H:%M:%S')
                        if (datetime.datetime.now() - last_update_dt).days > 7: # Signatures older than 7 days
                             last_update_str = f"{Colors.WARNING}{last_update_str} (Antiguo){Colors.ENDC}"
                             defender_problem = True
                        else:
                            last_update_str = f"{Colors.OKGREEN}{last_update_str}{Colors.ENDC}"
                    except ValueError:
                        pass # Keep N/A
                print(f"- Última actualización de firma: {last_update_str}")
                
                if not (defender_status.AntivirusEnabled and defender_status.RealTimeProtectionEnabled):
                    print(f"{Colors.FAIL}⚠️ Windows Defender no está completamente activo.{Colors.ENDC}")
                    defender_problem = True
                break
        except wmi.WMIError as e:
            print(f"- {Colors.FAIL}No se pudo obtener el estado de Windows Defender (WMI error: {e}). Puede que requiera permisos de administrador o que el servicio esté detenido.{Colors.ENDC}")
            defender_problem = True
        except Exception as e:
            print(f"- {Colors.FAIL}Error al obtener el estado de Windows Defender: {e}{Colors.ENDC}")
            defender_problem = True
        
        if not defender_found or defender_problem:
            add_recommendation("10.2, 10.3", "Asegúrese de que Windows Defender (o su solución AV) esté activo, con protección en tiempo real y que las firmas se actualicen automáticamente.")


        # Other Antivirus Solutions (via WMI root\SecurityCenter2 - Salvaguarda 10.2)
        print("\nSoluciones antivirus detectadas (via SecurityCenter2):")
        antivirus_product_found = False
        antivirus_product_problem = False
        try:
            # Namespace for Security Center is root\SecurityCenter2
            security_center_wmi = wmi.WMI(namespace="root\\SecurityCenter2")
            for av_product in security_center_wmi.AntivirusProduct(): # Use AntivirusProduct for AV
                antivirus_product_found = True
                state_code = av_product.productState
                product_status = "Desconocido"
                
                # Simplified check for active state
                if (state_code & 0x100000) == 0x100000: # Product is enabled/active
                    product_status = f"{Colors.OKGREEN}Activo{Colors.ENDC}"
                elif (state_code & 0x01000) == 0x01000: # Product is disabled
                    product_status = f"{Colors.FAIL}Deshabilitado{Colors.ENDC}"
                    antivirus_product_problem = True
                elif (state_code & 0x0001) == 0x0001: # Product is snoozed
                    product_status = f"{Colors.WARNING}En pausa{Colors.ENDC}"
                    antivirus_product_problem = True
                else:
                    product_status = f"{Colors.WARNING}Estado no óptimo (Código: {state_code}){Colors.ENDC}"
                    antivirus_product_problem = True

                print(f"- {av_product.displayName} (Estado: {product_status})")
        except wmi.WMIError as e:
            print(f"- {Colors.FAIL}No se pudo consultar otras soluciones antivirus (WMI error: {e}). Puede que SecurityCenter2 no esté disponible o se requieran permisos.{Colors.ENDC}")
            antivirus_product_problem = True
        except Exception as e:
            print(f"- {Colors.FAIL}Error al obtener otras soluciones antivirus: {e}{Colors.ENDC}")
            antivirus_product_problem = True
        
        if not antivirus_product_found:
            print("- No se detectaron otras soluciones antivirus vía SecurityCenter2.")
            add_recommendation("10.2", "Asegúrese de tener una solución antivirus activa y monitoreada.")
        elif antivirus_product_problem:
            add_recommendation("10.2", "Revise el estado de las soluciones antivirus detectadas; algunas pueden no estar en un estado óptimo.")


        # Removable Media Scan (Salvaguarda 10.4) - Check for auto-scan registry setting
        print("\nConfiguración de Escaneo Automático de Medios Removibles:")
        removable_scan_problem = False
        try:
            # This is a common registry key for Windows Defender/Group Policy
            key_path = r"SOFTWARE\Policies\Microsoft\Windows Defender\Scan"
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ)
            disable_removable_drive_scan, _ = winreg.QueryValueEx(key, "DisableRemovableDriveScanning")
            
            if disable_removable_drive_scan == 0:
                print(f"{Colors.OKGREEN}✓ Escaneo automático de medios removibles: Habilitado.{Colors.ENDC}")
            else:
                print(f"{Colors.WARNING}Escaneo automático de medios removibles: Deshabilitado.{Colors.ENDC}")
                removable_scan_problem = True
            winreg.CloseKey(key)
        except FileNotFoundError:
            print(f"{Colors.WARNING}La configuración de escaneo automático de medios removibles no está definida por GPO. (Por defecto, Windows Defender escanea).{Colors.ENDC}")
            # This is not necessarily a "problem" if default behavior is good. Can be left without recommendation if it's implicitly on.
            pass
        except Exception as e:
            print(f"{Colors.FAIL}Error al verificar el escaneo de medios removibles: {e}{Colors.ENDC}")
            removable_scan_problem = True
        
        if removable_scan_problem:
            add_recommendation("10.4", "Asegúrese de que los medios removibles se escaneen automáticamente al conectarse.")

    except Exception as e:
        print(f"{Colors.FAIL}Error durante la verificación de defensa contra malware: {e}{Colors.ENDC}")

def test_network_vulnerabilities():
    """
    Control 12: Network Infrastructure Management
    Checks for enabled SMBv1 protocol and lists active network adapters.
    """
    print_section_header("Control 12: Gestión de Infraestructura de Red")

    try:
        # SMBv1 Status (Checking registry for SMB1Protocol status - Salvaguarda 4.8)
        print("Estado de SMBv1:")
        smbv1_enabled_problem = False
        try:
            # Check LanmanServer (server component)
            server_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", 0, winreg.KEY_READ)
            try:
                smb1_value, _ = winreg.QueryValueEx(server_key, "SMB1")
                if smb1_value == 1:
                    print(f"  Componente de servidor (LanmanServer\\Parameters\\SMB1): {Colors.FAIL}Habilitado{Colors.ENDC}")
                    smbv1_enabled_problem = True
                else:
                    print(f"  Componente de servidor (LanmanServer\\Parameters\\SMB1): {Colors.OKGREEN}Deshabilitado{Colors.ENDC}")
            except FileNotFoundError:
                print(f"  Componente de servidor (LanmanServer\\Parameters\\SMB1): {Colors.OKGREEN}No existe la clave (probablemente deshabilitado o valor por defecto).{Colors.ENDC}")
            winreg.CloseKey(server_key)

            # Check LanmanWorkstation (client component) for MrxSmb10 service
            result = subprocess.run(['sc', 'query', 'mrxsmb10'], capture_output=True, text=True, check=False, encoding='utf-8', errors='ignore')
            if "RUNNING" in result.stdout:
                print(f"  Componente de cliente (mrxsmb10): {Colors.FAIL}Habilitado (Servicio en ejecución){Colors.ENDC}")
                smbv1_enabled_problem = True
            else:
                print(f"  Componente de cliente (mrxsmb10): {Colors.OKGREEN}Deshabilitado (Servicio no en ejecución){Colors.ENDC}")

        except Exception as e:
            print(f"  {Colors.FAIL}Error al verificar SMBv1 en el registro/servicios: {e}{Colors.ENDC}")
            smbv1_enabled_problem = True

        if smbv1_enabled_problem:
            add_recommendation("4.8", "Deshabilite los protocolos inseguros como SMBv1. Verifique tanto el componente de servidor como el de cliente.")
        else:
            print(f"  {Colors.OKGREEN}✓ SMBv1 deshabilitado.{Colors.ENDC}")


        # Network Adapters (Salvaguarda 12.1 - for basic inventory)
        print("\nAdaptadores de red activos:")
        network_adapters_found = False
        for iface in psutil.net_if_stats():
            stats = psutil.net_if_stats()[iface]
            addrs = psutil.net_if_addrs().get(iface)
            ip_addresses = []
            if addrs:
                for addr in addrs:
                    if addr.family == socket.AF_INET: # IPv4
                        ip_addresses.append(addr.address)
            
            if stats.isup:
                network_adapters_found = True
                print(f"- {iface}: Estado {Colors.OKGREEN}Activo{Colors.ENDC}, Velocidad: {stats.speed} Mbps, IPs: {', '.join(ip_addresses) if ip_addresses else 'N/A'}")
        
        if not network_adapters_found:
            print("- No se encontraron adaptadores de red activos.")
        add_recommendation("12.6", "Revise las configuraciones de los adaptadores de red y considere la segmentación de red para aislar sistemas críticos.")

    except Exception as e:
        print(f"{Colors.FAIL}Error durante la verificación de vulnerabilidades de red: {e}{Colors.ENDC}")

def print_pending_cis_controls_info():
    """
    Prints detailed information about pending CIS Controls and key considerations.
    """
    print("\n" + "=" * 50)
    print(f"{Colors.HEADER}{Colors.BOLD}=== Puntos Pendientes y Recomendaciones para la Implementación de los Controles CIS v8.1 ==={Colors.ENDC}")
    print("Este script proporciona una auditoría inicial de varios Controles CIS, pero la implementación completa")
    print("de cada Control y sus Salvaguardas (Safeguards) requiere un enfoque más profundo, que a menudo incluye:")
    print(f"- {Colors.BOLD}Políticas y Procedimientos:{Colors.ENDC} Muchos controles dependen de la existencia, revisión y aplicación de políticas documentadas.")
    print(f"- {Colors.BOLD}Herramientas Dedicadas:{Colors.ENDC} Software de gestión de activos, SIEM, soluciones MDM, EDR/XDR, etc.")
    print(f"- {Colors.BOLD}Entrenamiento y Concientización:{Colors.ENDC} El factor humano es clave en la seguridad.")
    print(f"- {Colors.BOLD}Auditorías y Pruebas Periódicas:{Colors.ENDC} Validar la efectividad de los controles.")
    print(f"- {Colors.BOLD}Integración con Directorio Activo/GPOs:{Colors.ENDC} Para una gestión centralizada en entornos empresariales.")
    print("---")

    print(f"\n{Colors.BOLD}Control 1: Inventario y Control de Activos Empresariales{Colors.ENDC}")
    print("  - Puntos ya cubiertos parcialmente por el script: Identificación básica de hardware y detección de dispositivos USB.")
    print("  - Puntos clave a tener en cuenta (pendientes de auditoría por script o que requieren más):")
    print("    - 1.1 Establecer y Mantener un Inventario Detallado de Activos: No solo listar, sino tener información completa (propietario, ubicación, función, criticidad, sistema operativo, versión del firmware, etc.). Esto debe ser un proceso continuo, idealmente automatizado.")
    print("    - 1.2 Abordar Activos No Autorizados: El script detecta USBs, pero se necesita un proceso formal (y técnico) para identificar y gestionar/remediar cualquier dispositivo no autorizado en la red (ej. laptops personales, dispositivos IoT no aprobados). Considerar el uso de Network Access Control (NAC).")
    print("    - 1.3 Utilizar una Herramienta de Descubrimiento Activo: Implementar y configurar herramientas que escaneen la red de forma recurrente para descubrir nuevos activos.")
    print("    - 1.4 Utilizar DHCP Logging para Actualizar el Inventario: Integrar la información de DHCP para identificar rápidamente nuevos dispositivos que se conectan a la red.")
    print("    - 1.5 Inventario de Software en Firmware: Considerar el software integrado en el firmware de dispositivos (ej. routers, switches).")

    print(f"\n{Colors.BOLD}Control 3: Protección de Datos{Colors.ENDC}")
    print("  - Puntos ya cubiertos parcialmente por el script: Cifrado de disco (BitLocker).")
    print("  - Puntos clave a tener en cuenta (pendientes de auditoría por script):")
    print("    - 3.1 Establecer y Mantener un Proceso de Gestión de Datos Sensibles: Clasificación de datos (ej. pública, interna, confidencial), dónde se almacenan, quién tiene acceso, etc.")
    print("    - 3.2 Configurar Listas de Control de Acceso (ACLs): Asegurar que solo usuarios/grupos autorizados tengan acceso a los datos según su clasificación.")
    print("    - 3.3 Proteger Datos en Reposo: Cifrado de archivos y bases de datos más allá del cifrado de disco completo, si aplica.")
    print("    - 3.4 Retener Datos Basado en Procesos de Gestión: Definir y aplicar políticas de retención de datos.")
    print("    - 3.5 Eliminar Datos de Forma Segura: Implementar procedimientos para la eliminación segura de datos y dispositivos.")
    print("    - 3.6 Cifrar Datos en Dispositivos de Punto Final: Más allá del cifrado de disco completo, asegurar que la información sensible en laptops y otros endpoints esté protegida.")
    print("    - 3.7 Proteger Datos en Tránsito: Implementar HTTPS, VPNs, y otros protocolos de cifrado para la comunicación de datos.")

    print(f"\n{Colors.BOLD}Control 7: Gestión de Vulnerabilidades{Colors.ENDC}")
    print("  - Puntos clave a tener en cuenta (pendientes de auditoría por script):")
    print("    - 7.1 Establecer y Mantener un Proceso de Gestión de Vulnerabilidades: Un proceso integral que incluya escaneo, análisis, priorización, remediación y verificación.")
    print("    - 7.2 Realizar Escaneos de Vulnerabilidades Automatizados: Uso de herramientas de escaneo de vulnerabilidades para identificar debilidades en sistemas y aplicaciones.")
    print("    - 7.3 Realizar Escaneos Autenticados: Escaneos que utilizan credenciales para una detección más profunda de vulnerabilidades.")
    print("    - 7.4 Realizar Escaneos Periódicos en Aplicaciones Web: Si existen aplicaciones web.")
    print("    - 7.5 Remediar Vulnerabilidades: Un plan para aplicar parches y configuraciones para mitigar las vulnerabilidades descubiertas.")

    print(f"\n{Colors.BOLD}Control 9: Recuperación de Datos{Colors.ENDC}")
    print("  - Puntos clave a tener en cuenta (pendientes de auditoría por script):")
    print("    - 9.1 Establecer y Mantener un Proceso de Recuperación de Datos: Definir qué datos se respaldan, con qué frecuencia, dónde se almacenan y quién es responsable.")
    print("    - 9.2 Realizar Copias de Seguridad Automáticamente: Implementar soluciones de respaldo automatizadas para datos críticos.")
    print("    - 9.3 Proteger Datos de Recuperación: Asegurar que los backups estén protegidos (cifrado, control de acceso) al mismo nivel que los datos originales.")
    print("    - 9.4 Establecer y Mantener un Contenedor Aislado de Datos de Recuperación: Almacenar copias de seguridad críticas en ubicaciones offline o en una red aislada para protegerse contra ransomware y otros ataques que puedan afectar los backups en línea.")
    print("    - 9.5 Probar el Sistema de Recuperación de Datos: Realizar pruebas periódicas de restauración para asegurar que los datos pueden ser recuperados efectivamente.")

    print(f"\n{Colors.BOLD}Control 11: Gestión de Registros de Auditoría{Colors.ENDC}")
    print("  - Puntos ya cubiertos parcialmente por el script: Estado del servicio Event Log, tamaños de logs principales, sincronización horaria y auditoría de creación de procesos/línea de comandos.")
    print("  - Puntos clave a tener en cuenta (pendientes de auditoría por script):")
    print("    - 11.6 Recopilar Registros de Auditoría de Red: Recopilación de logs de dispositivos de red (firewalls, routers, switches).")
    print("    - 11.7 Recopilar Registros de Auditoría de Aplicaciones: Logs de aplicaciones clave.")
    print("    - 11.8 Centralizar y Retener Registros de Auditoría: Implementar un SIEM (Security Information and Event Management) o una solución de gestión de logs centralizada para recolectar, analizar y retener los logs por períodos adecuados (mínimo 90 días, idealmente más para forensia y cumplimiento).")
    print("    - 11.9 Monitorear Registros de Auditoría: Revisión activa y alerta sobre eventos de seguridad críticos.")

    print(f"\n{Colors.BOLD}Control 13: Gestión de Activos Móviles, de Periféricos y de Trabajo Remoto{Colors.ENDC}")
    print("  - Puntos clave a tener en cuenta (pendientes de auditoría por script):")
    print("    - 13.1 Establecer y Mantener un Inventario de Dispositivos Móviles: Similar al Control 1, pero específico para móviles (laptops, smartphones, tablets).")
    print("    - 13.2 Configurar de Forma Segura Dispositivos Móviles y Remotos: Aplicación de políticas de seguridad (MFA, bloqueo de pantalla, cifrado) y el uso de MDM (Mobile Device Management) o UEM (Unified Endpoint Management).")
    print("    - 13.3 Realizar Escaneos de Malware en Dispositivos Móviles: Asegurar que los dispositivos móviles también estén protegidos contra malware.")
    print("    - 13.4 Implementar Autenticación Multi-Factor (MFA) para Acceso Remoto: Esencial para proteger las conexiones desde ubicaciones no confiables.")
    print("    - 13.5 Establecer y Mantener Acceso Remoto Seguro: Uso de VPNs seguras, políticas de acceso menos privilegiado y monitoreo de sesiones remotas.")

    print(f"\n{Colors.BOLD}Control 14: Capacitación y Concientización en Seguridad{Colors.ENDC}")
    print("  - Puntos clave a tener en cuenta (pendientes de auditoría por script):")
    print("    - 14.1 Establecer y Mantener un Programa de Concientización en Seguridad: Capacitación inicial y periódica para todos los empleados sobre políticas de seguridad, amenazas comunes y mejores prácticas.")
    print("    - 14.2 Capacitar al Personal en Detección de Ataques de Ingeniería Social: Simulación de phishing y entrenamiento sobre cómo reconocer y reportar estos ataques.")
    print("    - 14.3 Capacitar al Personal en Mejores Prácticas de Autenticación: Uso de MFA, gestión de contraseñas seguras, etc.")
    print("    - 14.4 Capacitar al Personal en Mejores Prácticas de Manejo de Datos: Cómo identificar, almacenar, transferir y eliminar datos sensibles de forma segura.")

    print(f"\n{Colors.BOLD}Control 15: Gestión de Proveedores de Servicios{Colors.ENDC}")
    print("  - Puntos clave a tener en cuenta (pendientes de auditoría por script):")
    print("    - 15.1 Establecer y Mantener un Inventario de Proveedores de Servicios Externos: Saber qué proveedores tienen acceso a qué sistemas o datos.")
    print("    - 15.2 Establecer y Mantener un Proceso de Evaluación de la Seguridad de Proveedores: Evaluar la postura de seguridad de los proveedores antes de contratarlos y periódicamente.")
    print("    - 15.3 Asegurar que los Contratos con Proveedores Incluyan Requisitos de Seguridad: Cláusulas sobre protección de datos, auditorías, notificación de incidentes, etc.")
    print("    - 15.4 Monitorear la Seguridad de los Proveedores de Servicios Externos: Auditorías regulares, revisión de informes SOC 2, etc.")

    print(f"\n{Colors.BOLD}Control 16: Gestión de la Seguridad de las Aplicaciones{Colors.ENDC}")
    print("  - Puntos ya cubiertos parcialmente por el script: Inventario de software (indirectamente).")
    print("  - Puntos clave a tener en cuenta (pendientes de auditoría por script):")
    print("    - 16.1 Establecer y Mantener un Inventario de Aplicaciones: Similar al Control 2, pero enfocado en aplicaciones críticas y sus componentes.")
    print("    - 16.2 Gestionar el Ciclo de Vida de Desarrollo Seguro (SDLC): Integrar la seguridad desde el diseño hasta el despliegue y el mantenimiento de las aplicaciones.")
    print("    - 16.3 Realizar Pruebas de Seguridad en Aplicaciones: Pruebas de seguridad estáticas (SAST), dinámicas (DAST), análisis de composición de software (SCA) y pruebas de penetración en aplicaciones.")
    print("    - 16.4 Gestionar Vulnerabilidades en Aplicaciones: Identificar, priorizar y remediar vulnerabilidades en el código y en las bibliotecas de las aplicaciones.")
    print("    - 16.5 Implementar Controles de Seguridad de Aplicaciones: Asegurar que las aplicaciones apliquen controles como autenticación robusta, autorización, validación de entradas, gestión de sesiones, etc.")

    print(f"\n{Colors.BOLD}Control 17: Gestión de Respuesta a Incidentes{Colors.ENDC}")
    print("  - Puntos clave a tener en cuenta (pendientes de auditoría por script):")
    print("    - 17.1 Establecer y Mantener un Plan de Respuesta a Incidentes (IRP): Documentar los roles, responsabilidades, procedimientos y contactos para la gestión de incidentes.")
    print("    - 17.2 Asignar Roles y Responsabilidades de Respuesta a Incidentes: Definir claramente quién hace qué durante un incidente.")
    print("    - 17.3 Establecer y Mantener Contactos de Comunicación de Incidentes: Listas de contactos internos y externos (proveedores, autoridades).")
    print("    - 17.4 Definir Métricas de Incidentes: Indicadores clave para medir la efectividad de la respuesta a incidentes.")
    print("    - 17.5 Realizar Ejercicios de Prueba de Respuesta a Incidentes: Simulaciones de incidentes para probar la efectividad del plan y la preparación del equipo.")
    print("    - 17.6 Publicar el Plan de Respuesta a Incidentes: Asegurar que el plan sea accesible para el personal relevante.")

    print(f"\n{Colors.BOLD}Control 18: Pruebas de Penetración{Colors.ENDC}")
    print("  - Puntos clave a tener en cuenta (pendientes de auditoría por script):")
    print("    - 18.1 Establecer y Mantener un Proceso de Pruebas de Penetración: Definir el alcance, la frecuencia y los requisitos para las pruebas.")
    print("    - 18.2 Realizar Pruebas de Penetración en la Red Externa: Simular ataques de un adversario externo.")
    print("    - 18.3 Realizar Pruebas de Penetración en la Red Interna: Simular ataques de un adversario con acceso interno.")
    print("    - 18.4 Realizar Pruebas de Penetración en Aplicaciones Web: Si existen aplicaciones web críticas.")
    print("    - 18.5 Realizar Pruebas de Penetración Internas Periódicas: Estas pruebas deben hacerse periódicamente (al menos anualmente) para identificar y explotar debilidades en los controles.")
    print("\n" + "=" * 50)


# --- Función Principal de Auditoría ---

def invoke_cis_controls_audit():
    """
    Main function to run all CIS Controls audit checks.
    """
    print(f"{Colors.BOLD}Iniciando auditoría de Controles CIS v8.1 en Windows{Colors.ENDC}")
    print(f"Fecha: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Sistema: {platform.node()}")
    try:
        current_user = psutil.users()[0].name if psutil.users() else 'N/A'
    except Exception:
        current_user = 'N/A'
    print(f"Usuario Ejecutando: {current_user}")
    print("=" * 50)

    if not is_admin():
        print(f"{Colors.FAIL}¡ADVERTENCIA CRÍTICA: EL SCRIPT NO SE ESTÁ EJECUTANDO CON PRIVILEGIOS DE ADMINISTRADOR!{Colors.ENDC}")
        print(f"{Colors.FAIL}Muchas verificaciones fallarán o darán resultados incompletos. Por favor, ejecute como Administrador.{Colors.ENDC}")
        input("Presione Enter para continuar de todos modos (algunas funciones podrían fallar)...")
    
    # Re-initialize WMI if admin check passes, or if it was initially None
    global c
    if c is None and is_admin():
         try:
            c = wmi.WMI()
         except wmi.WMIConnectionError as e:
            print(f"{Colors.FAIL}Error al reconectar con WMI: {e}. Algunas funciones pueden verse afectadas.{Colors.ENDC}")
         except Exception as e:
            print(f"{Colors.FAIL}Error inesperado al re-inicializar WMI: {e}{Colors.ENDC}")


    try:
        get_hardware_inventory()
        get_software_inventory()
        test_network_security()
        test_account_management()
        test_access_control()
        test_audit_logs()
        test_malware_defense()
        test_network_vulnerabilities()

        print("\n" + "=" * 50)
        print(f"{Colors.OKGREEN}{Colors.BOLD}Auditoría completada.{Colors.ENDC}")
        print("\n" + f"{Colors.HEADER}{Colors.BOLD}=== Resumen de Recomendaciones CIS v8.1 (Basadas en la Auditoría Automática) ==={Colors.ENDC}")

        if RECOMMENDATIONS:
            for i, rec in enumerate(RECOMMENDATIONS):
                print(f"{i+1}. {Colors.WARNING}{rec}{Colors.ENDC}")
        else:
            print(f"{Colors.OKGREEN}✓ No se encontraron recomendaciones principales automáticas basadas en esta auditoría.{Colors.ENDC}")
        
        print("\n" + f"{Colors.BOLD}Acciones Adicionales:{Colors.ENDC}")
        print("- Revise los detalles de cada sección para información más específica.")
        print("- Los Controles CIS son un marco integral; esta auditoría cubre solo algunos puntos.")
        print("- Considere el uso de herramientas de hardening automatizadas para implementar las recomendaciones.")
        
        # Call the new function to print information about pending controls
        print_pending_cis_controls_info()

    except Exception as e:
        print(f"\n{Colors.FAIL}{Colors.BOLD}¡ERROR GRAVE DURANTE LA AUDITORÍA!{Colors.ENDC}")
        print(f"{Colors.FAIL}El script encontró un error inesperado: {e}{Colors.ENDC}")
        print(f"{Colors.FAIL}Por favor, revise la salida anterior para errores específicos.{Colors.ENDC}")

if __name__ == "__main__":
    invoke_cis_controls_audit()