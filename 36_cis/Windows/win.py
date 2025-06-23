import platform
import wmi
import psutil
import winreg
import subprocess
import datetime
import math

# Initialize WMI connection (can be reused across functions)
# This handles potential connection errors more gracefully
try:
    c = wmi.WMI()
except wmi.WMIConnectionError as e:
    print(f"Error connecting to WMI: {e}. Please ensure WMI service is running and you have sufficient permissions.")
    c = None # Set c to None if connection fails to avoid further errors

def print_section_header(title):
    """Prints a formatted section header."""
    print(f"\n=== {title} ===")

def get_hardware_inventory():
    """
    Control 1: Inventory and Control of Hardware Assets
    Gathers basic system information and lists connected USB devices.
    """
    print_section_header("Control 1: Inventario de Hardware")

    if not c:
        print("WMI connection not available. Skipping hardware inventory.")
        return

    try:
        # System Information
        for os_info in c.Win32_OperatingSystem():
            print(f"Sistema: {os_info.Caption} - {os_info.Version}")
            break # Only need the first OS object

        # Total Physical Memory using psutil
        total_ram_gb = round(psutil.virtual_memory().total / (1024**3), 2)
        print(f"RAM Total: {total_ram_gb} GB")

        # USB Devices
        print("\nDispositivos USB detectados:")
        usb_devices = []
        for usb_controller_device in c.Win32_USBControllerDevice():
            try:
                dependent_path = usb_controller_device.Dependent
                # Parse the path to get the device description
                # Example: Dependent="\\\\COMPUTERNAME\\root\\cimv2:Win32_PnPEntity.DeviceID=\"USB\\VID_XXXX&PID_XXXX\\XXXXXXXX\""
                device_id_part = dependent_path.split('DeviceID="')[1].split('"')[0]

                # Use Win32_PnPEntity to get a more readable description
                for pnp_entity in c.Win32_PnPEntity(DeviceID=device_id_part):
                    if "Root Hub" not in pnp_entity.Description:
                        usb_devices.append(pnp_entity.Description)
            except Exception as e:
                # Handle cases where Dependent might not be a valid WMI path or other errors
                # print(f"Could not parse USB device: {e}")
                pass # Silently ignore parsing errors for robust output

        if usb_devices:
            for device in sorted(list(set(usb_devices))): # Use set to remove duplicates, then sort
                print(f"- {device}")
        else:
            print("- No se detectaron dispositivos USB no-Root Hub.")

    except Exception as e:
        print(f"Error during hardware inventory: {e}")

def get_software_inventory():
    """
    Control 2: Inventory and Control of Software Assets
    Lists installed software, running services, and checks for suspicious processes.
    """
    print_section_header("Control 2: Inventario de Software")

    if not c:
        print("WMI connection not available. Skipping software inventory.")
        return

    try:
        # Installed Software (Note: Win32_Product is generally slow and has side-effects.
        # For a more robust solution, query Uninstall registry keys or use third-party tools.)
        installed_software = []
        for product in c.Win32_Product():
            installed_software.append({
                "Name": product.Name,
                "Version": product.Version,
                "Vendor": product.Vendor
            })

        print(f"Total de programas instalados: {len(installed_software)}")
        # Optionally, print the list if needed:
        # for app in sorted(installed_software, key=lambda x: x['Name']):
        #     print(f"  - {app['Name']} v{app['Version']} ({app['Vendor']})")

        # Running Services
        running_services_count = 0
        for service in c.Win32_Service(State="Running"):
            running_services_count += 1
        print(f"Servicios en ejecución: {running_services_count}")

        # Suspicious Processes (basic example)
        suspicious_processes = []
        current_pid = psutil.Process().pid
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                process_name = proc.info['name'].lower()
                if process_name in ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"] and proc.info['pid'] != current_pid:
                    suspicious_processes.append(f"{proc.info['name']} (PID: {proc.info['pid']})")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                # Process no longer exists or access denied
                continue

        if suspicious_processes:
            print("\nProcesos que requieren revisión:")
            for sp in suspicious_processes:
                print(f"- {sp}")
        else:
            print("No se encontraron procesos sospechosos básicos.")

    except Exception as e:
        print(f"Error during software inventory: {e}")

def test_network_security():
    """
    Control 4: Secure Configuration of Network Devices
    Checks open TCP ports and firewall status.
    """
    print_section_header("Control 4: Seguridad de Red")

    try:
        # Open Ports
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
        else:
            print("- No se encontraron puertos TCP en escucha.")

        # Firewall Status
        print("\nEstado del Firewall:")
        if not c:
            print("WMI connection not available. Cannot check firewall status.")
            return

        # Query Win32_NetworkAdapterConfiguration for firewall status (basic)
        # For more detailed firewall status (profiles), this typically requires querying
        # root\StandardCimv2:MSFT_NetFirewallProfile, which might be more complex or require admin.
        # Using a simpler check via subprocess for netsh advfirewall for better compatibility.
        try:
            # Check domain, private, public profiles
            profiles = ["Domain Profile", "Private Profile", "Public Profile"]
            for profile_name in profiles:
                cmd = f'netsh advfirewall show {profile_name} state'
                result = subprocess.run(cmd, capture_output=True, text=True, shell=True, check=True)
                output = result.stdout.strip()
                status = "Desconocido"
                if "State                          ON" in output:
                    status = "Habilitado"
                elif "State                          OFF" in output:
                    status = "Deshabilitado"
                print(f"- {profile_name}: {status}")

        except subprocess.CalledProcessError as e:
            print(f"Error checking firewall status with netsh: {e.stderr.strip()}")
        except Exception as e:
            print(f"Error checking firewall status: {e}")

    except Exception as e:
        print(f"Error during network security check: {e}")

def test_account_management():
    """
    Control 5: Account Management
    Lists local user accounts, their status, and members of the Administrators group.
    """
    print_section_header("Control 5: Gestión de Cuentas")

    if not c:
        print("WMI connection not available. Skipping account management check.")
        return

    try:
        # Local User Accounts
        print("Cuentas de usuario locales:")
        local_users_found = False
        for user in c.Win32_UserAccount(LocalAccount=True):
            local_users_found = True
            status = "Activa" if user.Disabled == False else "Inactiva"
            
            last_logon_time = "N/A"
            # Getting LastLogon via WMI can be unreliable for local accounts,
            # it might require more complex LDAP queries for domain controllers.
            # Using Win32_NetworkLoginProfile for a more direct check for last logon
            try:
                for login_profile in c.Win32_NetworkLoginProfile(Name=user.Name):
                    if login_profile.LastLogon:
                        # WMI datetime format to Python datetime
                        last_logon_time = datetime.datetime.strptime(login_profile.LastLogon.split('.')[0], '%Y%m%d%H%M%S')
                        break
            except Exception:
                pass # Ignore errors if login profile is not found or datetime conversion fails

            print(f"- {user.Name}: {status}, Último acceso: {last_logon_time}")
            if user.PasswordRequired == False: # In WMI, PasswordRequired is inverse of "password is not required"
                print("  \033[91m⚠️  Sin contraseña requerida\033[0m") # Red text

        if not local_users_found:
            print("- No se encontraron cuentas de usuario locales.")

        # Administrative Accounts
        print("\nMiembros del grupo Administradores:")
        admin_group_found = False
        for group in c.Win32_Group(Name="Administrators"):
            admin_group_found = True
            try:
                for member in group.associators(wmi_result_class="Win32_GroupUser"):
                    print(f"- {member.Caption.split('\\')[-1]}") # Get just the username
            except Exception as e:
                print(f"  Error getting admin group members: {e}")
            break # Assume only one Administrators group

        if not admin_group_found:
            print("- No se encontró el grupo de Administradores.")

    except Exception as e:
        print(f"Error during account management check: {e}")

def test_access_control():
    """
    Control 6: Access Control Management
    Checks UAC settings and recent successful login events.
    """
    print_section_header("Control 6: Control de Acceso")

    try:
        # UAC Settings (User Account Control)
        uac_status = "Desconocido"
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", 0, winreg.KEY_READ)
            enable_lua_value, _ = winreg.QueryValueEx(key, "EnableLUA")
            winreg.CloseKey(key)
            uac_status = "Habilitado" if enable_lua_value == 1 else "Deshabilitado"
        except FileNotFoundError:
            uac_status = "No se encontró la clave de registro de UAC."
        except Exception as e:
            uac_status = f"Error al verificar UAC: {e}"
        print(f"Control de Cuentas de Usuario (UAC): {uac_status}")

        # Last Successful Logons (Event ID 4624)
        print("\nÚltimos inicios de sesión exitosos:")
        try:
            # Use wevtutil to query the Security log for Event ID 4624 (Successful Logon)
            # and limit to the last 10 events.
            cmd = ['wevtutil', 'query-events', 'Security', '/rd:true', '/q:*[System[(EventID=4624)]]', '/c:10', '/f:text']
            result = subprocess.run(cmd, capture_output=True, text=True, check=True, encoding='utf-8', errors='ignore')
            log_output = result.stdout.strip()

            logons_found = False
            for line in log_output.splitlines():
                if "Date:" in line:
                    logons_found = True
                    timestamp = line.replace("Date:", "").strip()
                elif "Account Name:" in line:
                    username = line.replace("Account Name:", "").strip()
                    print(f"- {timestamp}: Usuario {username}")
            
            if not logons_found:
                print("- No se encontraron inicios de sesión exitosos recientes.")

        except subprocess.CalledProcessError as e:
            print(f"Error consultando eventos de inicio de sesión (wevtutil): {e.stderr.strip()}")
            print("- Asegúrese de ejecutar el script como administrador para acceder a los registros de seguridad.")
        except Exception as e:
            print(f"Error al obtener los últimos inicios de sesión: {e}")

    except Exception as e:
        print(f"Error during access control check: {e}")


def test_audit_logs():
    """
    Control 8: Audit Log Management
    Checks the status of the Event Log service and the size/event count of main logs.
    """
    print_section_header("Control 8: Gestión de Logs")

    if not c:
        print("WMI connection not available. Skipping audit log check.")
        return

    try:
        # Verify Event Log Service
        event_log_service_status = "Desconocido"
        try:
            for service in c.Win32_Service(Name="EventLog"):
                event_log_service_status = service.State
                break
        except Exception as e:
            event_log_service_status = f"Error: {e}"
        print(f"Servicio de Event Log: {event_log_service_status}")

        # Main Log Sizes
        print("\nInformación de los logs principales:")
        log_names = ['System', 'Application', 'Security']
        for log_name in log_names:
            try:
                # Use wevtutil to get log information
                cmd = ['wevtutil', 'get-log', log_name]
                result = subprocess.run(cmd, capture_output=True, text=True, check=True, encoding='utf-8', errors='ignore')
                output = result.stdout.strip()

                file_size_mb = "N/A"
                record_count = "N/A"

                for line in output.splitlines():
                    if "FileSize:" in line:
                        size_bytes = int(line.split(':')[1].strip())
                        file_size_mb = round(size_bytes / (1024**2), 2)
                    if "RecordCount:" in line:
                        record_count = int(line.split(':')[1].strip())
                
                print(f"Log {log_name} - Tamaño: {file_size_mb} MB, Eventos: {record_count}")

            except subprocess.CalledProcessError as e:
                print(f"Error consultando log {log_name} (wevtutil): {e.stderr.strip()}")
                print(f"- Asegúrese de ejecutar el script como administrador para acceder al log '{log_name}'.")
            except Exception as e:
                print(f"Error al obtener información del log {log_name}: {e}")

    except Exception as e:
        print(f"Error during audit log check: {e}")

def test_malware_defense():
    """
    Control 10: Malware Defense
    Checks Windows Defender status and other detected antivirus solutions.
    """
    print_section_header("Control 10: Defensa contra Malware")

    if not c:
        print("WMI connection not available. Skipping malware defense check.")
        return

    try:
        # Windows Defender Status (via WMI root\Microsoft\Windows\Defender)
        print("Windows Defender:")
        defender_found = False
        try:
            # Requires admin privileges and Windows Defender to be present
            # Note: The PowerShell Get-MpComputerStatus is a specific cmdlet.
            # WMI equivalent for basic status:
            for defender_status in c.IMsft_MpComputerStatus(): # In namespace root\Microsoft\Windows\Defender
                defender_found = True
                print(f"- Antivirus habilitado: {'Sí' if defender_status.AntivirusEnabled else 'No'}")
                # LastSignatureUpdate and RealtimeProtectionEnabled might also be available
                print(f"- Última actualización de firma: {defender_status.AntivirusSignatureLastUpdated}")
                print(f"- Protección en tiempo real: {'Sí' if defender_status.RealTimeProtectionEnabled else 'No'}")
                break
        except wmi.WMIError as e:
            print(f"- No se pudo obtener el estado de Windows Defender (WMI error: {e}). Puede que requiera permisos de administrador.")
        except Exception as e:
            print(f"- Error al obtener el estado de Windows Defender: {e}")
        
        if not defender_found:
            print("- Windows Defender no parece estar activo o no se pudo consultar su estado.")


        # Other Antivirus Solutions (via WMI root\SecurityCenter2)
        print("\nSoluciones antivirus detectadas:")
        antivirus_found = False
        try:
            for av_product in c.Win32_Product(namespace="root\\SecurityCenter2"):
                # This might also list Windows Defender itself
                print(f"- {av_product.displayName} (Estado: {av_product.productState})")
                antivirus_found = True
        except wmi.WMIError as e:
            print(f"- No se pudo consultar otras soluciones antivirus (WMI error: {e}). Puede que SecurityCenter2 no esté disponible o se requieran permisos.")
        except Exception as e:
            print(f"- Error al obtener otras soluciones antivirus: {e}")
        
        if not antivirus_found:
            print("- No se detectaron otras soluciones antivirus.")

    except Exception as e:
        print(f"Error during malware defense check: {e}")

def test_network_vulnerabilities():
    """
    Control 12: Network Vulnerability Management
    Checks for enabled SMBv1 protocol and lists active network adapters.
    """
    print_section_header("Control 12: Vulnerabilidades de Red")

    try:
        # SMBv1 Status (Checking registry for SMB1Protocol status)
        print("Estado de SMBv1:")
        smbv1_enabled = False
        try:
            # Registry path for SMB1Protocol
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", 0, winreg.KEY_READ)
            smb1_value, _ = winreg.QueryValueEx(key, "SMB1")
            if smb1_value == 1:
                smbv1_enabled = True
            winreg.CloseKey(key)
        except FileNotFoundError:
            # SMB1 key might not exist if it's explicitly disabled or not configured
            pass
        except Exception as e:
            print(f"  Error al verificar SMBv1 en el registro: {e}")

        if smbv1_enabled:
            print("  \033[91m⚠️  SMBv1 está habilitado (inseguro)\033[0m") # Red text
        else:
            print("  \033[92m✓ SMBv1 deshabilitado\033[0m") # Green text

        # Network Adapters
        print("\nAdaptadores de red activos:")
        network_adapters_found = False
        for iface in psutil.net_if_stats():
            stats = psutil.net_if_stats()[iface]
            if stats.isup:
                network_adapters_found = True
                print(f"- {iface}: Estado Activo, Velocidad: {stats.speed} Mbps")
        
        if not network_adapters_found:
            print("- No se encontraron adaptadores de red activos.")

    except Exception as e:
        print(f"Error during network vulnerabilities check: {e}")

def invoke_cis_controls_audit():
    """
    Main function to run all CIS Controls audit checks.
    """
    print("Iniciando auditoría de Controles CIS v8.1")
    print(f"Fecha: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Sistema: {platform.node()}")
    print(f"Usuario: {psutil.users()[0].name if psutil.users() else 'N/A'}")
    print("=" * 50)

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
        print("\033[92mAuditoría completada exitosamente\033[0m") # Green text
        print("\033[93mRevise los resultados y tome las acciones correctivas necesarias\033[0m") # Yellow text

    except Exception as e:
        print(f"\033[91mError durante la auditoría: {e}\033[0m") # Red text

if __name__ == "__main__":
    invoke_cis_controls_audit()
