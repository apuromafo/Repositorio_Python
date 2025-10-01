#!/usr/bin/env python3

import argparse
import sys
import re
import subprocess
from subprocess import PIPE
import datetime
import time
from colorama import init, Fore, Style

init(autoreset=True)

__version__ = '4.1.0'

LOG_LEVELS = 'VDIWE'
LOG_LEVELS_MAP = {LOG_LEVELS[i]: i for i in range(len(LOG_LEVELS))}

def run_cmd(cmd):
    try:
        return subprocess.check_output(cmd).decode('utf-8', errors='replace').splitlines()
    except subprocess.CalledProcessError:
        return []

def get_app_pid(serial, package):
    cmd = ['adb', '-s', serial, 'shell', 'pidof', package]
    try:
        return subprocess.check_output(cmd, stderr=PIPE).decode('utf-8').strip()
    except subprocess.CalledProcessError:
        return None

def launch_app(serial, package):
    cmd = ['adb', '-s', serial, 'shell', 'monkey', '-p', package, '1']
    try:
        subprocess.run(cmd, stdout=PIPE, stderr=PIPE, check=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"{Fore.RED}❌ Error al lanzar la app: {e}{Style.RESET_ALL}")
        return False

def generate_log_filename(package):
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M")
    return f"{package}_{timestamp}.log"

def choose_min_levels():
    descriptions = {'V': 'Verbose', 'D': 'Debug', 'I': 'Info', 'W': 'Warning', 'E': 'Error'}
    options = {
        '0': 'verbose',
        '1': '_info',
        '2': '_debug',
        '3': 'warning',
        '4': 'error'
    }

    print(f"{Fore.CYAN}📌 Elige los niveles de logs a mostrar (separados por coma):{Style.RESET_ALL}")
    for key, label in options.items():
        level = LOG_LEVELS[int(key)]
        print(f"  [{key}] {label} - {descriptions[level]}")

    while True:
        try:
            user_input = input("Niveles (índices separados por coma, ej: 0,1,3): ").strip()
            if not user_input:
                return ['V']  # Por defecto: verbose

            selected_indices = [int(x.strip()) for x in user_input.split(',')]
            valid_indices = [i for i in selected_indices if 0 <= i < len(LOG_LEVELS)]

            if not valid_indices:
                print(f"{Fore.RED}⚠️ Ningún índice válido. Inténtalo de nuevo.{Style.RESET_ALL}")
                continue

            selected_levels = [LOG_LEVELS[i] for i in valid_indices]
            print(f"{Fore.GREEN}✅ Mostrando niveles: {', '.join(selected_levels)}{Style.RESET_ALL}")
            return selected_levels

        except ValueError:
            print(f"{Fore.RED}⚠️ Por favor, introduce números válidos separados por comas.{Style.RESET_ALL}")

def ask_launch_app(package):
    choice = input(f"¿Deseas lanzar la app '{package}' automáticamente? (_n/s/_no/_si): ").strip().lower()
    return choice in ['s', 'si', 'y', 'yes']

def select_device():
    print(f"{Fore.CYAN}🔍 Buscando dispositivos ADB...{Style.RESET_ALL}")
    lines = run_cmd(['adb', 'devices'])
    devices = [line.split('\t')[0] for line in lines if '\tdevice' in line]
    if not devices:
        print(f"{Fore.RED}❌ No se encontraron dispositivos conectados.{Style.RESET_ALL}")
        return None
    print(f"{Fore.GREEN}📱 Dispositivos encontrados:{Style.RESET_ALL}")
    for i, dev in enumerate(devices):
        print(f"  [{i}] {dev}")
    while True:
        try:
            idx = int(input("Selecciona dispositivo por índice: "))
            if 0 <= idx < len(devices):
                return devices[idx]
            else:
                print(f"{Fore.RED}⚠️ Índice inválido. Debe estar entre 0 y {len(devices) - 1}.{Style.RESET_ALL}")
        except ValueError:
            print(f"{Fore.RED}⚠️ Por favor, introduce un número válido.{Style.RESET_ALL}")

def select_package(serial):
    print(f"{Fore.CYAN}📦 Obteniendo lista de apps instaladas por el usuario...{Style.RESET_ALL}")
    cmd = ['adb', '-s', serial, 'shell', 'pm', 'list', 'packages', '-3']
    lines = run_cmd(cmd)
    packages = [line.replace('package:', '') for line in lines if line.startswith('package:')]
    if not packages:
        print(f"{Fore.RED}❌ No se encontraron aplicaciones instaladas.{Style.RESET_ALL}")
        return None
    print(f"{Fore.GREEN}📦 Aplicaciones encontradas:{Style.RESET_ALL}")
    for i, pkg in enumerate(packages):
        print(f"  [{i}] {pkg}")
    while True:
        try:
            idx = int(input("Selecciona paquete por índice: "))
            if 0 <= idx < len(packages):
                return packages[idx]
            else:
                print(f"{Fore.RED}⚠️ Índice inválido. Debe estar entre 0 y {len(packages) - 1}.{Style.RESET_ALL}")
        except ValueError:
            print(f"{Fore.RED}⚠️ Por favor, introduce un número válido.{Style.RESET_ALL}")

def start_logcat(serial, package, selected_levels, output_file):
    pid = None
    print(f"{Fore.YELLOW}⏳ Esperando que la app inicie...{Style.RESET_ALL}")
    for _ in range(60):  # hasta 60 segundos
        pid = get_app_pid(serial, package)
        if pid:
            break
        time.sleep(1)

    adb_command = ['adb', '-s', serial, 'logcat']

    if pid:
        adb_command.append('--pid=' + pid)
        print(f"{Fore.GREEN}✅ Filtrando logs por PID: {pid}{Style.RESET_ALL}")
    else:
        # Fallback: usar nivel de log + filtrado adicional en código
        for level in selected_levels:
            adb_command.append(f'{package}:{level}')
        adb_command.append('*:S')  # Silenciar otros tags
        print(f"{Fore.YELLOW}⚠️ App no iniciada aún. Usando filtro básico de TAG. Se aplicará filtrado adicional.{Style.RESET_ALL}")

    def colorize(level, message):
        colors = {
            'V': Fore.WHITE,
            'D': Fore.BLUE,
            'I': Fore.GREEN,
            'W': Fore.YELLOW,
            'E': Fore.RED,
            'F': Fore.RED
        }
        return f"{colors.get(level, '')}{message}{Style.RESET_ALL}"

    try:
        #adb = subprocess.Popen(adb_command, stdout=PIPE, stderr=PIPE, universal_newlines=True)
        adb = subprocess.Popen(adb_command, stdout=PIPE, stderr=PIPE, universal_newlines=True, encoding='utf-8', errors='replace')
        print(f"\n📡 Mostrando logs para {package}. Presiona Ctrl+C para detener.\n")

        while True:
            line = adb.stdout.readline()
            if not line:
                if adb.poll() is not None:
                    break
                continue

            line = line.strip()
            if not line:
                continue

            # Detectar crash
            if "FATAL EXCEPTION" in line or ("AndroidRuntime" in line and "java.lang" in line):
                print(f"\n{Fore.RED}💥 ¡DETECTADO CRASH EN LA APP! 💥{Style.RESET_ALL}")
                print(f"{Fore.RED}📌 Detalles del crash:{Style.RESET_ALL}")

            # Parsear línea de logcat: <level>/<tag>(pid): message
            log_line = re.match(r'^([A-Z])/(.+?)$ *$(\d+)$: (.*?)$', line)
            if log_line:
                level, tag, owner, message = log_line.groups()
                if level not in selected_levels:
                    continue

                # Verificar si el tag o mensaje contiene el nombre del paquete (más seguro)
                if package not in tag and package not in message:
                    continue

                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                colored_message = colorize(level, message)
                print(colored_message)
                output_file.write(f"[{timestamp}] {message}\n")
                output_file.flush()

    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}⏹️ Logcat detenido por el usuario.{Style.RESET_ALL}")
    finally:
        output_file.close()

def main_menu():
    print(f"{Fore.CYAN}🔧 Bienvenido al Logcat Interactivo v{__version__}{Style.RESET_ALL}")
    while True:
        print("\n--- Menú Principal ---")
        print("[0] Iniciar sesión de logcat")
        print("[1] _Reiniciar sesión")
        print("[2] _Salir")
        choice = input("Selecciona una opción: ").strip()
        if choice == "0":
            serial = select_device()
            if not serial:
                continue
            package = select_package(serial)
            if not package:
                continue
            launch = ask_launch_app(package)
            if launch:
                if not launch_app(serial, package):
                    continue
            selected_levels = choose_min_levels()
            filename = generate_log_filename(package)
            print(f"{Fore.CYAN}📝 Guardando logs en: {filename}{Style.RESET_ALL}")
            output_file = open(filename, 'w', encoding='utf-8')
            start_logcat(serial, package, selected_levels, output_file)
        elif choice in ["1", "_1", "_reiniciar", "reiniciar"]:
            continue
        elif choice in ["2", "_2", "_salir", "salir"]:
            print(f"{Fore.GREEN}👋 Saliendo del script. ¡Hasta pronto!{Style.RESET_ALL}")
            break
        else:
            print(f"{Fore.RED}⚠️ Opción inválida. Inténtalo de nuevo.{Style.RESET_ALL}")

if __name__ == '__main__':
    try:
        main_menu()
    except Exception as e:
        print(f"{Fore.RED}❌ Error fatal: {e}{Style.RESET_ALL}")
        sys.exit(1)