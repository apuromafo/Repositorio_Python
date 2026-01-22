"""
================================================================================
FRIDUMP PRO - SINGLE FILE
================================================================================
COMANDOS DE USO:
    1. Local:  python3 fridump_pro.py "NombreProceso"
    2. USB:    python3 fridump_pro.py -u "NombreProceso"
    3. IP:     python3 fridump_pro.py -H 192.168.1.15:27042 "NombreProceso"
================================================================================
"""

import frida
import os
import sys
import argparse
import logging
import re
from datetime import datetime

# --- SECCIÓN DE UTILIDADES (Basado en utils.py) ---

def print_progress(times, total, prefix='', suffix='', decimals=2, bar=50):
    """Muestra una barra de progreso visual."""
    filled = int(round(bar * times / float(total)))
    percents = round(100.00 * (times / float(total)), decimals)
    bar_str = '#' * filled + '-' * (bar - filled)
    sys.stdout.write(f'\r{prefix} [{bar_str}] {percents}% {suffix}')
    sys.stdout.flush()
    if times == total: print("\n")

def extract_strings(filename, directory, min_chars=4):
    """Extrae texto legible de los volcados binarios."""
    strings_file = os.path.join(directory, "strings.txt")
    path = os.path.join(directory, filename)
    with open(path, encoding='Latin-1') as infile:
        str_list = re.findall(r"[A-Za-z0-9/\-:;.,_$%'!()[\]<> \#]+", infile.read())
        with open(strings_file, "a") as st:
            for s in str_list:
                if len(s) > min_chars:
                    st.write(s + "\n")

def normalize_app_name(app_name):
    """Asegura que el nombre de la app sea procesable por Frida."""
    try:
        return int(app_name)
    except ValueError:
        return app_name

# --- SECCIÓN DE VOLCADO (Basado en dumper.py) ---

def dump_to_file(agent, base, size, directory):
    """Escribe un bloque de memoria a disco."""
    try:
        filename = f"{base}_dump.data"
        dump = agent.read_memory(base, size)
        with open(os.path.join(directory, filename), 'wb') as f:
            f.write(dump)
    except Exception as e:
        logging.debug(f"Error en {base}: {e}")

def splitter(agent, base, size, max_size, directory):
    """Divide bloques grandes en partes más pequeñas."""
    times = size // max_size
    diff = size % max_size
    cur_base = int(base, 0) if isinstance(base, str) else base

    for _ in range(times):
        dump_to_file(agent, cur_base, max_size, directory)
        cur_base += max_size

    if diff != 0:
        dump_to_file(agent, cur_base, diff, directory)

# --- FLUJO PRINCIPAL (Basado en fridump3.py) ---

def main():
    parser = argparse.ArgumentParser(prog='fridump')
    parser.add_argument('process', help='Proceso objetivo')
    parser.add_argument('-o', '--out', help='Directorio base')
    parser.add_argument('-u', '--usb', action='store_true', help='Usar USB')
    parser.add_argument('-H', '--host', help='Usar IP:PUERTO')
    parser.add_argument('-v', '--verbose', action='store_true', help='Modo detallado')
    parser.add_argument('-r', '--read-only', action='store_true', help='Vuelca R--')
    parser.add_argument('-s', '--strings', action='store_true', help='Extraer texto')
    parser.add_argument('--max-size', type=int, default=20971520, help='Max bytes por archivo')
    
    args = parser.parse_args()

    app_name = normalize_app_name(args.process)
    debug_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(format='%(levelname)s:%(message)s', level=debug_level)
    perms = 'r--' if args.read_only else 'rw-'

    try:
        if args.usb:
            device = frida.get_usb_device()
        elif args.host:
            device = frida.get_device_manager().add_remote_device(args.host)
        else:
            device = frida.get_local_device()
        
        session = device.attach(app_name)
    except Exception as e:
        print(f"Error de conexión: {e}")
        sys.exit(1)

    # 1. Crear carpetas con fecha
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    folder_name = f"{args.process}_{timestamp}"
    base_dir = args.out if args.out else os.path.join(os.getcwd(), "dump")
    directory = os.path.join(base_dir, folder_name)
    os.makedirs(directory, exist_ok=True)

    # 2. OBTENER INFORMACIÓN DEL DISPOSITIVO
    info_path = os.path.join(directory, "info_dispositivo.txt")
    with open(info_path, "w") as f:
        f.write(f"--- REPORTE DE DISPOSITIVO ---\n")
        f.write(f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"ID Dispositivo: {device.id}\n")
        f.write(f"Nombre: {device.name}\n")
        f.write(f"Tipo: {device.type}\n")
    
    print(f"📱 Información del dispositivo guardada en: info_dispositivo.txt")
    print(f"📁 Destino: {directory}")

    # 3. Cargar Script de Frida
    script = session.create_script("""
    'use strict';
    rpc.exports = {
        enumerateRanges: async function (prot) { return await Process.enumerateRanges(prot); },
        readMemory: function (address, size) { return ptr(address).readByteArray(size); }
    };
    """)
    script.load()
    agent = script.exports_sync
    ranges = agent.enumerate_ranges(perms)

    # 4. Volcado
    for i, r in enumerate(ranges):
        if r["size"] > args.max_size:
            splitter(agent, r["base"], r["size"], args.max_size, directory)
        else:
            dump_to_file(agent, r["base"], r["size"], directory)
        print_progress(i + 1, len(ranges), prefix='Progreso:', suffix='Completo')

    if args.strings:
        files = [f for f in os.listdir(directory) if f.endswith('.data')]
        for i, f1 in enumerate(files):
            extract_strings(f1, directory)
            print_progress(i + 1, len(files), prefix='Strings:', suffix='Completo')

    print(f"✅ ¡Proceso finalizado con éxito!")

if __name__ == "__main__":
    main()