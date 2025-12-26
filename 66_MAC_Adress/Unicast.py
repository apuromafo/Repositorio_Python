#!/usr/bin/env python3
import random
import sys
import os
import argparse
import csv
from datetime import datetime

# --- CONFIGURACIÓN DE IDENTIDAD ---
VERSION = "0.0.2"
AUTHOR = "iTrox (Original) | Ported & Enhanced by Apuromafo"
RUBY_SOURCE = "https://github.com/iTroxB/My-scripts/blob/main/Random-MAC-Creator/randomMACcreator.rb"

COLORS = {
    "blue": "\033[34m", "calypso": "\033[96m", "green": "\033[32m",
    "red": "\033[31m", "yellow": "\033[33m", "orange": "\033[38;5;208m",
    "gray": "\033[90m", "reset": "\033[0m"
}

# Rutas de base de datos
DB_PATHS = [
    os.path.join("db", "nmap-mac-prefixes"),
    r"C:\Program Files (x86)\Nmap\nmap-mac-prefixes",
    "/usr/share/nmap/nmap-mac-prefixes"
]

def find_db():
    for path in DB_PATHS:
        if os.path.exists(path): return path
    return None

def print_banner():
    banner = f"""
 {COLORS['orange']} ██████  █████  ███    ██ ██████   ██████  ███    ███     ███    ███ █████   ██████ 
 {COLORS['orange']} ██   ██ ██   ██ ████   ██ ██   ██ ██    ██ ████  ████     ████  ████ ██   ██ ██     
 {COLORS['orange']} ██████  ███████ ██ ██  ██ ██   ██ ██    ██ ██ ████ ██     ██ ████ ██ ███████ ██     
 {COLORS['orange']} ██   ██ ██   ██ ██  ██ ██ ██   ██ ██    ██ ██  ██  ██     ██  ██  ██ ██   ██ ██     
 {COLORS['orange']} ██   ██ ██   ██ ██   ████ ██████   ██████  ██      ██     ██      ██ ██   ██  ██████ {COLORS['reset']}

  {COLORS['calypso']}v{VERSION} | Inspired by: {COLORS['blue']}iTrox v2{COLORS['reset']}
  {COLORS['gray']}Source:{COLORS['reset']} {RUBY_SOURCE}
    """
    print(banner)

def get_vendor(mac, db_path):
    if not db_path: return "DB Not Found (check /db/ folder)"
    prefix = mac.replace(":", "").upper()[:6]
    try:
        with open(db_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                if line.upper().startswith(prefix):
                    return line[7:].strip()
    except: pass
    return "Unknown Vendor / Private"

def analyze_mac(mac, db_path, quiet=False):
    """Confirmación de datos técnicos (Pwn Techniques)."""
    try:
        clean_mac = mac.strip().replace("-", ":").upper()
        if len(clean_mac.split(':')) != 6: raise ValueError("Format error")
        
        first_byte = int(clean_mac.split(':')[0], 16)
        
        data = {
            "mac": clean_mac,
            "vendor": get_vendor(clean_mac, db_path),
            "type": "Multicast (Broadcasting)" if (first_byte & 1) else "Unicast (Safe)",
            "admin": "Locally Administered (LAA)" if (first_byte >> 1 & 1) else "Universal (UAA/Hardware)",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

        if not quiet:
            print(f" {COLORS['green']}[✔] MAC:{COLORS['reset']} {COLORS['calypso']}{data['mac']}{COLORS['reset']}")
            print(f"   ├─ {COLORS['blue']}Vendor:{COLORS['reset']}   {data['vendor']}")
            print(f"   ├─ {COLORS['blue']}Anatomy:{COLORS['reset']}  {data['type']} | {data['admin']}")
            print(f"   └─ {COLORS['gray']}---{COLORS['reset']}")
        return data
    except Exception as e:
        if not quiet: print(f" {COLORS['red']}[!] Error en {mac}: Formato inválido.{COLORS['reset']}")
        return None

def save_to_csv(results, filename="mac_audit_log.csv"):
    if not results: return
    keys = results[0].keys()
    file_exists = os.path.isfile(filename)
    with open(filename, 'a', newline='', encoding='utf-8') as f:
        dict_writer = csv.DictWriter(f, fieldnames=keys)
        if not file_exists: dict_writer.writeheader()
        dict_writer.writerows(results)
    print(f"\n{COLORS['yellow']}[*] Auditoría guardada en: {filename}{COLORS['reset']}")

def main():
    if os.name == 'nt': os.system('color')
    print_banner()
    
    db_path = find_db()
    parser = argparse.ArgumentParser(description="Herramienta de Auditoría y Generación de MACs")
    parser.add_argument("-g", "--generate", type=int, help="Generar X cantidad de MACs Stealth")
    parser.add_argument("-a", "--analyze", type=str, help="Analizar una MAC específica")
    parser.add_argument("-f", "--file", type=str, help="Validar lista de MACs desde un archivo")
    parser.add_argument("-o", "--output", action="store_true", help="Guardar resultados en CSV")
    
    args = parser.parse_args()
    results_to_save = []

    if not any(vars(args).values()):
        # Comportamiento por defecto (como el script original pero con 4 opciones)
        args.generate = 4

    if args.generate:
        for _ in range(args.generate):
            # 0xFC asegura que sea Unicast (bit 0 = 0) y UAA/Hardware (bit 1 = 0)
            f_byte = random.randint(0x00, 0xff) & 0xFC
            mac = ":".join([f"{f_byte:02X}"] + [f"{random.randint(0,255):02X}" for _ in range(5)])
            res = analyze_mac(mac, db_path)
            if res: results_to_save.append(res)

    if args.analyze:
        res = analyze_mac(args.analyze, db_path)
        if res: results_to_save.append(res)

    if args.file:
        if os.path.exists(args.file):
            print(f"{COLORS['yellow']}[*] Leyendo archivo: {args.file}{COLORS['reset']}")
            with open(args.file, 'r') as f:
                for line in f:
                    if line.strip():
                        res = analyze_mac(line, db_path)
                        if res: results_to_save.append(res)
        else:
            print(f"{COLORS['red']}[!] Archivo no encontrado.{COLORS['reset']}")

    if args.output and results_to_save:
        save_to_csv(results_to_save)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{COLORS['red']}[!] Abortado por el usuario.{COLORS['reset']}")
        sys.exit(0)