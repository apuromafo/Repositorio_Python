#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# main.py
#
# Lanzador central (Orquestador) de la Jasper CLI Suite.
# Proporciona una interfaz interactiva para acceder a los módulos de:
# Análisis, Conversión, Compilación y Descompilación de reportes Jasper.
#
# Uso:
# python main.py
# ==============================================================================
# --- HISTORIAL DE VERSIONES ---
# ==============================================================================
# v2.0.0 (2026-05-20) - [INTEGRACIÓN TOTAL]
#   ✅ Estandarización de nombres de módulos (analizar.py, compilar.py, etc.).
#   ✅ Optimización de flujo de ejecución mediante subprocesos con codificación UTF-8.
#
# v1.0.0 (2025-09-15) - [LANZAMIENTO]
#   ✅ Interfaz interactiva básica para la suite de herramientas.
# ==============================================================================
import subprocess
import sys
import os
import time

# Forzar codificación UTF-8 para evitar errores de caracteres especiales (emojis)
if sys.platform == 'win32':
    os.system('chcp 65001 > NUL')
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')

# Configuración de la Suite
SUITE = {
    "1": {"name": "Analizar (Auditoría)", "file": "analizar.py"},
    "2": {"name": "Convertir (.jasper -> PDF)", "file": "convertir.py"},
    "3": {"name": "Compilar (.jrxml -> .jasper)", "file": "compilar.py"},
    "4": {"name": "Descompilar (.jasper -> .jrxml)", "file": "decompilar_v3.py"}
}

def ejecutar_modulo(choice):
    script = SUITE[choice]["file"]
    print(f"\n[+] Lanzando: {SUITE[choice]['name']}")
    
    # Captura de datos
    modo = input("¿Modo (a)rchivo o (f)carpeta?: ").strip().lower()
    ruta = os.path.abspath(input("Ruta completa: "))
    
    args = [sys.executable, script]
    if modo == 'a': 
        args.extend(["-a", ruta])
    elif modo == 'f': 
        args.extend(["-f", ruta])
    else:
        print("[-] Modo no válido.")
        return

    # Si es Compilar o Descompilar, pedimos destino y lo creamos
    if choice in ["3", "4"]:
        out = os.path.abspath(input("Carpeta de destino: "))
        os.makedirs(out, exist_ok=True)
        args.extend(["-o", out])

    # Ejecución con manejo de errores
    try:
        # Se redirige la salida al terminal actual
        # al usar 'text=True' y la reconfiguración UTF-8, no debería dar UnicodeError
        subprocess.run(args, check=True)
        print(f"[+] Finalizado con éxito.")
    except subprocess.CalledProcessError:
        print(f"[-] El script {script} terminó con errores.")
    except Exception as e:
        print(f"[-] Error fatal: {e}")

def main():
    while True:
        print("\n=== JASPER SUITE v2.0 ===")
        for k, v in SUITE.items():
            print(f"{k}. {v['name']}")
        print("5. Salir")
        
        c = input("Seleccione: ").strip()
        if c == "5": break
        if c in SUITE:
            ejecutar_modulo(c)
        else:
            print("[-] Opción no válida.")

if __name__ == "__main__":
    main()