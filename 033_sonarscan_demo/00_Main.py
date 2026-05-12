# -*- coding: utf-8 -*-
# 00_Main.py
# Versión: 1.0.0 - REFACCIÓN: Centralización Estricta de Strings y Constantes
# Función: Orquestador de procesos con manejo de argumentos e interactividad para el Paso 7.

import sys
import os
import subprocess
import argparse 
from typing import Dict, Any, Optional, List

# ===================================================
# 📌 CONSTANTES DE MENSAJES CENTRALIZADAS
# ===================================================
version= "1.0.0"
fecha="18.11.2025"
# --- SEPARADORES Y CABECERAS ---
TITLE_SEPARATOR = "=================================================="
SUCCESS_SEPARATOR = "====================================================="
MAIN_TITLE = "       INICIO DEL ORQUESTADOR SONARQUBE         "

# --- MENSAJES DE ESTADO Y PROMPT ---
PROMPT_CHOICE = "Seleccione una opción ({min}-{max}): "
EXIT_MESSAGE = "\n[👋] Saliendo del Orquestador SonarQube. ¡Hasta pronto!"
SUCCESS_FULL_SEQUENCE = "    [✔] SECUENCIA COMPLETA EJECUTADA CON ÉXITO.      "
INFO_EXECUTING_STEP = "\n---> EJECUTANDO {step_number}. {description} ({file_name}) <---"
INFO_REPORT_ARGS = "\n[i] El Paso 7 (Reporte) requiere argumentos. ¿Desea proporcionarlos ahora?"
PROMPT_REPORT_ARGS = "¿Ingresar argumentos para el Paso 7? (s/n): "

# --- MENSAJES DE ERROR ---
ERROR_INVALID_INPUT = "[❗] Entrada no válida. Por favor, ingrese un número."
ERROR_NOT_DEFINED = "[❌] Opción {choice} no válida o no definida."
ERROR_OUT_OF_RANGE = "[❗] Opción {choice} fuera del rango permitido ({min}-{max})."
ERROR_STEP_NOT_DEFINED = "[❌] Error: El paso {step_number} no está definido."
ERROR_STEP_EXECUTION = "[❌] Error durante la ejecución del paso {step_number} ({file_name}): {error}"
ERROR_SEQUENCE_INTERRUPTED = "[❌] Secuencia interrumpida: Falló el Paso {step_number}."


# --- 1. Definición de Pasos (Usa constantes para las descripciones) ---
_available_steps = {
    1: {'file': '01_config.ini.py', 'description': 'Sincronización y Configuración'},
    2: {'file': '02_validate_env.py', 'description': 'Validación de Entorno (PATH)'},
    3: {'file': '03_download_scanner.py', 'description': 'Descarga de SonarScanner'},
    4: {'file': '04_validate_sonarscan.py', 'description': 'Verificación de Scanner y API'},
    5: {'file': '05_download_cnes_report.py', 'description': 'Descarga/Validación CNES Report JAR'},
    6: {'file': '06_genera_nombre_env_v1.3.6.py', 'description': 'Generar Clave de Proyecto/Reporte'}, 
    7: {'file': '07_reporte.py', 'description': 'Generación de Reporte (Acepta -p, -o, -r)'}, 
}

# La opción 8 es la secuencia completa (MAX_STEP + 1)
MAX_STEP = len(_available_steps)
FULL_SEQUENCE_STEP = MAX_STEP + 1

# ===================================================
# --- 2. Funciones de Ayuda (run_script, display_menu, etc.) ---
# ===================================================

def run_script(file_name: str, args: Optional[List[str]] = None) -> bool:
    """
    Ejecuta un script Python en un proceso separado usando subprocess.run().
    
    Retorna True si el script termina con éxito (código de retorno 0), 
    False en caso contrario.
    """
    command = [sys.executable, file_name]
    if args:
        command.extend(args)
        
    try:
        result = subprocess.run(
            command, 
            check=False, # No lanza excepción si el código de retorno no es 0
            capture_output=False # Permite la salida directa para interactividad
        )
        return result.returncode == 0
    except FileNotFoundError:
        print(f"[❌] Error: El archivo '{file_name}' no se encontró. Revise la ruta.", file=sys.stderr)
        return False
    except Exception as e:
        print(f"[❌] Error desconocido al ejecutar el script '{file_name}': {e}", file=sys.stderr)
        return False


def display_menu():
    """Muestra el menú de opciones al usuario."""
    print(TITLE_SEPARATOR)
    print(" [0] Salir")
    
    # Mostrar pasos individuales
    for step_number, data in _available_steps.items():
        print(f" [{step_number}] {data['description']}")
    
    # Opción de secuencia completa
    print(f" [{FULL_SEQUENCE_STEP}] Ejecutar Secuencia Completa (1 -> {MAX_STEP})")
    print(TITLE_SEPARATOR)


def execute_step(step_number: int, args: Optional[List[str]] = None) -> bool:
    """Ejecuta un paso modular específico dentro de la secuencia."""
    data = _available_steps.get(step_number)
    
    if not data:
        # Usa la constante de error
        print(ERROR_STEP_NOT_DEFINED.format(step_number=step_number), file=sys.stderr)
        return False
        
    # Usa la constante con formato para el log
    print(INFO_EXECUTING_STEP.format(
        step_number=step_number, 
        description=data['description'], 
        file_name=data['file']
    ))
    
    return run_script(data['file'], args)


def execute_full_sequence(report_args: Optional[List[str]] = None) -> bool:
    """Ejecuta la secuencia completa de pasos, de 1 a MAX_STEP."""
    
    # Usa la constante para la cabecera
    print(f"\n{TITLE_SEPARATOR}")
    print(f"     INICIO DE LA SECUENCIA COMPLETA (1 -> {MAX_STEP})    ")
    print(f"{TITLE_SEPARATOR}")
    
    for step_number in range(1, FULL_SEQUENCE_STEP):
        current_args = None
        
        # Lógica especial para el Paso 7 (Generación de Reporte)
        if step_number == 7 and report_args:
            current_args = report_args
            
        if not execute_step(step_number, current_args):
            # Usa la constante de error
            print(ERROR_SEQUENCE_INTERRUPTED.format(step_number=step_number), file=sys.stderr)
            return False

    # Usa las constantes para el mensaje final
    print(f"\n{SUCCESS_SEPARATOR}")
    print(SUCCESS_FULL_SEQUENCE)
    print(SUCCESS_SEPARATOR)
    return True

def _prompt_for_report_args() -> List[str]:
    """Solicita argumentos adicionales para el script de reporte."""
    print("Ejemplo: -p PROYECTO-KEY -o output_dir -r")
    raw_args = input("Ingrese argumentos (o Enter para omitir): ").strip()
    return raw_args.split() if raw_args else []

# ===================================================
# --- 3. Función Principal (main) ---
# ===================================================

def main():
    """Función principal que implementa el menú interactivo."""
    
    # Capturar argumentos iniciales (útil para el Paso 7/Secuencia Completa)
    parser = argparse.ArgumentParser(description="Orquestador de procesos SonarQube.")
    # Permite pasar argumentos que luego se inyectan en el Paso 7
    parser.add_argument('report_args', nargs=argparse.REMAINDER, help="Argumentos para el Paso 7 (Reporte).")
    args = parser.parse_args()
    # Los argumentos para el reporte (si se pasaron por CLI)
    report_args = args.report_args 

    # Usa las constantes para la cabecera
    print(TITLE_SEPARATOR)
    print(MAIN_TITLE)
    # AÑADIR VERSIÓN Y FECHA
    print(f"     Versión: {version} - Fecha: {fecha}")     
    print(TITLE_SEPARATOR)

    while True:
        display_menu()
        
        try:
            # Usa la constante con formato para el prompt
            choice = input(PROMPT_CHOICE.format(min=0, max=FULL_SEQUENCE_STEP)).strip()
            if not choice:
                continue
            choice = int(choice)
        except ValueError:
            # Usa la constante de error de input
            print(ERROR_INVALID_INPUT)
            continue
            
        if choice == 0:
            # Usa la constante de salida
            print(EXIT_MESSAGE)
            sys.exit(0)
            
        elif choice == FULL_SEQUENCE_STEP:
            execute_full_sequence(report_args)
            
        elif 1 <= choice <= MAX_STEP:
            data = _available_steps.get(choice)
            
            if data:
                current_args = report_args
                
                if choice == 6:
                    # Paso 6: Generador de Nombre (Interactivo, no usa report_args)
                    run_script(data['file'])
                    
                elif choice == 7:
                    # Paso 7: Generación de Reporte (Usa la lógica de inyección y prompt)
                    if not report_args:
                        print(INFO_REPORT_ARGS) # Usa la constante de info
                        if input(PROMPT_REPORT_ARGS).strip().lower() == 's': # Usa la constante de prompt
                            current_args = _prompt_for_report_args()
                            
                    run_script(data['file'], current_args)
                else:
                    # Otros pasos (1, 2, 3, 4, 5)
                    run_script(data['file']) 
            else:
                # Usa la constante de opción no definida
                print(ERROR_NOT_DEFINED.format(choice=choice))
                
        else:
            # Usa la constante de fuera de rango
            print(ERROR_OUT_OF_RANGE.format(choice=choice, min=0, max=FULL_SEQUENCE_STEP))


if __name__ == "__main__":
    # La importación de sys ya está arriba, pero la dejamos para consistencia si se usa esta línea
    # en scripts modulares.
    
    # Hemos corregido los mensajes en el bloque de excepciones para usar UTF-8 correctamente.
    
    try:
        main() 
        sys.exit(0) 
    except KeyboardInterrupt:
        # Captura de interrupcion (Ctrl+C)
        print(EXIT_MESSAGE) # Usamos la constante centralizada
        sys.exit(0) # Salida limpia
    except Exception as e:
        # Captura de cualquier otro error critico no previsto
        print(f"\n[❓] Error crítico en el Orquestador (00_Main.py): {e}", file=sys.stderr)
        sys.exit(1)