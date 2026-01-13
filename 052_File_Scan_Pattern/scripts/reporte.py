import sys
import signal
from pathlib import Path

from .configuracion import load_config_from_file
from .logger_manager import setup_logger, log, cerrar_logger, LOGGER_STATE, color_text, Colors
from .patrones import load_all_patterns, PATTERNS_STATE
from .escaneo import escanear_archivo, escanear_carpeta, imprimir_tabla_resumen
from .utilidades import cargar_sugerencias

def signal_handler(sig, frame):
    print(color_text("\n⚠️ Interrupción detectada (Ctrl+C). Saliendo limpiamente...", Colors['WARNING']))
    cerrar_logger()
    sys.exit(0)

def main():
    signal.signal(signal.SIGINT, signal_handler)
    print(color_text(f"🛡️ Escáner de Patrones - Versión 1.2\n", Colors['HEADER']))
    config_path = Path("./Pattern/config.json")
    config = load_config_from_file(str(config_path))
    setup_logger(config)
    log("Escáner v1.2 iniciado", True)
    pattern_dir = Path("./Pattern")
    if not load_all_patterns(str(pattern_dir), config):
        print(color_text("ERROR: No se pudieron cargar patrones. Saliendo.", Colors['FAIL']))
        sys.exit(1)
    suggestions_path = Path("./Pattern/suggestions.json")
    suggestions = cargar_sugerencias(str(suggestions_path)) if suggestions_path.exists() else {}
    resumen_sesion = []
    while True:
        opcion = input(color_text("\n¿Escanear (A)rchivo, (F)older, o (S)alir?: ", Colors['OKCYAN'])).strip().lower()
        if opcion not in ("a", "f", "s"):
            print(color_text("Opción inválida.", Colors['WARNING']))
            continue
        if opcion == "s":
            print(color_text("Saliendo. Gracias por usar el escáner.", Colors['OKGREEN']))
            break
        rpt_in = input(color_text(
            "Opciones (S=Solo Sensible, I=Solo Informativo, ALL=Ambos) [ALL]: ",
            Colors['OKBLUE'])).strip().lower()
        opciones = {
            "sensibles": rpt_in in ("s", "all", ""),
            "informativos": rpt_in in ("i", "all", "")
        }
        patrones_sensibles = PATTERNS_STATE['sensibles']
        patrones_informativos = PATTERNS_STATE['informativos']
        if opcion == "a":
            ruta = input("Ruta del archivo: ").strip()
            if not Path(ruta).is_file():
                print(color_text("Archivo no encontrado.", Colors['FAIL']))
                continue
            resumen = escanear_archivo(Path(ruta), config, patrones_sensibles, patrones_informativos, opciones, suggestions)
            resumen_sesion.append(resumen)
            imprimir_tabla_resumen(resumen_sesion)
        elif opcion == "f":
            ruta = input("Ruta de la carpeta: ").strip()
            if not Path(ruta).is_dir():
                print(color_text("Carpeta no encontrada.", Colors['FAIL']))
                continue
            resumenes = escanear_carpeta(Path(ruta), config, patrones_sensibles, patrones_informativos, opciones, suggestions)
            resumen_sesion.extend(resumenes)
            imprimir_tabla_resumen(resumen_sesion)
        print(color_text(f"\n📄 Logs guardados en: {LOGGER_STATE.get('base_dir', Path('Scan_Reports')).resolve()}", Colors['OKCYAN']))
    cerrar_logger()

if __name__ == "__main__":
    main()
