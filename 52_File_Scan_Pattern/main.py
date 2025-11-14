"""
main.py - 
Versión 1.2.7
Se añade patrón para archivo dsx, y se mejora visualización de snippet
Versión 1.2.6
Bucle principal interactivo con impresión avanzada de metadatos incluyendo hash SHA256 completo.
Scripts están en /scripts/
"""

import sys
import signal
from pathlib import Path

from scripts.configuracion import cargar_configuracion_desde_archivo, obtener_configuracion_por_defecto
from scripts.logger_manager import inicializar_logger, registrar_log, cerrar_logger, ESTADO_LOGGER, texto_coloreado, Colores
from scripts.patrones import cargar_todos_los_patrones, ESTADO_PATRONES
from scripts.escaneo import escanear_archivo, escanear_carpeta, imprimir_resumen_tabla
from scripts.utilidades import cargar_sugerencias

__version__ = "1.2.7"

def manejador_senal(sig, frame):
    print(texto_coloreado("\n⚠️ Interrupción detectada (Ctrl+C). Saliendo limpiamente...", Colores['ADVERTENCIA']))
    cerrar_logger()
    sys.exit(0)

def imprimir_metadatos_formateados(metadatos: dict, nombre_archivo: str):
    print(texto_coloreado(f"\n📄 Metadatos resumidos de {nombre_archivo}:", Colores['NEGRITA']))
    print(f"- Tamaño: {metadatos.get('tamano_humano', 'N/A')}")
    lineas = metadatos.get('lineas')
    if lineas is not None and lineas != "N/A":
        print(f"- Líneas: {lineas}")
    else:
        print("- Líneas: N/A")
    print(f"- Tipo MIME: {metadatos.get('tipo_mime', 'N/A')}")
    permisos = metadatos.get('permisos_simbolicos')
    modo_num = metadatos.get('modo_numero')
    if permisos and modo_num is not None:
        print(f"- Permisos: {permisos} ({modo_num:04o})")
    elif permisos:
        print(f"- Permisos: {permisos}")
    else:
        print("- Permisos: N/A")
    fecha = metadatos.get('fecha_modificacion')
    if fecha:
        print(f"- Última Modificación: {fecha}")
    duracion = metadatos.get('duracion_segundos')
    if duracion:
        print(f"- Duración (segundos): {duracion:.2f}")
    resolucion = metadatos.get('resolucion')
    if resolucion:
        print(f"- Resolución (WxH): {resolucion[0]}x{resolucion[1]}")
    hash_full = metadatos.get('hash_sha256')
    if hash_full:
        print(f"- SHA256: {hash_full}")
    recomendacion = metadatos.get('recomendacion')
    if recomendacion:
        print("- Recomendaciones:")
        for item in recomendacion:
            print(f"  • {item}")
    print()

def main():
    signal.signal(signal.SIGINT, manejador_senal)

    print(texto_coloreado(f"🛡️ Escáner de Patrones - Versión {__version__}\n", Colores['ENCABEZADO']))

    ruta_config = Path("./Pattern/config.json")
    if ruta_config.exists():
        config = cargar_configuracion_desde_archivo(str(ruta_config))
    else:
        print(texto_coloreado("⚠️ No se encontró archivo de configuración. Usando valores por defecto.", Colores['ADVERTENCIA']))
        config = obtener_configuracion_por_defecto()

    inicializar_logger(config)
    registrar_log(f"Escáner versión {__version__} iniciado", True)

    directorio_patrones = Path(config.get('rutas', {}).get('directorio_patrones', "./Pattern"))
    if not cargar_todos_los_patrones(str(directorio_patrones), config):
        print(texto_coloreado("ERROR: No se pudieron cargar los patrones. Terminando ejecución.", Colores['FALLO']))
        cerrar_logger()
        sys.exit(1)

    archivo_sugerencias = Path(config.get('rutas', {}).get('archivo_sugerencias', "./Pattern/suggestions.json"))
    sugerencias = cargar_sugerencias(str(archivo_sugerencias)) if archivo_sugerencias.exists() else {}

    resumen_general = []

    try:
        while True:
            opcion = input(texto_coloreado("\n¿Escanear (A)rchivo, (C)arpeta o (S)alir?: ", Colores['CIAN_OK'])).strip().lower()

            if opcion not in ("a", "c", "s"):
                print(texto_coloreado("Opción inválida, intente de nuevo.", Colores['ADVERTENCIA']))
                continue

            if opcion == "s":
                print(texto_coloreado("Saliendo. Gracias por usar el escáner.", Colores['VERDE_OK']))
                break

            modo_reportes = input(texto_coloreado("Opciones (S=Solo Sensible, I=Solo Informativo, T=Todos) [T]: ", Colores['AZUL_OK'])).strip().lower()
            opciones = {
                "sensibles": modo_reportes in ("s", "t", ""),
                "informativos": modo_reportes in ("i", "t", "")
            }

            patrones_sensibles = ESTADO_PATRONES['sensibles']
            patrones_informativos = ESTADO_PATRONES['informativos']

            if opcion == "a":
                ruta_archivo = input("Ruta del archivo: ").strip()
                p_archivo = Path(ruta_archivo)
                if not p_archivo.is_file():
                    print(texto_coloreado("Archivo no encontrado.", Colores['FALLO']))
                    continue
                resumen = escanear_archivo(p_archivo, config, patrones_sensibles, patrones_informativos, opciones, sugerencias)
                resumen_general.append(resumen)
                imprimir_metadatos_formateados(resumen.get("metadatos", {}), resumen["archivo"])
                imprimir_resumen_tabla(resumen_general)

            elif opcion == "c":
                ruta_carpeta = input("Ruta de la carpeta: ").strip()
                p_carpeta = Path(ruta_carpeta)
                if not p_carpeta.is_dir():
                    print(texto_coloreado("Carpeta no encontrada.", Colores['FALLO']))
                    continue
                resumenes = escanear_carpeta(p_carpeta, config, patrones_sensibles, patrones_informativos, opciones, sugerencias)
                resumen_general.extend(resumenes)
                for res in resumenes:
                    imprimir_metadatos_formateados(res.get("metadatos", {}), res["archivo"])
                imprimir_resumen_tabla(resumen_general)

            print(texto_coloreado(f"\n📄 Logs guardados en: {ESTADO_LOGGER.get('dir_base', Path('Scan_Reports')).resolve()}", Colores['CIAN_OK']))

    except KeyboardInterrupt:
        print(texto_coloreado("\n⚠️ Interrupción por teclado detectada. Cerrando...", Colores['ADVERTENCIA']))
    finally:
        cerrar_logger()

if __name__ == "__main__":
    main()
