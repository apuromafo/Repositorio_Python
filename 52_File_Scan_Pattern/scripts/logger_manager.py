"""
logger_manager.py - Versión 1.1.1
Gestión de logs, buffers, estadísticas, rotación de logs y manejo robusto.
Mejoras en nombres únicos de archivos para evitar solapamiento.
Separación de archivos hallazgos sensibles e informativos por archivo escaneado.
"""

import time
from pathlib import Path
from typing import Dict, Any
import sys

__version__ = "1.1.1"

ESTADO_LOGGER: Dict[str, Any] = {}

Colores = {
    'ENCABEZADO': '\033[95m',
    'AZUL_OK': '\033[94m',
    'CIAN_OK': '\033[96m',
    'VERDE_OK': '\033[92m',
    'ADVERTENCIA': '\033[93m',
    'FALLO': '\033[91m',
    'RESET': '\033[0m',
    'NEGRITA': '\033[1m'
}

def texto_coloreado(texto: str, color: str) -> str:
    if sys.stdout.isatty():
        return f"{color}{texto}{Colores['RESET']}"
    return texto

def inicializar_logger(configuracion: Dict[str, Any]) -> None:
    global ESTADO_LOGGER
    timestamp = time.strftime("%Y-%m-%d_%H%M%S")
    dir_base = Path("Scan_Reports") / time.strftime("%Y-%m-%d")
    dir_base.mkdir(parents=True, exist_ok=True)

    # Rotación simple: conservar 10 últimas carpetas
    try:
        padre = dir_base.parent
        carpetas = sorted([f for f in padre.iterdir() if f.is_dir()], reverse=True)
        max_carpetas = 10
        if len(carpetas) > max_carpetas:
            for vieja_carpeta in carpetas[max_carpetas:]:
                for archivo in vieja_carpeta.glob("*"):
                    archivo.unlink()
                vieja_carpeta.rmdir()
    except Exception:
        pass

    ESTADO_LOGGER.update({
        'config': configuracion,
        'dir_base': dir_base,
        'archivo_log': dir_base / f"reporte_{timestamp}.txt",
        'archivo_hallazgos': dir_base / f"hallazgos_{timestamp}.txt",
        'archivo_estadisticas': dir_base / f"estadisticas_{timestamp}.txt",
        'dir_hallazgos_por_archivo': dir_base / "Hallazgos",
        'buffer_hallazgos': [],
        'cerrado': False,
        'estadisticas': {
            'archivos_procesados': 0,
            'archivos_omitidos': 0,
            'archivos_binarios': 0,
            'archivos_grandes': 0,
            'lineas_analizadas': 0,
            'hallazgos_sensibles': 0,
            'hallazgos_informativos': 0,
            'errores': 0,
            'inicio': time.time()
        }
    })
    ESTADO_LOGGER['dir_hallazgos_por_archivo'].mkdir(parents=True, exist_ok=True)

def registrar_log(mensaje: str, imprimir_en_consola=True, nivel="INFO") -> None:
    global ESTADO_LOGGER
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    msg_log = f"[{timestamp}] [{nivel}] {mensaje}"
    config = ESTADO_LOGGER.get('config', {})
    try:
        if imprimir_en_consola and config.get('nivel_verbose') in ["INFO", "DEBUG"]:
            print(mensaje)
        with open(ESTADO_LOGGER['archivo_log'], "a", encoding="utf-8") as f:
            f.write(msg_log + "\n")
    except Exception as e:
        print(texto_coloreado(f"ERROR escribiendo log: {e}", Colores['FALLO']))

def actualizar_estadistica(clave: str, valor: int = 1) -> None:
    global ESTADO_LOGGER
    est = ESTADO_LOGGER.get('estadisticas', {})
    est[clave] = est.get(clave, 0) + valor

def vaciar_buffer_hallazgos() -> None:
    global ESTADO_LOGGER
    if not ESTADO_LOGGER['buffer_hallazgos']:
        return
    try:
        with open(ESTADO_LOGGER['archivo_hallazgos'], "a", encoding="utf-8") as f:
            f.write("\n".join(ESTADO_LOGGER['buffer_hallazgos']) + "\n")
        ESTADO_LOGGER['buffer_hallazgos'].clear()
    except Exception as e:
        registrar_log(f"ERROR escribiendo hallazgos: {e}", True, "ERROR")
        actualizar_estadistica('errores')

def agregar_hallazgo_al_buffer(texto: str) -> None:
    global ESTADO_LOGGER
    ESTADO_LOGGER['buffer_hallazgos'].append(texto)
    config = ESTADO_LOGGER.get('config', {})
    if len(ESTADO_LOGGER['buffer_hallazgos']) >= config.get('tamano_buffer', 100):
        vaciar_buffer_hallazgos()

def registrar_hallazgo_por_archivo(nombre_archivo: str, texto: str, tipo: str = "general") -> None:
    global ESTADO_LOGGER
    nombre_sin_extension = Path(nombre_archivo).stem
    timestamp_hora = time.strftime('%Y-%m-%d_%H%M%S')
    archivo_tipo = f"{nombre_sin_extension}_scan_{timestamp_hora}_{tipo}.txt"
    ruta_archivo = ESTADO_LOGGER['dir_hallazgos_por_archivo'] / archivo_tipo
    try:
        with open(ruta_archivo, "a", encoding="utf-8") as f:
            f.write(texto + "\n")
    except Exception as e:
        registrar_log(f"ERROR escribiendo hallazgo individual: {e}", True, "ERROR")
        actualizar_estadistica('errores')

def guardar_estadisticas_finales() -> None:
    global ESTADO_LOGGER
    est = ESTADO_LOGGER.get('estadisticas', {})
    duracion = time.time() - est.get('inicio', time.time())
    try:
        with open(ESTADO_LOGGER['archivo_estadisticas'], "w", encoding="utf-8") as f:
            f.write("="*70 + "\n")
            f.write("📈 ESTADÍSTICAS DEL ESCANEO\n")
            f.write("="*70 + "\n\n")
            f.write(f"Archivos procesados:          {est.get('archivos_procesados', 0)}\n")
            f.write(f"Archivos omitidos:            {est.get('archivos_omitidos', 0)}\n")
            f.write(f"  - Binarios:                 {est.get('archivos_binarios', 0)}\n")
            f.write(f"  - Tamaño excedido:          {est.get('archivos_grandes', 0)}\n")
            f.write(f"Líneas analizadas:            {est.get('lineas_analizadas', 0):,}\n")
            f.write(f"Hallazgos sensibles:          {est.get('hallazgos_sensibles', 0)}\n")
            f.write(f"Hallazgos informativos:       {est.get('hallazgos_informativos', 0)}\n")
            f.write(f"Errores encontrados:          {est.get('errores', 0)}\n")
            f.write(f"Tiempo total:                 {duracion:.2f}s\n")
            f.write("="*70 + "\n")
    except Exception as e:
        registrar_log(f"ERROR guardando estadísticas: {e}", True, "ERROR")

def cerrar_logger() -> None:
    global ESTADO_LOGGER
    if not ESTADO_LOGGER.get('cerrado', True):
        vaciar_buffer_hallazgos()
        guardar_estadisticas_finales()
        registrar_log("Ejecución finalizada con éxito.", True)
        ESTADO_LOGGER['cerrado'] = True
