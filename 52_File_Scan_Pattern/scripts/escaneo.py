"""
escaneo.py - Versión 1.3.6
Escaneo sin multitarea.
Mejoras: manejo de duplicados y validación 'id' en patrones.
"""

import time
from pathlib import Path
from typing import Dict, List, Any
from .logger_manager import registrar_log, actualizar_estadistica, registrar_hallazgo_por_archivo, vaciar_buffer_hallazgos, Colores, texto_coloreado

from .utilidades import mostrar_recomendaciones_binario, formatear_texto_hallazgo, imprimir_hallazgo
from .metadatos import obtener_metadatos_archivo

__version__ = "1.3.6"

def es_archivo_binario(ruta_archivo: Path, umbral: float) -> bool:
    try:
        with open(ruta_archivo, 'rb') as f:
            bloque = f.read(8192)
            if not bloque:
                return False
            count_nulos = bloque.count(b'\x00')
            return (count_nulos / len(bloque)) > umbral
    except Exception:
        return False

def escanear_archivo(
    ruta_archivo: Path,
    configuracion: Dict,
    patrones_sensibles: List[Dict],
    patrones_informativos: List[Dict],
    opciones: Dict[str, bool],
    sugerencias: Dict,
) -> Dict[str, Any]:
    registrar_log(f"Procesando: {ruta_archivo}", False)

    try:
        if ruta_archivo.suffix.lower() in configuracion.get('scan_config', {}).get('extensiones_excluidas', []):
            registrar_log(f"Omitido (extensión excluida): {ruta_archivo}", False)
            actualizar_estadistica('archivos_omitidos')
            return {"archivo": str(ruta_archivo), "sensibles": 0, "informativos": 0, "tiempo": 0, "omitido": True, "metadatos": {}}

        size_mb = ruta_archivo.stat().st_size / (1024*1024)
        if size_mb > configuracion.get('scan_config', {}).get('tamano_maximo_mb', 1500):
            print(texto_coloreado(f"⚠️ Archivo demasiado grande ({size_mb:.1f}MB): {ruta_archivo.name}", Colores['ADVERTENCIA']))
            actualizar_estadistica('archivos_grandes')
            actualizar_estadistica('archivos_omitidos')
            return {"archivo": str(ruta_archivo), "sensibles": 0, "informativos": 0, "tiempo": 0, "omitido": True, "metadatos": {}}

        if es_archivo_binario(ruta_archivo, configuracion.get('scan_config', {}).get('umbral_deteccion_binaria', 0.05)):
            mostrar_recomendaciones_binario(ruta_archivo, sugerencias)
            actualizar_estadistica('archivos_binarios')
            actualizar_estadistica('archivos_omitidos')
            return {"archivo": str(ruta_archivo), "sensibles": 0, "informativos": 0, "tiempo": 0, "omitido": True, "metadatos": {}}
    except Exception as e:
        registrar_log(f"ERROR verificando archivo {ruta_archivo}: {e}", True, "ERROR")
        actualizar_estadistica('errores')
        return {"archivo": str(ruta_archivo), "sensibles": 0, "informativos": 0, "tiempo": 0, "omitido": True, "metadatos": {}}

    metadatos = obtener_metadatos_archivo(ruta_archivo, sugerencias)

    print(texto_coloreado(f"\n🔎 Escaneando: {ruta_archivo}", Colores['AZUL_OK']))

    hallazgos = []
    hallazgos_vistos = set()
    tiempo_inicio = time.time()

    try:
        with open(ruta_archivo, 'r', encoding='utf-8', errors='replace') as archivo:
            for num_linea, linea in enumerate(archivo, 1):
                actualizar_estadistica('lineas_analizadas')
                contenido = linea.strip()

                if opciones.get('sensibles', True):
                    for patron in patrones_sensibles:
                        regla_id = patron.get('id')
                        if regla_id is None:
                            registrar_log(f"ADVERTENCIA: Patrón sin 'id' detectado y saltado: {patron}", True)
                            continue
                        if patron['regex'].search(linea):
                            clave = f"{regla_id}|{num_linea}|{contenido[:30]}"
                            if clave not in hallazgos_vistos:
                                hallazgos_vistos.add(clave)
                                hallazgos.append(
                                    {**patron, 'lineanum': num_linea, 'lineacontenido': contenido, 'es_sensible': True}
                                )
                                actualizar_estadistica('hallazgos_sensibles')

                if opciones.get('informativos', False):
                    for patron in patrones_informativos:
                        regla_id = patron.get('id')
                        if regla_id is None:
                            registrar_log(f"ADVERTENCIA: Patrón sin 'id' detectado y saltado: {patron}", True)
                            continue
                        clave = f"{regla_id}|{num_linea}|{contenido[:30]}"
                        if clave not in hallazgos_vistos and patron['regex'].search(linea):
                            hallazgos_vistos.add(clave)
                            hallazgos.append(
                                {**patron, 'lineanum': num_linea, 'lineacontenido': contenido, 'es_sensible': False}
                            )
                            actualizar_estadistica('hallazgos_informativos')
    except Exception as e:
        mensaje_error = f"ERROR escaneando {ruta_archivo}: {e}"
        print(texto_coloreado(mensaje_error, Colores['FALLO']))
        registrar_log(mensaje_error, False, 'ERROR')
        actualizar_estadistica('errores')

    duracion = time.time() - tiempo_inicio
    actualizar_estadistica('archivos_procesados')

    sensibles = [h for h in hallazgos if h.get('es_sensible', False)] if hallazgos else []
    informativos = [h for h in hallazgos if not h.get('es_sensible', False)] if hallazgos else []
    sensibles.sort(key=lambda h: h.get('lineanum', 0))
    informativos.sort(key=lambda h: h.get('lineanum', 0))

    numero_hallazgo = 1
    if sensibles:
        print(texto_coloreado('\n===== HALLAZGOS SENSIBLES =====', Colores['FALLO']))
        for hall in sensibles:
            imprimir_hallazgo(hall, numero_hallazgo)
            registrar_hallazgo_por_archivo(ruta_archivo.name, formatear_texto_hallazgo(hall, numero_hallazgo), tipo='sensibles')
            numero_hallazgo += 1

    if informativos:
        print(texto_coloreado('\n===== HALLAZGOS INFORMATIVOS =====', Colores['AZUL_OK']))
        for hall in informativos:
            imprimir_hallazgo(hall, numero_hallazgo)
            registrar_hallazgo_por_archivo(ruta_archivo.name, formatear_texto_hallazgo(hall, numero_hallazgo), tipo='informativos')
            numero_hallazgo += 1

    print(texto_coloreado(f'\n✅ Escaneo completado en {duracion:.2f} segundos\n', Colores['VERDE_OK']))
    vaciar_buffer_hallazgos()

    return {
        'archivo': str(ruta_archivo),
        'sensibles': len(sensibles),
        'informativos': len(informativos),
        'tiempo': duracion,
        'omitido': False,
        'metadatos': metadatos,
    }

def escanear_carpeta(
    ruta_carpeta: Path,
    configuracion: Dict,
    patrones_sensibles: List[Dict],
    patrones_informativos: List[Dict],
    opciones: Dict[str, bool],
    sugerencias: Dict,
) -> List[Dict[str, Any]]:
    print(texto_coloreado(f'\n📁 Escaneando carpeta recursiva: {ruta_carpeta}\n', Colores['AZUL_OK']))
    archivos = sorted(ruta_carpeta.rglob('*'))
    archivos = [f for f in archivos if f.is_file()]
    total_archivos = len(archivos)

    if total_archivos == 0:
        print(texto_coloreado('No se encontraron archivos.', Colores['ADVERTENCIA']))
        return []

    print(texto_coloreado(f'Archivos encontrados: {total_archivos}', Colores['CIAN_OK']))
    resumenes = []

    for indice, archivo in enumerate(archivos, 1):
        if configuracion.get('salida', {}).get('mostrar_progreso', True):
            print(texto_coloreado(f'\n[{indice}/{total_archivos}] Procesando: {archivo}', Colores['CIAN_OK']))
        resumen = escanear_archivo(archivo, configuracion, patrones_sensibles, patrones_informativos, opciones, sugerencias)
        resumenes.append(resumen)

    return resumenes

def imprimir_resumen_tabla(resumenes: List[Dict[str, Any]]) -> None:
    from .logger_manager import ESTADO_LOGGER
    estadisticas = ESTADO_LOGGER.get('estadisticas', {})
    print(texto_coloreado('\n' + '=' * 90, Colores['NEGRITA']))
    print(texto_coloreado('📊 TABLA RESUMEN CONSOLIDADO DE HALLAZGOS', Colores['NEGRITA']))
    print(texto_coloreado('=' * 90, Colores['NEGRITA']))
    print(f"{'ARCHIVO':<60} {'SENSIBLES':>8} {'INFORMATIVOS':>12} {'TIEMPO(s)':>12}")
    print('-' * 90)

    total_sensibles = 0
    total_informativos = 0
    total_tiempo = 0.0

    for item in resumenes:
        if not item.get('omitido', False):
            print(f"{item['archivo']:<60} {item['sensibles']:>8} {item['informativos']:>12} {item['tiempo']:>12.2f}")
            total_sensibles += item['sensibles']
            total_informativos += item['informativos']
            total_tiempo += item['tiempo']

    print('-' * 90)
    print(f"{'TOTALES':<60} {total_sensibles:>8} {total_informativos:>12} {total_tiempo:>12.2f}")
    print('-' * 90)

    print(texto_coloreado('\n📈 ESTADÍSTICAS DEL ESCANEO', Colores['NEGRITA']))
    print('-' * 90)
    print(f"Archivos procesados:      {estadisticas.get('archivos_procesados', 0)}")
    print(f"Archivos omitidos:        {estadisticas.get('archivos_omitidos', 0)}")
    print(f"  - Binarios:             {estadisticas.get('archivos_binarios', 0)}")
    print(f"  - Tamaño excedido:      {estadisticas.get('archivos_grandes', 0)}")
    print(f"Líneas analizadas:        {estadisticas.get('lineas_analizadas', 0):,}")
    print(f"Errores encontrados:      {estadisticas.get('errores', 0)}")
    print('-' * 90 + '\n')

# Nota de prudencia:
# Ejecuta escaneos solo con permisos y en ambientes autorizados. Respeta confidencialidad y respaldos.
