#!/usr/bin/env python3
"""
Conversor SRT / WEBVTT → TXT
Configuración interna: elige el patrón por defecto editando el script.
CLI: -a archivo|carpeta, -f carpeta, -o salida, -p patron (sobrescribe config), --sobrescribir
"""

import re
import argparse
from pathlib import Path
from datetime import datetime


# === 🔧 CONFIGURACIÓN INTERNA (edita aquí para cambiar el comportamiento por defecto) ===
#
# Descomenta UNA línea para definir el patrón predeterminado.
# Usa:
#   {nombre} → nombre original del archivo (sin extensión)
#   {fecha}  → fecha actual: YYYYMMDD
#   {hora}   → hora actual: HHMMSS
#
#CONFIG_PATRON = "{nombre}_limpio"           # Ej: video_limpio.txt
# CONFIG_PATRON = "{nombre}_{fecha}"         # Ej: video_20250405.txt
# CONFIG_PATRON = "sub_{nombre}"             # Ej: sub_video.txt
CONFIG_PATRON = "{nombre}_{fecha}_{hora}"  # Ej: video_20250405_142300.txt
# CONFIG_PATRON = "ES_{nombre}_final"        # Ej: ES_video_final.txt
#
# === FIN DE LA CONFIGURACIÓN ===


def detectar_formato(contenido):
    """Detecta si es WEBVTT o SRT."""
    if contenido.strip().startswith('WEBVTT'):
        return 'webvtt'
    if re.search(r'^\d+\s*\n\d{2}:\d{2}:\d{2},\d{3}', contenido, re.MULTILINE):
        return 'srt'
    return 'srt'


def limpiar_srt(contenido):
    contenido = re.sub(
        r'\d+\s*\n\d{2}:\d{2}:\d{2},\d{3}\s*-->\s*\d{2}:\d{2}:\d{2},\d{3}.*\n?',
        '', contenido, flags=re.IGNORECASE
    )
    return contenido


def limpiar_webvtt(contenido):
    contenido = re.sub(r'^WEBVTT.*\n?', '', contenido, count=1, flags=re.IGNORECASE)
    contenido = re.sub(r'^\s*NOTE.*\n?', '', contenido, flags=re.IGNORECASE | re.MULTILINE)
    contenido = re.sub(
        r'\d{1,2}:\d{2}:\d{2}\.\d+\s*-->\s*\d{1,2}:\d{2}:\d{2}\.\d+.*\n?',
        '', contenido, flags=re.MULTILINE | re.IGNORECASE
    )
    return contenido


def limpiar_subtitulo(contenido):
    formato = detectar_formato(contenido)
    if formato == 'webvtt':
        contenido = limpiar_webvtt(contenido)
    else:
        contenido = limpiar_srt(contenido)
    contenido = re.sub(r'\n{3,}', '\n\n', contenido)
    return contenido.strip()


def generar_nombre_salida(nombre_base, patron):
    """
    Genera el nombre de salida reemplazando marcadores.
    """
    fecha = datetime.now().strftime("%Y%m%d")
    hora = datetime.now().strftime("%H%M%S")
    nombre_final = (
        patron
        .replace('{nombre}', nombre_base)
        .replace('{fecha}', fecha)
        .replace('{hora}', hora)
    )
    return f"{nombre_final}.txt"


def procesar_archivo(ruta_archivo, carpeta_salida, patron_salida, sobrescribir):
    try:
        with ruta_archivo.open('r', encoding='utf-8') as f:
            contenido = f.read()
    except Exception as e:
        print(f"❌ [Lectura] {ruta_archivo.name}: {e}")
        return False

    contenido_limpio = limpiar_subtitulo(contenido)
    nombre_base = ruta_archivo.stem
    nombre_salida = generar_nombre_salida(nombre_base, patron_salida)
    ruta_salida = Path(carpeta_salida) / nombre_salida

    if ruta_salida.exists() and not sobrescribir:
        print(f"❌ Existente: {nombre_salida} (usa --sobrescribir)")
        return False

    try:
        ruta_salida.parent.mkdir(parents=True, exist_ok=True)
        with ruta_salida.open('w', encoding='utf-8') as f:
            f.write(contenido_limpio)
        print(f"✅ {ruta_archivo.name} → {nombre_salida}")
        return True
    except Exception as e:
        print(f"❌ [Escritura] {ruta_salida}: {e}")
        return False


def convertir_entrada(ruta_entrada, carpeta_salida, patron_salida, sobrescribir):
    ruta = Path(ruta_entrada)

    if not ruta.exists():
        print(f"❌ No existe: {ruta}")
        return False

    if ruta.is_file():
        if ruta.suffix.lower() not in ['.srt', '.vtt', '.webvtt']:
            print(f"❌ Formato no soportado: {ruta.suffix} ({ruta.name})")
            return False
        procesar_archivo(ruta, carpeta_salida, patron_salida, sobrescribir)
        return True

    elif ruta.is_dir():
        archivos = []
        for ext in ['*.srt', '*.vtt', '*.webvtt']:
            archivos.extend(ruta.glob(ext))
        archivos = sorted(set(archivos))

        if not archivos:
            print(f"⚠️ No hay archivos .srt o .vtt en: {ruta}")
            return False

        exitosos = 0
        for arch in archivos:
            if procesar_archivo(arch, carpeta_salida, patron_salida, sobrescribir):
                exitosos += 1
        print(f"\n🎉 {exitosos}/{len(archivos)} archivos procesados.")
        return exitosos > 0

    else:
        print(f"❌ Tipo no soportado: {ruta}")
        return False


# --- CLI ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="""
Convierte .srt y .webvtt a .txt limpio.
El patrón de nombre se define en el script (CONFIG_PATRON) o se pasa con -p.
        """,
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Ejemplos:
  python srt_txt.py -a video.srt -o ./txt
  python srt_txt.py -f ./subt/ -o ./out -p {nombre}_es --sobrescribir
        """
    )

    grupo_entrada = parser.add_mutually_exclusive_group(required=True)
    grupo_entrada.add_argument('-a', '--archivo', type=str, help="Archivo o carpeta de entrada")
    grupo_entrada.add_argument('-f', '--carpeta', type=str, help="Carpeta de entrada (sinónimo)")

    parser.add_argument('-o', '--salida', type=str, required=True, help="Carpeta de salida")
    parser.add_argument('-p', '--patron', type=str, help="Patrón de nombre (sobrescribe el de config)")
    parser.add_argument('--sobrescribir', action='store_true', help="Sobrescribe archivos existentes")

    args = parser.parse_args()

    # Decidir patrón: CLI > Config
    patron_usado = args.patron if args.patron is not None else CONFIG_PATRON

    entrada = args.archivo if args.archivo is not None else args.carpeta

    convertir_entrada(entrada, args.salida, patron_usado, args.sobrescribir)