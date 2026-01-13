"""
metadatos.py - Versión 1.1.1
Extracción avanzada de metadatos con permisos simbólicos y octales, resolución de imágenes y más.
"""

import hashlib
import mimetypes
import stat
from pathlib import Path
from datetime import datetime
import subprocess

try:
    import chardet
except ImportError:
    chardet = None

def formatear_tamano(tamano_bytes: int) -> str:
    if tamano_bytes < 1024 * 1024:
        tamano_kb = tamano_bytes / 1024
        return f"{tamano_kb:.2f} KB"
    else:
        tamano_mb = tamano_bytes / (1024 * 1024)
        return f"{tamano_mb:.2f} MB"

def modo_simbolico(modo_num: int) -> str:
    permisos = ''
    if stat.S_ISDIR(modo_num):
        permisos += 'd'
    elif stat.S_ISLNK(modo_num):
        permisos += 'l'
    else:
        permisos += '-'
    permisos += 'r' if modo_num & stat.S_IRUSR else '-'
    permisos += 'w' if modo_num & stat.S_IWUSR else '-'
    permisos += 'x' if modo_num & stat.S_IXUSR else '-'
    permisos += 'r' if modo_num & stat.S_IRGRP else '-'
    permisos += 'w' if modo_num & stat.S_IWGRP else '-'
    permisos += 'x' if modo_num & stat.S_IXGRP else '-'
    permisos += 'r' if modo_num & stat.S_IROTH else '-'
    permisos += 'w' if modo_num & stat.S_IWOTH else '-'
    permisos += 'x' if modo_num & stat.S_IXOTH else '-'
    return permisos

def fecha_ultima_modificacion(ruta: Path) -> str:
    ts = ruta.stat().st_mtime
    return datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')

def obtener_hash_sha256(ruta: Path, chunk_size=8192):
    sha256 = hashlib.sha256()
    try:
        with ruta.open('rb') as f:
            while True:
                bloque = f.read(chunk_size)
                if not bloque:
                    break
                sha256.update(bloque)
        return sha256.hexdigest()
    except Exception as e:
        return f"Error calculando hash: {e}"

def detectar_encoding(ruta: Path, max_bytes=100000):
    if chardet is None:
        return "chardet no instalado"
    try:
        with ruta.open('rb') as f:
            data = f.read(max_bytes)
        resultado = chardet.detect(data)
        return resultado.get('encoding')
    except Exception:
        return "Error detectando encoding"

def obtener_duracion_multimedia(ruta: Path):
    try:
        resultado = subprocess.run(
            ['ffprobe', '-v', 'error', '-show_entries', 'format=duration', '-of',
             'default=noprint_wrappers=1:nokey=1', str(ruta)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5)
        duracion = resultado.stdout.strip()
        if duracion:
            segundos = float(duracion)
            return segundos
        else:
            return None
    except Exception:
        return None

def obtener_resolucion_imagen(ruta: Path):
    try:
        from PIL import Image
    except ImportError:
        return None
    try:
        with Image.open(ruta) as img:
            return img.size  # (width, height)
    except Exception:
        return None

def obtener_metadatos_archivo(ruta_archivo: Path, sugerencias: dict) -> dict:
    metadatos = {}
    try:
        metadatos['hash_sha256'] = obtener_hash_sha256(ruta_archivo)
        metadatos['tamano_bytes'] = ruta_archivo.stat().st_size
        metadatos['tamano_humano'] = formatear_tamano(metadatos['tamano_bytes'])
        modo_num = ruta_archivo.stat().st_mode
        metadatos['modo_numero'] = stat.S_IMODE(modo_num)  # solo bits permisos
        metadatos['permisos_simbolicos'] = modo_simbolico(modo_num)
        metadatos['fecha_modificacion'] = fecha_ultima_modificacion(ruta_archivo)

        tipo, _ = mimetypes.guess_type(str(ruta_archivo))
        metadatos['tipo_mime'] = tipo or "desconocido"

        if tipo and tipo.startswith("text"):
            try:
                with ruta_archivo.open('r', encoding='utf-8', errors='replace') as f:
                    lineas = 0
                    for _ in f:
                        lineas += 1
                        if lineas > 1000000:
                            break
                metadatos['lineas'] = lineas
            except Exception:
                metadatos['lineas'] = "error leyendo líneas"
            metadatos['encoding'] = detectar_encoding(ruta_archivo)
        else:
            metadatos['lineas'] = None
            metadatos['encoding'] = None

        if tipo and (tipo.startswith("video") or tipo.startswith("audio")):
            metadatos['duracion_segundos'] = obtener_duracion_multimedia(ruta_archivo)
        else:
            metadatos['duracion_segundos'] = None

        if tipo and tipo.startswith("image"):
            metadatos['resolucion'] = obtener_resolucion_imagen(ruta_archivo)
        else:
            metadatos['resolucion'] = None

        if metadatos['tipo_mime'] == "desconocido" or metadatos['tipo_mime'] is None:
            metadatos['recomendacion'] = sugerencias.get('otros', {}).get('herramientas', [])

    except Exception as e:
        metadatos['error'] = str(e)
    return metadatos
