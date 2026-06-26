
# =============================================================================
# AVISO LEGAL / LEGAL NOTICE
# -----------------------------------------------------------------------------
# Esta herramienta es unicamente para fines educativos y de auditoria de
# seguridad autorizada. El uso no autorizado contra sistemas sin el
# consentimiento explicito del propietario es ilegal.
# El usuario asume toda responsabilidad por el uso indebido.
#
# This tool is for educational and authorized security auditing purposes only.
# Unauthorized use against systems without the owner's explicit consent is
# illegal. The user assumes all responsibility for misuse.
# =============================================================================

# ==============================================================================
# --- HISTORIAL DE VERSIONES ---
# ==============================================================================
# v1.1.0 (2025-09-23) - [ESTABLE]
#   ✅ Corregido: Creación de archivos temporales en el mismo directorio del APK de entrada.
#   ✅ Mejorado: Lógica de limpieza de archivos temporales.
#   ✅ Refactorizado: Nombres de funciones para mayor claridad.
#
# v1.0.0 (2025-09-19) - [INICIO]
#   ✅ Primera versión para extraer bundles de APKs.
#   ✅ Búsqueda y extracción de archivos bundle.
#   ❌ Directorios temporales creados en la ubicación de ejecución.
# ==============================================================================
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bundle_extractor_final.py - Extractor de index.bundle optimizado para pentesting
"""

from pathlib import Path
from hashlib import sha256
import shutil
from datetime import datetime
import zipfile
import os
import sys
import time

# ──────────────────────────── Funciones auxiliares ────────────────────────────

def sha256_file(file_path: Path) -> str:
    """Calcula SHA-256 de un archivo."""
    h = sha256()
    with file_path.open('rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()

def readable_size(size_bytes: int) -> str:
    """Convierte bytes a formato legible (KB/MB/GB)."""
    if size_bytes == 0:
        return "0 bytes"
    
    for unit in ['bytes', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            if unit == 'bytes':
                return f"{size_bytes:,} {unit}"
            else:
                return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} PB"

def find_index_bundle_variants(base_dir: Path) -> Path | None:
    """Busca bundle con múltiples patrones en assets/."""
    assets_dir = base_dir / "assets"
    if not assets_dir.is_dir():
        return None
    
    patrones_especificos = [
        "index.android.bundle", "index.ios.bundle", "index.bundle",
        "main.jsbundle", "bundle.js"
    ]
    
    for patron in patrones_especificos:
        for path in assets_dir.rglob(patron):
            if path.is_file():
                return path
    
    patrones_genericos = ["index.*.bundle", "*.bundle", "*bundle*"]
    for patron in patrones_genericos:
        for path in assets_dir.rglob(patron):
            if path.is_file():
                return path
    
    return None

def dump_bundle(bundle_path: Path, output_dir: Path) -> tuple[Path, int]:
    """Extrae bundle con timestamp."""
    now = datetime.now().strftime("%Y%m%d_%H%M%S")
    dst_name = f"{bundle_path.name}_extracted_{now}.js"
    dst_path = output_dir / dst_name
    shutil.copy2(bundle_path, dst_path)
    return dst_path, dst_path.stat().st_size

def unzip_to_folder(zip_path: Path, extract_dir: Path) -> None:
    """Descomprime ZIP a carpeta."""
    with zipfile.ZipFile(zip_path, 'r') as zf:
        zf.extractall(extract_dir)

def clean_up_temp_files(temp_zip_path: Path, temp_extract_dir: Path) -> None:
    """Limpia archivos temporales."""
    try:
        if temp_zip_path and temp_zip_path.is_file():
            os.remove(temp_zip_path)
        if temp_extract_dir and temp_extract_dir.is_dir():
            shutil.rmtree(temp_extract_dir)
    except Exception:
        pass

def read_magic_header(file_path: Path, n_bytes: int = 16) -> str:
    """Lee magic header en formato hex."""
    try:
        with file_path.open("rb") as f:
            header_bytes = f.read(n_bytes)
        return ' '.join(f'{b:02X}' for b in header_bytes)
    except Exception:
        return "Error leyendo header"

# ──────────────────────────── Funciones principales ────────────────────────────

def process_full_extraction(apk_path: Path) -> None:
    """Proceso completo de extracción del bundle."""
    print(f"📱 APK de entrada: {apk_path}")
    
    start_time = time.time()
    start_datetime = datetime.now()
    
    size_apk = apk_path.stat().st_size
    print(f"📋 Iniciando proceso de extracción completo... ({start_datetime.strftime('%H:%M:%S')})")
    print(f"📏 Tamaño del APK: {readable_size(size_apk)}")
    
    # Calcular SHA-256 del APK (sin línea separada)
    sha_apk = sha256_file(apk_path)
    print(f"🔐 SHA-256 APK: {sha_apk}")
    
    # Configurar archivos temporales en el mismo directorio del APK
    apk_dir = apk_path.parent
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    temp_zip_path = apk_dir / f"{apk_path.stem}_{timestamp}.zip"
    temp_extract_dir = apk_dir / f"{apk_path.stem}_{timestamp}_extract"
    
    try:
        # Descomprimir y buscar bundle
        shutil.copy2(apk_path, temp_zip_path)
        unzip_to_folder(temp_zip_path, temp_extract_dir)
        bundle_path = find_index_bundle_variants(temp_extract_dir)
        
        if not bundle_path:
            print("❌ No se encontró archivo bundle compatible.")
            return
        
        # Mostrar bundle encontrado
        bundle_relative = bundle_path.relative_to(temp_extract_dir)
        print(f"✅ Se encontró al menos un archivo bundle en el APK:")
        print(f"   - {bundle_relative}")
        
        # Extraer bundle
        final_path, size_bundle = dump_bundle(bundle_path, apk_dir)
        sha_bundle = sha256_file(final_path)
        
        # Información del magic header
        magic_header = read_magic_header(bundle_path)
        
        # Calcular tiempo transcurrido
        elapsed_time = time.time() - start_time
        end_datetime = datetime.now()
        
        # Output final ordenado (sin duplicar tamaño APK)
        print(f"📄 Bundle extraído: {final_path}")
        print(f"🔍 Magic header: {magic_header}")
        print(f"🔐 SHA-256 Bundle: {sha_bundle}")
        print(f"📏 Tamaño Bundle: {readable_size(size_bundle)}")
        print("")  # Línea en blanco antes del resumen
        print(f"🎉 Proceso completado exitosamente! (Tiempo: {elapsed_time:.2f}s, Fin: {end_datetime.strftime('%H:%M:%S')})")
        
    finally:
        clean_up_temp_files(temp_zip_path, temp_extract_dir)

def initial_scan_apk(apk_path: Path) -> None:
    """Escaneo rápido del APK sin extracción completa."""
    print(f"📱 APK de entrada: {apk_path}")
    
    start_time = time.time()
    start_datetime = datetime.now()
    
    size_apk = apk_path.stat().st_size
    print(f"🔍 Realizando escaneo rápido... ({start_datetime.strftime('%H:%M:%S')})")
    print(f"📏 Tamaño del APK: {readable_size(size_apk)}")
    
    sha_apk = sha256_file(apk_path)
    print(f"🔐 SHA-256 APK: {sha_apk}")
    
    try:
        with zipfile.ZipFile(apk_path, 'r') as zf:
            found_files = []
            
            patrones_especificos = [
                "assets/index.android.bundle", "assets/index.ios.bundle", 
                "assets/index.bundle", "assets/main.jsbundle", "assets/bundle.js"
            ]
            patrones_genericos = ["assets/index.", "assets/bundle"]
            
            for file_path in zf.namelist():
                if file_path.startswith("assets/"):
                    if any(file_path == p for p in patrones_especificos) or \
                       any(p in file_path for p in patrones_genericos):
                        found_files.append(file_path)
        
        elapsed_time = time.time() - start_time
        end_datetime = datetime.now()
        
        if not found_files:
            print("❌ No se encontró archivo bundle compatible durante el escaneo.")
            print("💡 Considera usar el 'proceso completo' para búsqueda exhaustiva.")
        else:
            print("✅ Se encontró al menos un archivo bundle en el APK:")
            for found_file in sorted(list(set(found_files))):
                print(f"   - {found_file}")
        
        print("")  # Línea en blanco
        print(f"🎉 Escaneo completado! (Tiempo: {elapsed_time:.2f}s, Fin: {end_datetime.strftime('%H:%M:%S')})")
        
    except zipfile.BadZipFile:
        print("❌ Error: Archivo no es un ZIP/APK válido.")
    except Exception as e:
        print(f"❌ Error inesperado: {e}")

def analyze_bundle_file(file_path: Path) -> None:
    """Analiza un archivo bundle existente."""
    print(f"📄 Archivo bundle: {file_path}")
    
    start_time = time.time()
    start_datetime = datetime.now()
    
    if not file_path.is_file():
        print("❌ Archivo no existe o no es válido.")
        return
    
    size_bundle = file_path.stat().st_size
    print(f"📋 Analizando archivo bundle... ({start_datetime.strftime('%H:%M:%S')})")
    print(f"📏 Tamaño: {readable_size(size_bundle)}")
    
    magic_header = read_magic_header(file_path)
    print(f"🔍 Magic header: {magic_header}")
    
    sha_bundle = sha256_file(file_path)
    print(f"🔐 SHA-256: {sha_bundle}")
    
    elapsed_time = time.time() - start_time
    end_datetime = datetime.now()
    
    print("")  # Línea en blanco
    print(f"🎉 Análisis completado! (Tiempo: {elapsed_time:.2f}s, Fin: {end_datetime.strftime('%H:%M:%S')})")

# ──────────────────────────── Main ────────────────────────────

def main() -> None:
    print("═══ Bundle Extractor v3 - Pentesting Tool ═══\n")
    print("Seleccione opción:")
    print("1. Extraer y analizar bundle (proceso completo)")
    print("2. Escaneo rápido de APK")
    print("3. Analizar archivo bundle existente")
    print("0. Salir")
    
    opcion = input("\n➤ Opción (0-3): ").strip()
    
    if opcion == '0':
        print("👋 Saliendo...")
        return
    
    if opcion not in ['1', '2', '3']:
        print("❌ Opción inválida.")
        return
    
    if opcion in ['1', '2']:
        ruta_input = input("📂 Ruta del APK: ").strip().strip('"').strip("'")
        ruta = Path(ruta_input).expanduser().resolve()
        
        if not ruta.is_file():
            print("❌ Archivo APK no encontrado.")
            return
        
        if opcion == '1':
            process_full_extraction(ruta)
        else:  # opcion == '2'
            initial_scan_apk(ruta)
            
    elif opcion == '3':
        ruta_input = input("📂 Ruta del bundle: ").strip().strip('"').strip("'")
        ruta = Path(ruta_input).expanduser().resolve()
        analyze_bundle_file(ruta)


print("\n[!] AVISO LEGAL: Use solo con autorizacion. / LEGAL NOTICE: Authorized use only.\n")
if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n⚠️  Proceso interrumpido por el usuario.")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error inesperado: {e}")
        sys.exit(1)