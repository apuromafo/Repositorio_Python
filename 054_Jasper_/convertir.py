#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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

#
# convertir.py
#
# Herramienta de línea de comandos para la conversión silenciosa de archivos
# .jasper a formato PDF. Diseñada para entornos de pentesting donde la 
# supresión de ruido (logs de consola de la JVM) es crítica.
#
# Uso:
# python convertir.py -a archivo.jasper -o ./pdf/
# python convertir.py -f carpeta/ -o ./pdf/
# ==============================================================================
# --- HISTORIAL DE VERSIONES ---
# ==============================================================================
# v2.0.0 (2026-05-20) - [ESTANDARIZACIÓN]
#   ✅ Alineación con Jasper CLI Suite v2.0.
#   ✅ Mejorado: Manejo de rutas absolutas y relativas para evitar errores de escritura.
#
# v1.0.0 (2025-09-15) - [LANZAMIENTO]
#   ✅ Primera versión funcional con supresión de salida de consola.
# ==============================================================================

import argparse
import os
import sys
import time
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

def resolve_output_path(output_arg, input_path):
    """Resuelve la ruta de salida correctamente"""
    if output_arg is None:
        return Path.cwd()
    
    output_path = Path(output_arg)
    
    if output_path.is_absolute():
        if os.name == 'nt' and str(output_arg).startswith('/'):
            relative_path = str(output_arg).lstrip('/')
            return (Path.cwd() / relative_path).resolve()
        else:
            return output_path.resolve()
    else:
        return (Path.cwd() / output_path).resolve()

def format_duration(seconds):
    """Formatea la duración en formato legible"""
    if seconds < 1:
        return f"{seconds:.2f}s"
    elif seconds < 60:
        return f"{seconds:.1f}s"
    else:
        td = timedelta(seconds=int(seconds))
        return str(td)

def get_unique_filename(file_path):
    """
    Si el archivo existe, genera un nombre único agregando timestamp.
    Formato: nombre_original_YYYYMMDD_HHMMSS.extension
    """
    path = Path(file_path)
    
    if not path.exists():
        return path, False
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    new_name = f"{path.stem}_{timestamp}{path.suffix}"
    new_path = path.with_name(new_name)
    
    counter = 1
    while new_path.exists():
        new_name = f"{path.stem}_{timestamp}_{counter:03d}{path.suffix}"
        new_path = path.with_name(new_name)
        counter += 1
    
    return new_path, True

def convertir_jasper_a_pdf(archivo_jasper, archivo_salida_base):
    """Convierte un archivo .jasper a PDF con supresión REAL de mensajes Java"""
    start_time = time.time()
    
    try:
        from pyreportjasper import PyReportJasper
        
        # Verificar si el archivo de salida ya existe y generar nombre único
        output_path_original = Path(f"{archivo_salida_base}.pdf")
        output_path_final, was_renamed = get_unique_filename(output_path_original)
        salida_base_final = output_path_final.with_suffix('')
        
        # Configurar pyreportjasper
        pyreportjasper = PyReportJasper()
        pyreportjasper.config(
            input_file=str(archivo_jasper),
            output_file=str(salida_base_final),
            output_formats=["pdf"]
        )
        
        # SUPRESIÓN REAL - Redirigir file descriptors a nivel OS
        # Guardar los descriptores originales
        original_stdout = os.dup(1)  # stdout
        original_stderr = os.dup(2)  # stderr
        
        try:
            # Crear archivos temporales para redirigir la salida
            with tempfile.TemporaryFile() as temp_file:
                # Redirigir stdout y stderr al archivo temporal
                os.dup2(temp_file.fileno(), 1)
                os.dup2(temp_file.fileno(), 2)
                
                # Ejecutar conversión (ahora SIN mensajes Java)
                pyreportjasper.process_report()
                
        finally:
            # SIEMPRE restaurar los descriptores originales
            os.dup2(original_stdout, 1)
            os.dup2(original_stderr, 2)
            os.close(original_stdout)
            os.close(original_stderr)
        
        # Calcular tiempo
        end_time = time.time()
        duration = end_time - start_time
        
        # Verificar resultado
        if output_path_final.exists():
            result_msg = f"✅ {Path(archivo_jasper).name} → {output_path_final.name}"
            if was_renamed:
                result_msg += f" 🔄 (renombrado)"
            
            return True, result_msg, duration, was_renamed
        else:
            return False, f"❌ Error: {Path(archivo_jasper).name} - archivo no creado", duration, False
            
    except ImportError:
        end_time = time.time()
        duration = end_time - start_time
        return False, "❌ Error: pyreportjasper no instalado", duration, False
    except Exception as e:
        end_time = time.time()
        duration = end_time - start_time
        return False, f"❌ Error: {Path(archivo_jasper).name} - {str(e)[:60]}...", duration, False

def main():
    parser = argparse.ArgumentParser(
        description="🔧 Convertidor Jasper a PDF - Herramienta para Pentesting",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Ejemplos de uso:
  python jasper_final.py -a reporte.jasper
  python jasper_final.py -f ./reportes/
  python jasper_final.py -f ./input/ -o ./salida/

Características:
  - Sin mensajes Java molestos
  - Protección automática contra sobrescritura
  - Información clara de ubicación y progreso  
  - Medición de tiempo precisa
        """
    )
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-a", "--archivo", help="Archivo .jasper individual")
    group.add_argument("-f", "--folder", help="Carpeta con archivos .jasper")
    
    parser.add_argument("-o", "--output", help="Carpeta de salida (por defecto: directorio actual)")
    
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
        
    args = parser.parse_args()
    
    # Tiempo inicio total
    start_total = time.time()
    
    # Configurar rutas
    input_path = Path(args.archivo or args.folder).resolve()
    if not input_path.exists():
        print(f"❌ Error: '{input_path}' no existe")
        sys.exit(1)
    
    output_path = resolve_output_path(args.output, input_path)
    output_path.mkdir(parents=True, exist_ok=True)
    
    # Mostrar información de ubicación clara y concisa
    current_dir = Path.cwd()
    print(f"📍 Trabajando en: {current_dir.name}")
    
    if output_path != current_dir:
        try:
            rel_output = output_path.relative_to(current_dir)
            print(f"📂 Guardando PDFs en: {rel_output}")
        except ValueError:
            print(f"📂 Guardando PDFs en: {output_path}")
    else:
        print(f"📂 Guardando PDFs en: directorio actual")
    
    print("-" * 70)
    
    # Procesar archivos
    archivos_convertidos = 0
    archivos_totales = 0
    archivos_renombrados = 0
    tiempo_total_conversion = 0
    
    if args.archivo:
        # Archivo individual
        if input_path.suffix.lower() != '.jasper':
            print("❌ Error: El archivo debe tener extensión .jasper")
            sys.exit(1)
            
        nombre_base = input_path.stem
        salida_pdf = output_path / nombre_base
        
        print(f"🔄 Convirtiendo: {input_path.name}")
        print()
        
        success, mensaje, duration, was_renamed = convertir_jasper_a_pdf(input_path, salida_pdf)
        tiempo_total_conversion += duration
        
        if success:
            archivos_convertidos = 1
            if was_renamed:
                archivos_renombrados = 1
        
        print(f"   {mensaje}")
        print(f"   ⏱️  Tiempo: {format_duration(duration)}")
        archivos_totales = 1
        
    else:
        # Carpeta completa
        jasper_files = list(input_path.glob("*.jasper"))
        archivos_totales = len(jasper_files)
        
        if archivos_totales == 0:
            print(f"❌ No hay archivos .jasper en '{input_path}'")
            sys.exit(1)
        
        try:
            relative_input = input_path.relative_to(current_dir)
            print(f"📁 Procesando {archivos_totales} archivo(s) desde: {relative_input}")
        except ValueError:
            print(f"📁 Procesando {archivos_totales} archivo(s) desde: {input_path.name}")
        
        print("=" * 70)
        
        for i, jasper_file in enumerate(jasper_files, 1):
            nombre_base = jasper_file.stem
            salida_pdf = output_path / nombre_base
            
            print(f"🔄 [{i}/{archivos_totales}] {jasper_file.name}")
            print()
            
            success, mensaje, duration, was_renamed = convertir_jasper_a_pdf(jasper_file, salida_pdf)
            tiempo_total_conversion += duration
            
            if success:
                archivos_convertidos += 1
                if was_renamed:
                    archivos_renombrados += 1
            
            print(f"   {mensaje}")
            print(f"   ⏱️  Tiempo: {format_duration(duration)}")
    
    # Tiempo total
    end_total = time.time()
    duration_total = end_total - start_total
    
    # Resumen final
    print("=" * 70)
    print(f"📊 Resumen: {archivos_convertidos}/{archivos_totales} archivos convertidos")
    if archivos_renombrados > 0:
        print(f"🔄 Archivos renombrados: {archivos_renombrados} (ya existían)")
    print(f"⏱️  Tiempo total: {format_duration(duration_total)} (conversión: {format_duration(tiempo_total_conversion)})")


print("\n[!] AVISO LEGAL: Use solo con autorizacion. / LEGAL NOTICE: Authorized use only.\n")
if __name__ == "__main__":
    main()