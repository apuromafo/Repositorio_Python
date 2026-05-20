#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# compilar.py
#
# Herramienta de línea de comandos para compilar archivos fuente .jrxml
# a binarios .jasper. Utiliza un puente Java dinámico para asegurar la 
# compatibilidad con JasperReports.
#
# Uso:
# python compilar.py -a archivo.jrxml      # Compila un JRXML
# python compilar.py -f carpeta/           # Compila una carpeta completa
# ==============================================================================
# --- HISTORIAL DE VERSIONES ---
# ==============================================================================
# v2.0.0 (2026-05-20) - [ESTANDARIZACIÓN]
#   ✅ Alineación con la Jasper CLI Suite v2.0.
#   ✅ Corregido: Gestión de rutas y creación automática de directorios de salida.
#
# v1.0.0 (2025-09-14) - [LANZAMIENTO]
#   ✅ Primera versión funcional del compilador con puente Java.
# ==============================================================================
import os
import sys
import subprocess
import argparse
import glob
import site

JAVA_COMPILER_BRIDGE = """
import net.sf.jasperreports.engine.JasperCompileManager;
import java.io.File;
public class JasperCompilerBridge {
    public static void main(String[] args) {
        try {
            JasperCompileManager.compileReportToFile(args[0], args[1]);
            System.out.println("SUCCESS");
        } catch (Exception e) { e.printStackTrace(); System.exit(1); }
    }
}
"""

def detectar_librerias():
    for site_path in site.getsitepackages():
        potential_path = os.path.join(site_path, "pyreportjasper", "libs")
        if os.path.exists(potential_path):
            return os.pathsep.join(glob.glob(os.path.join(potential_path, "*.jar")))
    return None

def compilar(input_path, output_dir):
    # --- AQUÍ ESTÁ EL CAMBIO ---
    if not os.path.exists(output_dir):
        print(f"[+] Creando carpeta de destino: {output_dir}")
        os.makedirs(output_dir)
    # ---------------------------
    
    cp = detectar_librerias()
    if not cp:
        print("[-] Error: No se encontraron librerías de JasperReports.")
        return

    # Crear el archivo Java del compilador
    with open("JasperCompilerBridge.java", "w") as f:
        f.write(JAVA_COMPILER_BRIDGE)
    
    # Compilar el puente
    subprocess.run(["javac", "-cp", cp, "JasperCompilerBridge.java"], capture_output=True)

    # Ejecutar la compilación del reporte
    nombre_archivo = os.path.basename(input_path).replace(".jrxml", ".jasper")
    destino = os.path.join(output_dir, nombre_archivo)
    
    res = subprocess.run(["java", "-cp", f".{os.pathsep}{cp}", "JasperCompilerBridge", input_path, destino], capture_output=True)
    
    if res.returncode == 0:
        print(f"[+] Compilado: {nombre_archivo}")
    else:
        print(f"[-] Error al compilar: {res.stderr.decode()}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-a", "--analyze-file", help="Archivo .jrxml")
    group.add_argument("-f", "--analyze-folder", help="Carpeta con .jrxml")
    parser.add_argument("-o", "--output", required=True, help="Carpeta destino")
    args = parser.parse_args()

    if args.analyze_file:
        compilar(args.analyze_file, args.output)
    else:
        for jrxml in glob.glob(os.path.join(args.analyze_folder, "*.jrxml")):
            compilar(jrxml, args.output)