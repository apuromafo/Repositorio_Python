#!/usr/bin/env python3
# ------------------------------------------------------------
# DISCLAIMER: Este script es parte del repositorio de herramientas de pruebas de penetración.
# Su uso está sujeto a los términos de la licencia MIT y al aviso legal presente en el README.
# ------------------------------------------------------------

import logging
logger = logging.getLogger(__name__)
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
logger.addHandler(handler)
logger.setLevel(logging.INFO)

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
# main.py
#
# Lanzador central (Orquestador) de la Jasper CLI Suite.
#
# Modo directo (pipeline completo en una sola carpeta de salida):
#   python main.py -f <carpeta> -o <carpeta_destino>
#   python main.py -a <archivo> -o <carpeta_destino>
#
# Estructura generada en <carpeta_destino>:
#   reporte.log                  -> registro completo de la corrida
#   informe_auditoria.md         -> resumen legible de hallazgos
#   analisis/reporte_analisis.json -> hallazgos tecnicos (JSON)
#   pdf/                         -> PDFs convertidos
#   compilados/                  -> .jasper generados desde .jrxml sin binario
#
# Modo interactivo (sin argumentos):
#   python main.py
# ==============================================================================
# --- HISTORIAL DE VERSIONES ---
# ==============================================================================
# v2.1.0 (2026-08-24) - [PIPELINE DIRECTO]
#   OK Modo por argumentos: -a archivo / -f carpeta + -o destino (obligatorio).
#   OK Pipeline automatico: analizar -> compilar faltantes -> convertir a PDF.
#   OK Registro: reporte.log + informe_auditoria.md dejados en la carpeta destino.
#   OK Usa el .venv de la herramienta si existe (patron wrapper del repositorio).
#
# v2.0.0 (2026-05-20) - [INTEGRACIÓN TOTAL]
#   OK Estandarización de nombres de módulos (analizar.py, compilar.py, etc.).
#   OK Optimización de flujo de ejecución mediante subprocesos con codificación UTF-8.
#
# v1.0.0 (2025-09-15) - [LANZAMIENTO]
#   OK Interfaz interactiva básica para la suite de herramientas.
# ==============================================================================
import subprocess
import sys
import os
import json
import time
import argparse
from datetime import datetime

# Forzar codificación UTF-8 para evitar errores de caracteres especiales (emojis)
if sys.platform == 'win32':
    os.system('chcp 65001 > NUL')
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')

TOOL_DIR = os.path.dirname(os.path.abspath(__file__))
VERSION_SUITE = "2.1.0"

# Configuración de la Suite
SUITE = {
    "1": {"name": "Analizar (Auditoría)", "file": "analizar.py"},
    "2": {"name": "Convertir (.jasper -> PDF)", "file": "convertir.py"},
    "3": {"name": "Compilar (.jrxml -> .jasper)", "file": "compilar.py"},
    "4": {"name": "Descompilar (.jasper -> .jrxml)", "file": "decompilar_v3.py"}
}

SEVERIDAD_MAP = {
    "SQL Injection": "CRÍTICO", "RCE CRÍTICO": "CRÍTICO",
    "XXE POTENCIAL": "CRÍTICO", "Riesgo LFI": "CRÍTICO", "Riesgo LFI/RFI": "CRÍTICO",
    "Debilidad de Tipado": "MEDIO", "Exposición de Datos": "MEDIO", "XSS": "MEDIO",
    "Obsolescencia": "INFORMATIVO"
}


def python_exe():
    """Prefiere el .venv de la herramienta si existe (patron wrapper del repo)."""
    venv_python = os.path.join(TOOL_DIR, ".venv", "Scripts", "python.exe")
    if os.path.exists(venv_python):
        return venv_python
    return sys.executable


class Registro:
    """Acumula el registro de la corrida y lo deja en reporte.log."""

    def __init__(self, carpeta_destino, comando):
        self.carpeta = carpeta_destino
        self.ruta_log = os.path.join(carpeta_destino, "reporte.log")
        self.lineas = []
        self.cabecera(comando)

    def cabecera(self, comando):
        self.add("=" * 78)
        self.add("HERRAMIENTA: Jasper | Categoria: util | Version suite: " + VERSION_SUITE)
        self.add(f"Fecha:       {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self.add(f"Comando:     {comando}")
        self.add("=" * 78)

    def add(self, texto=""):
        self.lineas.append(texto)

    def paso(self, nombre, cmd, returncode, duracion, salida_stdout, salida_stderr):
        self.add()
        self.add(f"[PASO] {nombre}")
        self.add(f"  Comando   : {' '.join(cmd)}")
        self.add(f"  Exit code : {returncode} | Duracion: {duracion:.1f}s")
        self.add("  --- stdout ---")
        self.add(salida_stdout.rstrip() or "(sin salida)")
        if salida_stderr.strip():
            self.add("  --- stderr ---")
            self.add(salida_stderr.rstrip())
        estado = "OK" if returncode == 0 else "ERROR"
        self.add(f"  Resultado : {estado}")
        print(f"    [{'OK' if returncode == 0 else 'ERROR'}] {nombre} ({duracion:.1f}s)")

    def guardar(self):
        self.add()
        self.add("=" * 78)
        self.add(f"Fin de la corrida: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self.add(f"Registro guardado en: {self.ruta_log}")
        self.add("=" * 78)
        with open(self.ruta_log, "w", encoding="utf-8") as f:
            f.write("\n".join(self.lineas) + "\n")


def ejecutar_paso(registro, nombre, script, args_extra):
    """Ejecuta un modulo de la suite capturando su salida para el registro."""
    cmd = [python_exe(), os.path.join(TOOL_DIR, script)] + args_extra
    t0 = time.time()
    proc = subprocess.run(cmd, capture_output=True, cwd=TOOL_DIR)
    duracion = time.time() - t0
    stdout = proc.stdout.decode("utf-8", errors="replace")
    stderr = proc.stderr.decode("utf-8", errors="replace")
    print(stdout.rstrip())
    if stderr.strip():
        print(stderr.rstrip())
    registro.paso(nombre, cmd, proc.returncode, duracion, stdout, stderr)
    return proc.returncode == 0


def recolectar_archivos(ruta):
    """Devuelve (jrxml, jasper) desde un archivo o carpeta (recursivo)."""
    jrxml, jasper = [], []
    if os.path.isfile(ruta):
        baja = ruta.lower()
        if baja.endswith(".jrxml"):
            jrxml.append(ruta)
        elif baja.endswith(".jasper"):
            jasper.append(ruta)
        return jrxml, jasper
    for root, _, files in os.walk(ruta):
        for fn in sorted(files):
            fp = os.path.join(root, fn)
            if fn.lower().endswith(".jrxml"):
                jrxml.append(fp)
            elif fn.lower().endswith(".jasper"):
                jasper.append(fp)
    return jrxml, jasper


def generar_informe_md(ruta_json, ruta_md):
    """Genera informe_auditoria.md legible a partir del JSON de analizar.py."""
    try:
        with open(ruta_json, "r", encoding="utf-8") as f:
            resultados = json.load(f)
    except Exception as e:
        print(f"[-] No se pudo leer el JSON de análisis: {e}")
        return False

    resumen = {"CRÍTICO": 0, "MEDIO": 0, "INFORMATIVO": 0}
    filas = []
    for item in resultados:
        nombre = item.get("file_name", "N/A")
        hash_archivo = item.get("file_hash", "N/A")
        hallazgos = item.get("security_findings", [])
        for h in hallazgos:
            sev = SEVERIDAD_MAP.get(h.get("tipo"), "INFORMATIVO")
            resumen[sev] += 1
            detalle = str(h.get("detalle", "")).replace("|", "/")
            filas.append((nombre, sev, h.get("tipo", "N/A"), detalle))
        if not hallazgos:
            filas.append((nombre, "LIMPIO", "-", "Sin riesgos evidentes"))

    orden = {"CRÍTICO": 0, "MEDIO": 1, "INFORMATIVO": 2, "LIMPIO": 3}
    filas.sort(key=lambda x: (orden.get(x[1], 9), x[0]))

    with open(ruta_md, "w", encoding="utf-8") as f:
        f.write("# Informe de Auditoría JasperReports\n\n")
        f.write(f"**Fecha:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  \n")
        f.write(f"**Archivos analizados:** {len(resultados)}\n\n")
        f.write("## Resumen de severidad\n\n")
        f.write("| Severidad | Cantidad |\n| :--- | :--- |\n")
        for sev in ("CRÍTICO", "MEDIO", "INFORMATIVO"):
            f.write(f"| {sev} | {resumen[sev]} |\n")
        f.write("\n## Detalle de hallazgos\n\n")
        f.write("| Archivo | Severidad | Tipo | Detalle |\n| :--- | :--- | :--- | :--- |\n")
        iconos = {"CRÍTICO": "🔴", "MEDIO": "🟠", "INFORMATIVO": "🔵", "LIMPIO": "✅"}
        for nombre, sev, tipo, detalle in filas:
            f.write(f"| {nombre} | {iconos.get(sev, '')} {sev} | {tipo} | {detalle} |\n")

    print(f"[+] Informe generado: {ruta_md}")
    return True


def ejecutar_pipeline(ruta, salida, comando):
    ruta = os.path.abspath(ruta)
    salida = os.path.abspath(salida)

    if not os.path.exists(ruta):
        print(f"[-] Error: la ruta '{ruta}' no existe.")
        return 1

    os.makedirs(salida, exist_ok=True)
    dir_analisis = os.path.join(salida, "analisis")
    dir_pdf = os.path.join(salida, "pdf")
    dir_compilados = os.path.join(salida, "compilados")
    for d in (dir_analisis, dir_pdf, dir_compilados):
        os.makedirs(d, exist_ok=True)

    registro = Registro(salida, comando)
    errores = 0
    t_total = time.time()

    try:
        jrxml, jasper = recolectar_archivos(ruta)
        print(f"\n[+] Entrada : {ruta}")
        print(f"[+] Destino : {salida}")
        print(f"[+] Archivos: {len(jrxml)} .jrxml | {len(jasper)} .jasper\n")

        # PASO 1: Analisis (reporte)
        print("[PASO 1/4] Análisis de seguridad...")
        json_salida = os.path.join(dir_analisis, "reporte_analisis.json")
        ok = ejecutar_paso(registro, "Análisis (analizar.py)", "analizar.py",
                           ["-a" if os.path.isfile(ruta) else "-f", ruta, "-o", json_salida])
        if not ok:
            errores += 1

        # PASO 2: Compilar .jrxml que no tengan su .jasper
        stems_jasper = {os.path.splitext(os.path.basename(p))[0].lower() for p in jasper}
        faltantes = [p for p in jrxml
                     if os.path.splitext(os.path.basename(p))[0].lower() not in stems_jasper]
        compilados = []
        if faltantes:
            print(f"\n[PASO 2/4] Compilando {len(faltantes)} .jrxml sin binario...")
            for fp in faltantes:
                ok = ejecutar_paso(registro, f"Compilar {os.path.basename(fp)}", "compilar.py",
                                   ["-a", fp, "-o", dir_compilados])
                if ok:
                    compilados.append(os.path.join(dir_compilados,
                                                   os.path.splitext(os.path.basename(fp))[0] + ".jasper"))
                else:
                    errores += 1
        else:
            print("\n[PASO 2/4] Compilación: omitida (todo .jrxml tiene su .jasper)")
            registro.add("\n[PASO] Compilación: omitida (todo .jrxml tiene su .jasper)")

        # PASO 3: Conversion a PDF
        a_convertir = jasper + compilados
        if a_convertir:
            print(f"\n[PASO 3/4] Convirtiendo {len(a_convertir)} .jasper a PDF...")
            for fp in a_convertir:
                ok = ejecutar_paso(registro, f"Convertir {os.path.basename(fp)}", "convertir.py",
                                   ["-a", fp, "-o", dir_pdf])
                if not ok:
                    errores += 1
        else:
            print("\n[PASO 3/4] Conversión: omitida (no hay .jasper)")
            registro.add("\n[PASO] Conversión: omitida (no hay .jasper)")

        # PASO 4: Informe legible
        print("\n[PASO 4/4] Generando informe Markdown...")
        md_generado = generar_informe_md(json_salida, os.path.join(salida, "informe_auditoria.md"))
        registro.add("\n[PASO] Informe Markdown: " + ("OK" if md_generado else "ERROR"))

        # Resumen final
        pdfs = [f for f in os.listdir(dir_pdf) if f.lower().endswith(".pdf")]
        dur_total = time.time() - t_total
        resumen = [
            "",
            "=" * 78,
            "RESUMEN DE LA CORRIDA",
            f"  .jrxml encontrados     : {len(jrxml)}",
            f"  .jasper originales     : {len(jasper)}",
            f"  .jasper compilados     : {len(compilados)}",
            f"  PDFs generados         : {len(pdfs)}",
            f"  Pasos con error        : {errores}",
            f"  Tiempo total           : {dur_total:.1f}s",
            "",
            "Artefactos en la carpeta destino:",
            f"  {os.path.join(salida, 'reporte.log')}",
            f"  {os.path.join(salida, 'informe_auditoria.md')}",
            f"  {json_salida}",
            f"  {dir_pdf}",
            "=" * 78,
        ]
        for linea in resumen:
            print(linea)
        registro.add("\n".join(resumen))
        return 0 if errores == 0 else 1
    finally:
        registro.guardar()
        print(f"[+] Registro dejado en: {registro.ruta_log}")


def modo_cli():
    parser = argparse.ArgumentParser(
        description=f"Jasper CLI Suite v{VERSION_SUITE} - pipeline directo: "
                    "análisis + compilación + conversión a PDF con registro en la carpeta destino.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-a", "--archivo", help="Archivo individual (.jrxml o .jasper)")
    group.add_argument("-f", "--folder", help="Carpeta con .jrxml/.jasper (recursivo)")
    parser.add_argument("-o", "--output", required=True,
                        help="Carpeta destino donde queda todo ordenado + reporte.log")
    args = parser.parse_args()

    ruta = args.archivo if args.archivo else args.folder
    comando = " ".join(sys.argv[1:])
    return ejecutar_pipeline(ruta, args.output, comando)


def ejecutar_modulo(choice):
    script = SUITE[choice]["file"]
    print(f"\n[+] Lanzando: {SUITE[choice]['name']}")

    # Captura de datos
    modo = input("¿Modo (a)rchivo o (f)carpeta?: ").strip().lower()
    ruta = os.path.abspath(input("Ruta completa: "))

    args = [sys.executable, script]
    if modo == 'a':
        args.extend(["-a", ruta])
    elif modo == 'f':
        args.extend(["-f", ruta])
    else:
        print("[-] Modo no válido.")
        return

    # Si es Compilar o Descompilar, pedimos destino y lo creamos
    if choice in ["3", "4"]:
        out = os.path.abspath(input("Carpeta de destino: "))
        os.makedirs(out, exist_ok=True)
        args.extend(["-o", out])

    # Ejecución con manejo de errores
    try:
        # Se redirige la salida al terminal actual
        # al usar 'text=True' y la reconfiguración UTF-8, no debería dar UnicodeError
        subprocess.run(args, check=True)
        print(f"[+] Finalizado con éxito.")
    except subprocess.CalledProcessError:
        print(f"[-] El script {script} terminó con errores.")
    except Exception as e:
        print(f"[-] Error fatal: {e}")


def main():
    print(f"HERRAMIENTA: Jasper | VERSION: {VERSION_SUITE} | Categoria: util | Autor: Michel Faúndez")

    # Modo directo por argumentos (-a / -f presentes en la linea de comandos)
    if {"-a", "--archivo", "-f", "--folder"} & set(sys.argv[1:]):
        sys.exit(modo_cli())

    while True:
        print(f"\n=== JASPER SUITE v{VERSION_SUITE} ===")
        for k, v in SUITE.items():
            print(f"{k}. {v['name']}")
        print("5. Salir")

        c = input("Seleccione: ").strip()
        if c == "5":
            break
        if c in SUITE:
            ejecutar_modulo(c)
        else:
            print("[-] Opción no válida.")


print("\n[!] AVISO LEGAL: Use solo con autorizacion. / LEGAL NOTICE: Authorized use only.\n")
if __name__ == "__main__":
    main()
