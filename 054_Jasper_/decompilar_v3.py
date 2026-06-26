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
# decompilar_v3.py
#
# Herramienta de línea de comandos para la descompilación de binarios .jasper
# a archivos fuente .jrxml. Integra un puente Java para una reconstrucción fiel
# y ejecuta un motor de análisis estático (OWASP) sobre el código recuperado.
#
# Uso:
# python decompilar_v3.py -a archivo.jasper -o salida/
# python decompilar_v3.py -f carpeta/ -o salida/
# ==============================================================================
# --- HISTORIAL DE VERSIONES ---
# ==============================================================================
# v3.0.0 (2026-05-20) - [INTEGRACIÓN SUITE]
#   ✅ Alineación con Jasper CLI Suite v2.0.
#   ✅ Añadido: Reporte automático de auditoría de seguridad en formato JSON y Markdown.
#
# v2.0.0 (2025-09-20) - [ESTABLE]
#   ✅ Lanzamiento del puente Java mejorado para evitar errores en versiones antiguas.
#
# v1.0.0 (2025-09-14) - [INICIO]
#   ✅ Primera versión de descompilador funcional.
# ==============================================================================
import os
import sys
import subprocess
import argparse
import glob
import site
import re
import json
import datetime

# Puente Java para descompilación fiel
JAVA_BRIDGE = """
import net.sf.jasperreports.engine.JasperReport;
import net.sf.jasperreports.engine.util.JRLoader;
import net.sf.jasperreports.engine.xml.JRXmlWriter;
import java.io.File;
public class JasperBridge {
    public static void main(String[] args) {
        try {
            JasperReport jr = (JasperReport) JRLoader.loadObject(new File(args[0]));
            JRXmlWriter.writeReport(jr, args[1], "UTF-8");
            System.out.println("SUCCESS");
        } catch (Exception e) { e.printStackTrace(); System.exit(1); }
    }
}
"""

def detectar_librerias():
    # Detecta el site-packages de forma dinámica
    for site_path in site.getsitepackages():
        potential_path = os.path.join(site_path, "pyreportjasper", "libs")
        if os.path.exists(potential_path):
            return os.pathsep.join(glob.glob(os.path.join(potential_path, "*.jar")))
    return None

def calcular_severidad(hallazgos):
    severidad = {"CRÍTICO": 0, "MEDIO": 0, "BAJO": 0}
    for h in hallazgos:
        if h['tipo'] in ['RCE CRÍTICO', 'SQL Injection']: severidad['CRÍTICO'] += 1
        elif h['tipo'] in ['Riesgo LFI', 'XSS', 'Exposición de Datos']: severidad['MEDIO'] += 1
        else: severidad['BAJO'] += 1
    return severidad

def motor_analisis_evidencias(jrxml_path):
    evidencias = []
    with open(jrxml_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
        lineas = content.splitlines()

    # 1. Auditoría Exhaustiva de Parámetros
    params = re.findall(r'parameter name="([^"]+)" class="([^"]+)"', content)
    for p, p_class in params:
        tipo_limpio = p_class.split('.')[-1]
        if p.startswith("PV60_"):
            evidencias.append({"tipo": "Obsolescencia", "detalle": f"Param '{p}' (Tipo: {tipo_limpio})"})
        if "java.lang.Object" in p_class:
            evidencias.append({"tipo": "Debilidad de Tipado", "detalle": f"Param '{p}' usa tipo Object. Recomendado: String, BigDecimal o Integer."})

    # 2. Análisis de Inyección (SQL, LFI, RCE)
    for i, linea in enumerate(lineas):
        if "$P!{" in linea:
            match = re.search(r'\$P!\{([^}]+)\}', linea)
            p = match.group(1) if match else "desconocido"
            evidencias.append({"tipo": "SQL Injection", "detalle": f"Query dinámico inseguro en línea {i+1} con param '$P!{{{p}}}'"})
        if "imageExpression" in linea and "$P{" in linea:
            match = re.search(r'\$P\{([^}]+)\}', linea)
            p = match.group(1) if match else "desconocido"
            evidencias.append({"tipo": "Riesgo LFI", "detalle": f"Imagen dinámica en línea {i+1} con param '$P{{{p}}}'. Requiere Whitelist."})

    # 3. Análisis de Riesgos Globales
    if re.search(r'(Runtime\.getRuntime|java\.io\.File|ProcessBuilder)', content):
        evidencias.append({"tipo": "RCE CRÍTICO", "detalle": "Clases de sistema detectadas (Riesgo de ejecución de comandos)"})
    sensible = re.search(r'(rut|clave|password|cuenta_bancaria)', content, re.IGNORECASE)
    if sensible:
        evidencias.append({"tipo": "Exposición de Datos", "detalle": f"Campo sensible detectado: '{sensible.group(0)}' (posible PII/credencial)"})
    if 'markup="html"' in content:
        evidencias.append({"tipo": "XSS", "detalle": "Markup HTML habilitado (posible inyección de scripts)"})

    return evidencias

def generar_reporte_ejecutivo(total_archivos, reporte_detallado, output_dir):
    resumen_severidad = {"Crítico": 0, "Medio": 0, "Informativo": 0}
    hallazgos_unicos = set()
    severidad_map = {"Riesgo LFI": "Crítico", "Debilidad de Tipado": "Medio", "Obsolescencia": "Informativo"}
    
    for hallazgos in reporte_detallado.values():
        for h in hallazgos:
            resumen_severidad[severidad_map.get(h['tipo'], "Informativo")] += 1
            hallazgos_unicos.add(h['tipo'])

    # --- Salida en consola (Tu lógica original intacta) ---
    print("\n" + "="*85)
    print("INFORME EJECUTIVO DE AUDITORÍA: JASPER REPORTS")
    print(f"Distribución de Riesgos: {resumen_severidad}")
    print("="*85)
    
    for arch, hallazgos in reporte_detallado.items():
        if hallazgos:
            print(f"\n[!] {arch}:")
            for h in hallazgos: print(f"    - [{h['tipo'].upper()}]: {h['detalle']}")
    
    print("\n" + "="*85)
    print("GUÍA DE REMEDIACIÓN Y BUENAS PRÁCTICAS (OWASP)")
    
    if "Riesgo LFI" in hallazgos_unicos:
        print("\n[!] ALERTA CRÍTICA: RIESGO DE LFI (Local File Inclusion)")
        print("    -> Referencia: OWASP A03:2021-Injection")
        print("    -> Acción: Implementar Whitelist (lista blanca) de archivos permitidos.")
        print("    -> Ejemplo: Validar que el parámetro solo contenga nombres de archivos del directorio autorizado.")
    
    if "Debilidad de Tipado" in hallazgos_unicos:
        print("\n[!] MEJORA: TIPADO ESTRICTO (Referencia CWE-704)")
        print("    -> Cambiar 'java.lang.Object' por:")
        print("       - java.lang.String (Textos/Nombres/RUT)")
        print("       - java.math.BigDecimal (Montos monetarios - evita errores de precisión)")
        print("       - java.lang.Integer o java.lang.Long (Códigos/Folios)")
    
    if "Obsolescencia" in hallazgos_unicos:
        print("\n[!] DEUDA TÉCNICA: ESTRUCTURA DE DATOS")
        print("    -> Acción: Refactorizar 'PV60_XX' a nombres descriptivos (ej: 'ClientTaxID').")
        print("    -> Beneficio: Facilita auditorías de seguridad y trazabilidad de datos sensibles.")
        
    print("="*85 + "\n")

    # --- Generación dinámica del reporte.md (Basado estrictamente en los mismos hallazgos) ---
    with open(os.path.join(output_dir, "reporte.md"), "w", encoding="utf-8") as f:
        f.write("# INFORME EJECUTIVO DE AUDITORÍA: JASPER REPORTS\n\n")
        f.write(f"**Distribución de Riesgos:** `{resumen_severidad}`\n\n")
        for arch, hallazgos in reporte_detallado.items():
            if hallazgos:
                f.write(f"## [!] {arch}:\n")
                for h in hallazgos: f.write(f"- **[{h['tipo'].upper()}]**: {h['detalle']}\n")
        
        f.write("\n---\n# GUÍA DE REMEDIACIÓN Y BUENAS PRÁCTICAS (OWASP)\n")
        if "Riesgo LFI" in hallazgos_unicos:
            f.write("\n### [!] ALERTA CRÍTICA: RIESGO DE LFI\n- **Referencia**: OWASP A03:2021-Injection\n- **Acción**: Implementar Whitelist de archivos permitidos.\n")
        if "Debilidad de Tipado" in hallazgos_unicos:
            f.write("\n### [!] MEJORA: TIPADO ESTRICTO\n- **Acción**: Cambiar 'java.lang.Object' por String, BigDecimal, Integer o Long.\n")
        if "Obsolescencia" in hallazgos_unicos:
            f.write("\n### [!] DEUDA TÉCNICA: ESTRUCTURA DE DATOS\n- **Acción**: Refactorizar 'PV60_XX' a nombres descriptivos.\n")

def main():
    start_time = datetime.datetime.now()
    print(f"[{start_time.strftime('%H:%M:%S')}] [HITO 0] Iniciando Auditoría...")
    
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-a", "--archivo"); group.add_argument("-f", "--folder")
    parser.add_argument("-o", "--output", required=True)
    args = parser.parse_args()

    print("[HITO 1] Configurando entorno...")
    cp = detectar_librerias()
    if not cp: sys.exit("❌ Error: Librerías no detectadas.")
    os.makedirs(args.output, exist_ok=True)
    archivos = [args.archivo] if args.archivo else [os.path.join(r, fi) for r, _, fs in os.walk(args.folder) for fi in fs if fi.endswith(".jasper")]
    
    print("[HITO 2] Preparando motor de descompilación...")
    reporte_detallado = {}
    audit_log = []
    with open("JasperBridge.java", "w") as f: f.write(JAVA_BRIDGE)
    subprocess.run(["javac", "-cp", cp, "JasperBridge.java"], capture_output=True)

    print("[HITO 3] Analizando archivos...")
    for arch in archivos:
        nombre = os.path.basename(arch).replace(".jasper", ".jrxml")
        destino = os.path.join(args.output, nombre)
        res = subprocess.run(["java", "-cp", f".{os.pathsep}{cp}", "JasperBridge", arch, destino], capture_output=True)
        if res.returncode == 0:
            hallazgos = motor_analisis_evidencias(destino)
            reporte_detallado[nombre] = hallazgos
            audit_log.append(f"Auditado: {nombre} | Hallazgos: {len(hallazgos)}")
            print(f"[+] Auditado: {nombre} | Hallazgos: {len(hallazgos)}")

    print("[HITO 4] Generando artefactos finales...")
    with open(os.path.join(args.output, "audit.log"), "w") as f: f.write("\n".join(audit_log))
    with open(os.path.join(args.output, "findings.json"), "w") as f: json.dump(reporte_detallado, f, indent=4)
    with open(os.path.join(args.output, "reporte.md"), "w") as f:
        for arch, h in reporte_detallado.items():
            if h: f.write(f"## {arch}\n" + "\n".join([f"- **[{item['tipo'].upper()}]**: {item['detalle']}" for item in h]) + "\n\n")

    generar_reporte_ejecutivo(len(archivos), reporte_detallado, args.output)
    for f in ["JasperBridge.java", "JasperBridge.class"]:
        if os.path.exists(f): os.remove(f)
    print(f"--- Proceso finalizado en {datetime.datetime.now() - start_time} ---")


print("\n[!] AVISO LEGAL: Use solo con autorizacion. / LEGAL NOTICE: Authorized use only.\n")
if __name__ == "__main__":
    main()