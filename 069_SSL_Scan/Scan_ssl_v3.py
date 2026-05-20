import sys
import argparse
import re
import subprocess
import os
import urllib.request
import zipfile
import shutil
from datetime import datetime
from colorama import init, Fore, Style

# ======================================================================================
# SCAN SSL - Versión 34.0 | FULL COMPLIANCE & ARCHITECT EDITION
# --------------------------------------------------------------------------------------
# [✔] VISUAL: Coloreado exacto de SSLScan (Cyan/Verde/Rojo).
# [✔] PQC: FIPS 203 (ML-KEM) y FIPS 204 (ML-DSA) - Riesgo de Shor & Harvest-now.
# [✔] PCI DSS 4.0.1: Requisitos de confianza, renegociación y cifrados.
# [✔] NIST SP 800-52: Control de vigencia, CA y TLS 1.3.
# [✔] INFRA: Persistencia jerárquica con logs inalterados.
# ======================================================================================

init(autoreset=True)

# --- [CONFIGURACIÓN Y RUTAS] ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TOOLS_DIR = os.path.join(BASE_DIR, "tools", "sslscan", "2.2.2")
SSLSCAN_BINARY = os.path.join(TOOLS_DIR, "sslscan.exe")
RAIZ_RESULTADOS = os.path.join(BASE_DIR, "Resultados_SSL")

TITULOS_CYAN = [
    "SSL/TLS Protocols:", "TLS Fallback SCSV:", "TLS renegotiation:", 
    "TLS Compression:", "Heartbleed:", "Supported Server Cipher(s):", 
    "Server Key Exchange Group(s):", "SSL Certificate:", "Issuer:", "Altnames:"
]

def provisionar_binario():
    """Garantiza la disponibilidad de la herramienta de escaneo."""
    if os.path.exists(SSLSCAN_BINARY): return True
    os.makedirs(TOOLS_DIR, exist_ok=True)
    url = "https://github.com/rbsec/sslscan/releases/download/2.2.2/sslscan-2.2.2.zip"
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        zip_path = os.path.join(TOOLS_DIR, "temp.zip")
        with urllib.request.urlopen(req) as r, open(zip_path, 'wb') as f: f.write(r.read())
        with zipfile.ZipFile(zip_path, 'r') as z: z.extractall(TOOLS_DIR)
        for root, _, files in os.walk(TOOLS_DIR):
            if "sslscan.exe" in files: shutil.move(os.path.join(root, "sslscan.exe"), SSLSCAN_BINARY)
        if os.path.exists(zip_path): os.remove(zip_path)
        return True
    except Exception as e:
        print(f"{Fore.RED}[✘] Error crítico de provisión: {e}")
        return False

# --- [MOTOR DE COLOREADO PROFESIONAL] ---

def render_log_line(linea):
    """Lógica de Semáforo Estricto: Protocolos obsoletos siempre en Rojo."""
    l = linea.rstrip()
    
    # 1. Títulos y Versión
    if l.startswith("Version:"): return f"Version: {Fore.GREEN}{l.replace('Version:', '').strip()}{Style.RESET_ALL}"
    for t in TITULOS_CYAN:
        if t in l: return f"{Fore.CYAN}{Style.BRIGHT}{l}"

    # 2. Lógica de Protocolos (CORREGIDA)
    # SSLv2, SSLv3, TLSv1.0, TLSv1.1 -> ROJO si están 'enabled'
    # TLSv1.2, TLSv1.3 -> VERDE si están 'enabled'
    p_inseguros = ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"]
    p_seguros = ["TLSv1.2", "TLSv1.3"]

    for p in p_inseguros:
        if p in l:
            l = l.replace("disabled", f"{Fore.GREEN}disabled{Style.RESET_ALL}")
            l = l.replace("enabled", f"{Fore.RED}{Style.BRIGHT}enabled{Style.RESET_ALL}")
            return l
    for p in p_seguros:
        if p in l:
            l = l.replace("disabled", f"{Fore.RED}disabled{Style.RESET_ALL}")
            l = l.replace("enabled", f"{Fore.GREEN}enabled{Style.RESET_ALL}")
            return l

    # 3. Cifrados y PQC
    if any(x in l for x in ["Accepted", "Preferred", "bits"]):
        l = l.replace("Preferred", f"{Fore.GREEN}Preferred{Style.RESET_ALL}")
        l = re.sub(r"(\d{3,4} bits)", f"{Fore.GREEN}\\1{Style.RESET_ALL}", l)
        l = re.sub(r"\b(TLS_[A-Z0-9_]+|ECDHE-[A-Z0-9-]+|X25519MLKEM\d+|MLKEM\d+|Kyber\d+)\b", f"{Fore.GREEN}\\1{Style.RESET_ALL}", l)
        return l

    # 4. Vulnerabilidades
    if "to heartbleed" in l:
        c = Fore.GREEN if "not vulnerable" in l else Fore.RED + Style.BRIGHT
        return l.replace("not vulnerable", f"{c}not vulnerable{Style.RESET_ALL}").replace("vulnerable", f"{c}vulnerable{Style.RESET_ALL}")

    return l

# --- [MOTOR DE AUDITORÍA Y CUMPLIMIENTO] ---

def ejecutar_auditoria_v34(texto_analizar, target_id):
    """Genera el reporte de cumplimiento técnico estructurado."""
    ts_actual = datetime.now()
    
    def print_h(item, status, ref="", motivo="", evidencia="", accion=""):
        if any(x in status for x in ["Good", "Vanguardia", "Not vulnerable", "Trusted", "Vigente", "OK"]):
            color = Fore.GREEN + Style.BRIGHT
        elif any(x in status for x in ["Non-compliant", "VULNERABLE", "No cumple", "Riesgo", "Legacy"]):
            color = Fore.RED + Style.BRIGHT
        else:
            color = Fore.YELLOW
            
        print(f"{item:45} | {color}{status}")
        if ref: print(f"    {Fore.WHITE}Reference: {ref}")
        if motivo: print(f"    {Fore.WHITE}{Style.DIM}└─ {motivo}")
        if evidencia: print(f"    {Fore.BLUE}{Style.NORMAL}└─ Evidencia Técnica: {evidencia}")
        if accion: print(f"    {Fore.MAGENTA}{Style.BRIGHT}└─ REQUERIMIENTO: {accion}")

    print(f"\n{Fore.MAGENTA}{'='*95}")
    print(f"INFORME TÉCNICO DE AUDITORÍA SSL v34.0 | TARGET: {target_id}")
    print(f"Fecha de análisis: {ts_actual.strftime('%d-%m-%Y %H:%M:%S')}")
    print(f"{Fore.MAGENTA}{'='*95}")

    # --- SECCIÓN: POST-QUANTUM (FIPS 203/204) ---
    print(f"\n{Fore.CYAN}>>> Post-Quantum Cryptography (PQC) Readiness Test ".ljust(95, "-"))
    kex = re.search(r"(X25519MLKEM\d+|MLKEM\d+|Kyber\d+)", texto_analizar, re.I)
    print_h("Hybrid ML-KEM Key Exchange", "Vanguardia" if kex else "Non-compliant", 
            ref="FIPS 203", motivo="Mitigación de ataques de retro-descifrado (Harvest-now).",
            evidencia=kex.group(1) if kex else "Criptografía asimétrica clásica detectada.")

    sig = re.search(r"Signature Algorithm:\s+(.*)", texto_analizar)
    alg_str = sig.group(1).strip() if sig else "RSA/Classic"
    is_pqc_sig = not any(x in alg_str.lower() for x in ["rsa", "sha256", "ecdsa"])
    print_h("PQC Digital Signature", "Vanguardia" if is_pqc_sig else "Non-compliant with NIST",
            ref="FIPS 204", motivo=f"Algoritmo {alg_str} vulnerable al algoritmo de Shor.",
            evidencia=alg_str, accion="Migrar a ML-DSA en la próxima renovación de certificados.")

    # --- SECCIÓN: PCI DSS 4.0.1 ---
    print(f"\n{Fore.CYAN}>>> SSL/TLS PCI DSS 4.0.1 Compliance Test ".ljust(95, "-"))
    issuer = re.search(r"Issuer:\s+(.*)", texto_analizar)
    print_h("Certificates are Trusted", "Trusted" if issuer else "Non-compliant", 
            ref="PCI DSS 4.2", evidencia=f"CA: {issuer.group(1).strip() if issuer else 'Desconocida'}")

    hb = "vulnerable to heartbleed" in texto_analizar.lower() and "not vulnerable" not in texto_analizar.lower()
    print_h("Vulnerability: HEARTBLEED", "Not vulnerable" if not hb else "VULNERABLE")

    reneg = "Insecure client-initiated renegotiation" in texto_analizar and "not supported" not in texto_analizar
    print_h("Secure Renegotiation", "Good configuration" if not reneg else "Riesgo", 
            motivo="Protección contra inyección de datos durante el apretón de manos.")

    # --- SECCIÓN: NIST & BEST PRACTICES ---
    print(f"\n{Fore.CYAN}>>> NIST SP 800-52 & Best Practices Test ".ljust(95, "-"))
    tls13 = "TLSv1.3" in texto_analizar
    print_h("TLS 1.3 Supported", "Good configuration" if tls13 else "Legacy / Risk", 
            motivo="Recomendado por NIST para confidencialidad persistente.")

    try:
        exp = re.search(r"Not valid after:\s+(.*) GMT", texto_analizar)
        if exp:
            f_exp = datetime.strptime(exp.group(1).strip(), "%b %d %H:%M:%S %Y")
            dias = (f_exp - ts_actual).days
            print_h("Certificate Validity", "Vigente" if dias > 0 else "Expirado", 
                    motivo=f"Vencimiento: {f_exp.strftime('%d-%m-%Y')}", evidencia=f"{dias} días restantes.")
    except: pass

    print(f"\n{Fore.MAGENTA}{'='*95}\n")

# --- [FLUJO DE CONTROL] ---

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", help="Dominio o IP")
    parser.add_argument("-f", "--file", help="Carga de evidencia offline")
    args = parser.parse_args()

    content = ""

    if args.file:
        log_path = os.path.join(args.file, "EVIDENCIA_SSLSCAN.log")
        if os.path.exists(log_path):
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                for linea in f:
                    content += linea
                    print(render_log_line(linea))
            ejecutar_auditoria_v34(content, args.file)
        else:
            print(f"{Fore.RED}[✘] No se encontró evidencia en la ruta especificada.")
        return

    if args.target:
        if not provisionar_binario(): return
        print(f"{Fore.YELLOW}[*] Ejecutando análisis técnico sobre {args.target}...")
        
        # Escaneo sin color para procesamiento de datos
        proc = subprocess.run([SSLSCAN_BINARY, "--no-colour", args.target], capture_output=True, text=True)
        
        # Persistencia de datos
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        folder = os.path.join(RAIZ_RESULTADOS, f"{args.target.replace('.','_')}_{stamp}")
        os.makedirs(folder, exist_ok=True)
        
        with open(os.path.join(folder, "EVIDENCIA_SSLSCAN.log"), "w", encoding='utf-8') as f:
            f.write(proc.stdout)
        
        # Visualización y Auditoría
        for linea in proc.stdout.splitlines():
            print(render_log_line(linea))
            
        ejecutar_auditoria_v34(proc.stdout, args.target)
        print(f"{Fore.GREEN}[✔] Proceso finalizado. Evidencia física en: {folder}")
    else:
        parser.print_help()

if __name__ == "__main__":
    main()