#!/usr/bin/env python3
"""
 __S_C_A_N___S_S_L__   v34.1 — FULL COMPLIANCE & ARCHITECT EDITION
═══════════════════════════════════════════════════════════════════
  SSL/TLS Security Auditor with Post-Quantum Cryptography readiness.

  [+] PCI DSS 4.0.1  |  NIST SP 800-52  |  FIPS 203/204  |  CVSS 3.1/4.0
  [+] Real-time colored output  |  Offline evidence review  |  Executive summary
  [+] sslscan engine 2.2.2     |  Automatic binary provisioning

  Author:  Apuromafo Security Team
  Repo:    https://github.com/apuromafo/Repositorio_Python
═══════════════════════════════════════════════════════════════════
"""
import sys
import argparse
import re
import json
import subprocess
import os
import urllib.request
import zipfile
import shutil
from datetime import datetime, timezone
from colorama import init, Fore, Style, Back

init(autoreset=True)

VERSION = "v34.1"

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

# -----------------------------------------------------------------------
# CVSS 3.1 / 4.0 — Referencias oficiales FIRST.org
# Documentación de referencia:
#   CVSS 4.0 Spec:  https://www.first.org/cvss/v4-0/cvss-v40-specification_v1.0.pdf
#   CVSS 3.1 Spec:  https://www.first.org/cvss/v3-1/cvss-v31-specification_v1.1.pdf
#   Calculadora:    https://www.first.org/cvss/calculator/4.0
#
# Vectores asignados según guías oficiales:
#   SSLv2/3 enabled   →  AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H  (9.8 CRITICAL)
#                         Ref: CVE-2014-3566 (POODLE), CVE-2016-0800 (DROWN)
#   TLSv1.0/1 enabled →  AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L  (7.4 HIGH)
#                         Ref: CVE-2011-3389 (BEAST), RFC 8996 (deprecation)
#   TLSv1.3 disabled  →  AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N  (5.9 MEDIUM)
#                         Ref: NIST SP 800-52 Rev. 2, PCI DSS 4.0.1 req.
#   Heartbleed        →  AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N  (7.5 HIGH)
#                         Ref: CVE-2014-0160, CAPEC-497
#   Reneg. insegura   →  AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N  (6.8 MEDIUM)
#                         Ref: CVE-2009-3555, RFC 5746
#   Sin PQC KEX       →  AV:N/AC:H/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N  (4.8 MEDIUM)
#                         Ref: FIPS 203 (ML-KEM), NIST IR 8545
#   Sin PQC firma     →  AV:N/AC:H/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N  (5.3 MEDIUM)
#                         Ref: FIPS 204 (ML-DSA), NIST IR 8413
# -----------------------------------------------------------------------
CVSS_MAP = {
    "SSLv2 enabled":          {"score40": 9.8, "vector40": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H",
                               "score31": 9.8, "vector31": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "severity": "CRITICAL"},
    "SSLv3 enabled":          {"score40": 9.8, "vector40": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H",
                               "score31": 9.8, "vector31": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "severity": "CRITICAL"},
    "TLSv1.0 enabled":        {"score40": 7.4, "vector40": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L",
                               "score31": 7.5, "vector31": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "severity": "HIGH"},
    "TLSv1.1 enabled":        {"score40": 7.4, "vector40": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L",
                               "score31": 7.5, "vector31": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "severity": "HIGH"},
    "TLSv1.3 disabled":       {"score40": 5.9, "vector40": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N",
                               "score31": 5.9, "vector31": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", "severity": "MEDIUM"},
    "heartbleed vulnerable":  {"score40": 7.5, "vector40": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N",
                               "score31": 7.5, "vector31": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "severity": "HIGH"},
    "insecure renegotiation": {"score40": 6.8, "vector40": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N",
                               "score31": 6.8, "vector31": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", "severity": "MEDIUM"},
    "no_pqc_kex":             {"score40": 4.8, "vector40": "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N",
                               "score31": 4.8, "vector31": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N", "severity": "MEDIUM"},
    "no_pqc_sig":             {"score40": 5.3, "vector40": "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N",
                               "score31": 5.3, "vector31": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N", "severity": "MEDIUM"},
}

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
    if l.startswith("Version:"):
        return f"Version: {Fore.GREEN}{l.replace('Version:', '').strip()}{Style.RESET_ALL}"
    for t in TITULOS_CYAN:
        if t in l:
            return f"{Fore.CYAN}{Style.BRIGHT}{l}"

    # 2. Heartbleed (antes que protocolos para evitar falsos positivos)
    if "to heartbleed" in l:
        c = Fore.GREEN if "not vulnerable" in l else Fore.RED + Style.BRIGHT
        return l.replace("not vulnerable", f"{c}not vulnerable{Style.RESET_ALL}").replace("vulnerable", f"{c}vulnerable{Style.RESET_ALL}")

    # 3. Cifrados y PQC (antes que protocolos)
    if any(l.startswith(x) for x in ["Accepted", "Preferred"]):
        l = l.replace("Preferred", f"{Fore.GREEN}Preferred{Style.RESET_ALL}")
        l = re.sub(r"(\d{3,4} bits)", f"{Fore.GREEN}\\1{Style.RESET_ALL}", l)
        l = re.sub(r"\b(TLS_[A-Z0-9_]+|ECDHE-[A-Z0-9-]+|X25519MLKEM\d+|MLKEM\d+|Kyber\d+)\b",
                   f"{Fore.GREEN}\\1{Style.RESET_ALL}", l)
        return l

    # 4. Lógica de Protocolos (solo líneas simples como "SSLv2     enabled")
    # SSLv2, SSLv3, TLSv1.0, TLSv1.1 -> ROJO si están 'enabled'
    # TLSv1.2, TLSv1.3 -> VERDE si están 'enabled'
    p_inseguros = ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"]
    p_seguros = ["TLSv1.2", "TLSv1.3"]
    es_protocolo = lambda t: (t in l) and ("disabled" in l or "enabled" in l) \
                             and not l.startswith("Accepted") and not l.startswith("Preferred")

    for p in p_inseguros:
        if es_protocolo(p):
            l = l.replace("disabled", f"{Fore.GREEN}disabled{Style.RESET_ALL}")
            l = l.replace("enabled", f"{Fore.RED}{Style.BRIGHT}enabled{Style.RESET_ALL}")
            return l
    for p in p_seguros:
        if es_protocolo(p):
            l = l.replace("disabled", f"{Fore.RED}disabled{Style.RESET_ALL}")
            l = l.replace("enabled", f"{Fore.GREEN}enabled{Style.RESET_ALL}")
            return l

    return l

# --- [MOTOR DE AUDITORÍA Y CUMPLIMIENTO] ---

def ejecutar_auditoria_v34(texto_analizar, target_id):
    """Genera el reporte de cumplimiento técnico estructurado."""
    ts_actual = datetime.now()
    
    def print_h(item, status, ref="", motivo="", evidencia="", accion=""):
        if any(x in status for x in ["Buena config", "Vanguardia", "No vulnerable", "Confiable", "Vigente", "Correcto"]):
            color = Fore.GREEN + Style.BRIGHT
        elif any(x in status for x in ["No cumple", "VULNERABLE", "Riesgo", "Legado", "Inseguro"]):
            color = Fore.RED + Style.BRIGHT
        else:
            color = Fore.YELLOW
            
        print(f"{item:45} | {color}{status}")
        if ref: print(f"    {Fore.WHITE}Referencia: {ref}")
        if motivo: print(f"    {Fore.WHITE}{Style.DIM}└─ {motivo}")
        if evidencia: print(f"    {Fore.BLUE}{Style.NORMAL}└─ Evidencia: {evidencia}")
        if accion: print(f"    {Fore.MAGENTA}{Style.BRIGHT}└─ ACCIÓN REQUERIDA: {accion}")

    print(f"\n{Fore.MAGENTA}{'='*95}")
    print(f"INFORME TÉCNICO DE AUDITORÍA SSL {VERSION} | TARGET: {target_id}")
    print(f"Fecha de análisis: {ts_actual.strftime('%d-%m-%Y %H:%M:%S')}")
    print(f"{Fore.MAGENTA}{'='*95}")

    # --- SECCIÓN: POST-QUANTUM (FIPS 203/204) ---
    print(f"\n{Fore.CYAN}>>> Prueba de Preparación Post-Cuántica (PQC) FIPS 203/204 ".ljust(95, "-"))
    kex = re.search(r"(X25519MLKEM\d+|MLKEM\d+|Kyber\d+)", texto_analizar, re.I)
    print_h("Intercambio de Claves Híbrido ML-KEM", "Vanguardia" if kex else "No cumple", 
            ref="FIPS 203", motivo="Mitigación de ataques de retro-descifrado (Harvest-now).",
            evidencia=kex.group(1) if kex else "Criptografía asimétrica clásica detectada.")

    sig = re.search(r"Signature Algorithm:\s+(.*)", texto_analizar)
    alg_str = sig.group(1).strip() if sig else "RSA/Classic"
    is_pqc_sig = not any(x in alg_str.lower() for x in ["rsa", "sha256", "ecdsa"])
    print_h("Firma Digital PQC (ML-DSA)", "Vanguardia" if is_pqc_sig else "No cumple con NIST",
            ref="FIPS 204", motivo=f"Algoritmo {alg_str} vulnerable al algoritmo de Shor.",
            evidencia=alg_str, accion="Migrar a ML-DSA en la próxima renovación de certificados.")

    # --- SECCIÓN: PCI DSS 4.0.1 ---
    print(f"\n{Fore.CYAN}>>> Prueba de Cumplimiento PCI DSS 4.0.1 ".ljust(95, "-"))
    issuer = re.search(r"Issuer:\s+(.*)", texto_analizar)
    print_h("Certificados Confiables", "Confiable" if issuer else "No cumple", 
            ref="PCI DSS 4.2", evidencia=f"CA Emisora: {issuer.group(1).strip() if issuer else 'Desconocida'}")

    hb = "vulnerable to heartbleed" in texto_analizar.lower() and "not vulnerable" not in texto_analizar.lower()
    print_h("Vulnerabilidad: HEARTBLEED", "No vulnerable" if not hb else "VULNERABLE",
            ref="CVE-2014-0160", motivo="Fuga de memoria en memoria del servidor.")

    reneg = "Insecure client-initiated renegotiation" in texto_analizar and "not supported" not in texto_analizar
    print_h("Renegociación Segura", "Buena configuración" if not reneg else "Riesgo", 
            ref="RFC 5746", motivo="Protección contra inyección de datos durante el apretón de manos.")

    # --- SECCIÓN: NIST & MEJORES PRÁCTICAS ---
    print(f"\n{Fore.CYAN}>>> Prueba NIST SP 800-52 y Mejores Prácticas ".ljust(95, "-"))
    tls13_match = re.search(r"TLSv1\.3\s+(\w+)", texto_analizar)
    tls13_on = tls13_match and tls13_match.group(1) == "enabled"
    print_h("TLS 1.3 Soportado", "Correcto" if tls13_on else "Legado / Riesgo", 
            ref="NIST SP 800-52 Rev.2", motivo="Recomendado por NIST para confidencialidad persistente.")

    try:
        exp = re.search(r"Not valid after:\s+(.*) GMT", texto_analizar)
        if exp:
            f_exp = datetime.strptime(exp.group(1).strip(), "%b %d %H:%M:%S %Y")
            dias = (f_exp - ts_actual).days
            print_h("Vigencia del Certificado", "Vigente" if dias > 0 else "Expirado",
                    ref="PCI DSS 4.0.1 req.", motivo=f"Vencimiento: {f_exp.strftime('%d-%m-%Y')}", evidencia=f"{dias} días restantes.")
    except: pass

    # --- RESUMEN EJECUTIVO CON CVSS ---
    print(f"\n{Fore.CYAN}>>> Resumen Ejecutivo de Riesgo (CVSS 4.0 / 3.1) ".ljust(95, "-"))
    hallazgos = []
    riesgo_total = 0.0
    max_score = 0.0

    for proto in ["SSLv2", "SSLv3"]:
        if f"{proto}     enabled" in texto_analizar:
            hallazgos.append(("CRITICAL", proto, CVSS_MAP["SSLv2 enabled"]))
            riesgo_total += 9.8; max_score = max(max_score, 9.8)

    for proto in ["TLSv1.0", "TLSv1.1"]:
        if f"{proto}   enabled" in texto_analizar or f"{proto}  enabled" in texto_analizar:
            hallazgos.append(("HIGH", proto, CVSS_MAP["TLSv1.0 enabled"]))
            riesgo_total += 7.4; max_score = max(max_score, 7.4)

    if "TLSv1.3   disabled" in texto_analizar:
        hallazgos.append(("MEDIUM", "TLS 1.3 no habilitado", CVSS_MAP["TLSv1.3 disabled"]))
        riesgo_total += 5.9; max_score = max(max_score, 5.9)

    if "vulnerable to heartbleed" in texto_analizar.lower() and "not vulnerable" not in texto_analizar.lower():
        hallazgos.append(("HIGH", "Heartbleed", CVSS_MAP["heartbleed vulnerable"]))
        riesgo_total += 7.5; max_score = max(max_score, 7.5)

    if "Insecure client-initiated renegotiation" in texto_analizar and "not supported" not in texto_analizar:
        hallazgos.append(("MEDIUM", "Renegociación insegura", CVSS_MAP["insecure renegotiation"]))
        riesgo_total += 6.8; max_score = max(max_score, 6.8)

    if not kex:
        hallazgos.append(("MEDIUM", "Sin KEX Post-Cuántico", CVSS_MAP["no_pqc_kex"]))
        riesgo_total += 4.8; max_score = max(max_score, 4.8)

    if not is_pqc_sig:
        hallazgos.append(("MEDIUM", "Sin firma Post-Cuántica", CVSS_MAP["no_pqc_sig"]))
        riesgo_total += 5.3; max_score = max(max_score, 5.3)

    for severity, finding, info in hallazgos:
        color_tag = Fore.RED if severity == "CRITICAL" else (Fore.YELLOW if severity == "HIGH" else Fore.CYAN)
        print(f"  {color_tag}[{severity}]{Style.RESET_ALL} {finding:40}")
        print(f"    CVSS 4.0: {info['score40']} | {info['vector40']}")
        print(f"    CVSS 3.1: {info['score31']} | {info['vector31']}")

    riesgo_normalizado = min(riesgo_total / 10.0, 10.0)
    nivel = "BAJO" if riesgo_normalizado < 4 else ("MEDIO" if riesgo_normalizado < 7 else "ALTO")
    color_nivel = Fore.GREEN if nivel == "BAJO" else (Fore.YELLOW if nivel == "MEDIO" else Fore.RED)

    print(f"\n  {'Score de Riesgo Acumulado:' :50} {color_nivel}{riesgo_normalizado:.1f}/10 ({nivel}){Style.RESET_ALL}")
    print(f"  {'Hallazgos Críticos:' :50} {Fore.RED}{sum(1 for s,_,_ in hallazgos if s=='CRITICAL')}{Style.RESET_ALL}")
    print(f"  {'Hallazgos Altos:' :50} {Fore.YELLOW}{sum(1 for s,_,_ in hallazgos if s=='HIGH')}{Style.RESET_ALL}")
    print(f"  {'Hallazgos Medios:' :50} {Fore.CYAN}{sum(1 for s,_,_ in hallazgos if s=='MEDIUM')}{Style.RESET_ALL}")
    print(f"  {'Referencia CVSS 4.0:' :50} https://www.first.org/cvss/calculator/4.0")
    print(f"  {'Referencia CVSS 3.1:' :50} https://www.first.org/cvss/calculator/3.1")
    print(f"\n{Fore.MAGENTA}{'='*95}\n")

    return hallazgos, riesgo_normalizado, nivel


# --- [GENERADOR DE CURLS PARA PRUEBAS SSL] ---

def generar_curls(target, folder=""):
    """Genera comandos curl para verificación manual de SSL/TLS."""
    target_clean = target.replace("https://", "").replace("http://", "").split("/")[0]
    curls = {
        "meta": {
            "target": target_clean,
            "generado": datetime.now(timezone.utc).isoformat(),
            "herramienta": f"Scan_SSL {VERSION}",
            "propósito": "Comandos curl para verificación manual de SSL/TLS"
        },
        "comandos": [
            {
                "id": "01",
                "descripcion": "Handshake SSL básico (verbose)",
                "comando": f"curl -vI https://{target_clean} 2>&1"
            },
            {
                "id": "02",
                "descripcion": "Forzar TLS 1.2 (excluye 1.3/1.1/1.0)",
                "comando": f"curl --tlsv1.2 --tls-max 1.2 -vI https://{target_clean} 2>&1"
            },
            {
                "id": "03",
                "descripcion": "Forzar TLS 1.3 (excluye 1.2/1.1/1.0)",
                "comando": f"curl --tlsv1.3 --tls-max 1.3 -vI https://{target_clean} 2>&1"
            },
            {
                "id": "04",
                "descripcion": "Ver cadena de certificados completa",
                "comando": f"openssl s_client -connect {target_clean}:443 -showcerts < /dev/null 2>/dev/null | openssl x509 -text -noout"
            },
            {
                "id": "05",
                "descripcion": "Cifrados soportados (nmap)",
                "comando": f"nmap --script ssl-enum-ciphers -p 443 {target_clean}"
            },
            {
                "id": "06",
                "descripcion": "Heartbleed check (nmap)",
                "comando": f"nmap --script ssl-heartbleed -p 443 {target_clean}"
            },
            {
                "id": "07",
                "descripcion": "Fecha de expiración del certificado",
                "comando": f"echo | openssl s_client -connect {target_clean}:443 -servername {target_clean} 2>/dev/null | openssl x509 -noout -dates"
            },
            {
                "id": "08",
                "descripcion": "TODO: Protocolos y cifrados (curl + openssl)",
                "comando": f"for v in ssl2 ssl3 tls1 tls1_1 tls1_2 tls1_3; do echo \"=== $v ===\"; curl --$v -vI https://{target_clean} 2>&1 | grep -E \"(SSL connection|error|alert)\"; done"
            },
        ]
    }

    # Salida a pantalla
    print(f"\n{Fore.CYAN}{Style.BRIGHT}╔{'═'*70}╗")
    print(f"║{'CURL COMPATIBLES — VERIFICACIÓN MANUAL SSL/TLS':^70}║")
    print(f"║{'Target: ' + target_clean:^70}║")
    print(f"╚{'═'*70}╝{Style.RESET_ALL}")
    for cmd in curls["comandos"]:
        print(f"\n{Fore.YELLOW}[{cmd['id']}]{Style.RESET_ALL} {cmd['descripcion']}")
        print(f"  {Fore.GREEN}$ {cmd['comando']}{Style.RESET_ALL}")

    # Persistencia
    if folder:
        ruta_curl = os.path.join(folder, "CURLS_SSL.json")
        with open(ruta_curl, "w", encoding="utf-8") as f:
            json.dump(curls, f, indent=2, ensure_ascii=False)
        print(f"\n{Fore.GREEN}[✔] Curls exportados: {ruta_curl}{Style.RESET_ALL}")

    return curls


# --- [EXPORTACIÓN DE HALLAZGOS A JSON] ---

def exportar_findings_json(hallazgos, riesgo_normalizado, nivel, target_id, folder, raw_text=""):
    """Exporta findings estructurados a JSON para integración con otras herramientas."""
    ts = datetime.now(timezone.utc).isoformat()
    issuer = re.search(r"Issuer:\s+(.*)", raw_text)
    exp = re.search(r"Not valid after:\s+(.*) GMT", raw_text)
    cert_data = {}
    if exp:
        try:
            f_exp = datetime.strptime(exp.group(1).strip(), "%b %d %H:%M:%S %Y")
            cert_data["valido_hasta"] = f_exp.isoformat()
            cert_data["dias_restantes"] = (f_exp - datetime.now()).days
        except:
            pass
    if issuer:
        cert_data["emisor"] = issuer.group(1).strip()

    findings_json = {
        "herramienta": f"Scan_SSL {VERSION}",
        "target": target_id,
        "timestamp": ts,
        "riesgo": {
            "score_normalizado": round(riesgo_normalizado, 1),
            "nivel": nivel,
        },
        "certificado": cert_data,
        "hallazgos": [],
    }

    for severity, finding, info in hallazgos:
        findings_json["hallazgos"].append({
            "severidad": severity,
            "hallazgo": finding,
            "cvss40": {"score": info["score40"], "vector": info["vector40"]},
            "cvss31": {"score": info["score31"], "vector": info["vector31"]},
        })

    ruta_json = os.path.join(folder, "FINDINGS_SSL.json")
    with open(ruta_json, "w", encoding="utf-8") as f:
        json.dump(findings_json, f, indent=2, ensure_ascii=False)
    print(f"{Fore.GREEN}[✔] Findings exportados: {ruta_json}{Style.RESET_ALL}")


# --- [FLUJO DE CONTROL] ---

def main():
    parser = argparse.ArgumentParser(
        prog="Scan_SSL",
        description=f"SCAN SSL {VERSION} — Auditor de seguridad SSL/TLS con PQC y cumplimiento normativo.",
        epilog="Documentación: https://github.com/apuromafo/Repositorio_Python/tree/main/069_SSL_Scan",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-t", "--target", help="Dominio o IP a escanear (ej: example.com)")
    parser.add_argument("-f", "--file", help="Carga de evidencia offline (ruta a carpeta con EVIDENCIA_SSLSCAN.log)")
    parser.add_argument("-c", "--curl", action="store_true", help="Genera comandos curl compatibles para verificación manual SSL/TLS")
    parser.add_argument("-V", "--version", action="version", version=f"%(prog)s {VERSION}")
    args = parser.parse_args()

    content = ""

    if args.file:
        log_path = os.path.join(args.file, "EVIDENCIA_SSLSCAN.log")
        if os.path.exists(log_path):
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                for linea in f:
                    content += linea
                    print(render_log_line(linea))
            hallazgos, riesgo, nivel = ejecutar_auditoria_v34(content, args.file)
            exportar_findings_json(hallazgos, riesgo, nivel, args.file, args.file, raw_text=content)
            if args.curl:
                generar_curls(args.file, folder=args.file)
        else:
            print(f"{Fore.RED}[✘] No se encontró evidencia en la ruta especificada.")
        return

    if args.target:
        if not provisionar_binario(): return
        print(f"{Fore.YELLOW}[*] Ejecutando análisis técnico sobre {args.target}...")
        
        proc = subprocess.run([SSLSCAN_BINARY, "--no-colour", args.target], capture_output=True, text=True)
        
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        folder = os.path.join(RAIZ_RESULTADOS, f"{args.target.replace('.','_')}_{stamp}")
        os.makedirs(folder, exist_ok=True)
        
        with open(os.path.join(folder, "EVIDENCIA_SSLSCAN.log"), "w", encoding='utf-8') as f:
            f.write(proc.stdout)
        
        for linea in proc.stdout.splitlines():
            print(render_log_line(linea))
            
        hallazgos, riesgo, nivel = ejecutar_auditoria_v34(proc.stdout, args.target)
        exportar_findings_json(hallazgos, riesgo, nivel, args.target, folder, raw_text=proc.stdout)

        if args.curl:
            generar_curls(args.target, folder=folder)

        ts_resumen = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
        print(f"\n{Fore.CYAN}{Style.BRIGHT}╔{'═'*70}╗")
        print(f"║{'RESUMEN DE LA EJECUCIÓN':^70}║")
        print(f"╠{'═'*70}╣")
        print(f"║ {'Target:':30} {args.target:<37} ║")
        print(f"║ {'Fecha:':30} {ts_resumen:<37} ║")
        print(f"║ {'Estado:':30} {Fore.GREEN}{'COMPLETADO':<37}{Style.RESET_ALL} ║")
        print(f"║ {'Evidencia:':30} {folder:<37} ║")
        archivos = os.listdir(folder)
        for a in archivos:
            print(f"║ {'':30} {Fore.YELLOW}├─ {a:<35}{Style.RESET_ALL} ║")
        print(f"╚{'═'*70}╝{Style.RESET_ALL}")
    else:
        print(f"\n{Fore.CYAN}{Style.BRIGHT}╔{'═'*70}╗")
        print(f"║{'SCAN SSL ' + VERSION + ' — AUDITOR DE SEGURIDAD SSL/TLS':^70}║")
        print(f"║{'PCI DSS 4.0.1 | NIST SP 800-52 | FIPS 203/204 | CVSS 4.0/3.1':^70}║")
        print(f"╚{'═'*70}╝{Style.RESET_ALL}")
        print(f"\n  {Fore.GREEN}Uso:{Style.RESET_ALL} python Scan_ssl_v3.py -t <dominio>")
        print(f"  {Fore.GREEN}Ej:{Style.RESET_ALL}  python Scan_ssl_v3.py -t example.com")
        print(f"  {Fore.GREEN}Offline:{Style.RESET_ALL} python Scan_ssl_v3.py -f ./Resultados_SSL/example_20260625_120000")
        print(f"  {Fore.GREEN}Info:{Style.RESET_ALL}  python Scan_ssl_v3.py -h")
        print(f"  {Fore.GREEN}Versión:{Style.RESET_ALL} python Scan_ssl_v3.py --version\n")

if __name__ == "__main__":
    main()