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
import platform
import urllib.request
import urllib.error
import zipfile
import tarfile
import shutil
import io
from datetime import datetime, timezone
from colorama import init, Fore, Style, Back

init(autoreset=True)

if sys.stdout.encoding and sys.stdout.encoding.upper() not in ("UTF-8", "UTF8"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

VERSION = "v34.1"

# -----------------------------------------------------------------------
# SISTEMA DE IDIOMAS (ES/EN)
# -----------------------------------------------------------------------
LANG = "es"

TR = {
    "es": {
        "vanguardia": "Vanguardia",
        "no_cumple": "No cumple",
        "no_cumple_nist": "No cumple con NIST",
        "confiable": "Confiable",
        "no_vulnerable": "No vulnerable",
        "vulnerable": "VULNERABLE",
        "buena_config": "Buena configuración",
        "riesgo": "Riesgo",
        "correcto": "Correcto",
        "legado_riesgo": "Legado / Riesgo",
        "vigente": "Vigente",
        "expirado": "Expirado",
        "header_auditoria": "INFORME TÉCNICO DE AUDITORÍA SSL",
        "header_pqc": ">>> Prueba de Preparación Post-Cuántica (PQC) FIPS 203/204",
        "header_pci": ">>> Prueba de Cumplimiento PCI DSS 4.0.1",
        "header_nist": ">>> Prueba NIST SP 800-52 y Mejores Prácticas",
        "header_cvss": ">>> Resumen Ejecutivo de Riesgo (CVSS 4.0 / 3.1)",
        "item_kex": "Intercambio de Claves Híbrido ML-KEM",
        "item_firma": "Firma Digital PQC (ML-DSA)",
        "item_certs": "Certificados Confiables",
        "item_heartbleed": "Vulnerabilidad: HEARTBLEED",
        "item_reneg": "Renegociación Segura",
        "item_tls13": "TLS 1.3 Soportado",
        "item_vigencia": "Vigencia del Certificado",
        "ref": "Referencia",
        "evidencia": "Evidencia",
        "accion": "ACCIÓN REQUERIDA",
        "motivo_harvest": "Mitigación de ataques de retro-descifrado (Harvest-now).",
        "motivo_shor": "Algoritmo {algo} vulnerable al algoritmo de Shor.",
        "motivo_heartbleed": "Fuga de memoria en memoria del servidor.",
        "motivo_reneg": "Protección contra inyección de datos durante el apretón de manos.",
        "motivo_tls13": "Recomendado por NIST para confidencialidad persistente.",
        "accion_ml_dsa": "Migrar a ML-DSA en la próxima renovación de certificados.",
        "ref_fips203": "FIPS 203",
        "ref_fips204": "FIPS 204",
        "ref_pci": "PCI DSS 4.2",
        "ref_cve_heartbleed": "CVE-2014-0160",
        "ref_rfc5746": "RFC 5746",
        "ref_nist52": "NIST SP 800-52 Rev.2",
        "ref_pci_req": "PCI DSS 4.0.1 req.",
        "evidencia_clasica": "Criptografía asimétrica clásica detectada.",
        "score_riesgo": "Score de Riesgo Acumulado:",
        "hallazgos_criticos": "Hallazgos Críticos:",
        "hallazgos_altos": "Hallazgos Altos:",
        "hallazgos_medios": "Hallazgos Medios:",
        "ref_cvss40": "Referencia CVSS 4.0:",
        "ref_cvss31": "Referencia CVSS 3.1:",
        "bajo": "BAJO",
        "medio": "MEDIO",
        "alto": "ALTO",
        "provision_ok": "Binario sslscan listo.",
        "provision_desc": "Descargando sslscan {ver}...",
        "provision_error": "Error crítico de provisión: {e}",
        "analizando": "Ejecutando análisis técnico sobre {target}...",
        "no_evidencia": "No se encontró evidencia en la ruta especificada.",
        "findings_export": "Findings exportados",
        "curls_export": "Curls exportados",
        "resumen_ejecucion": "RESUMEN DE LA EJECUCIÓN",
        "target": "Target:",
        "fecha": "Fecha:",
        "estado": "Estado:",
        "completado": "COMPLETADO",
        "evidencia": "Evidencia:",
        "banner_titulo": "SCAN SSL {ver} — AUDITOR DE SEGURIDAD SSL/TLS",
        "banner_linea2": "PCI DSS 4.0.1 | NIST SP 800-52 | FIPS 203/204 | CVSS 4.0/3.1",
        "uso": "Uso:",
        "ejemplo": "Ej:",
        "offline": "Offline:",
        "info": "Info:",
        "version": "Versión:",
        "disclaimer_title": "⚠  AVISO LEGAL / LEGAL NOTICE",
        "disclaimer_auth": "Este escaneo debe realizarse ÚNICAMENTE con autorización explícita del propietario o con fines educativos en entornos controlados.",
        "disclaimer_no_perjuicio": "El uso indebido de esta herramienta es responsabilidad exclusiva del usuario. No nos hacemos responsables por daños o perjuicios.",
        "disclaimer_cvss": "Las puntuaciones CVSS 4.0 y 3.1 son REFERENCIALES, asignadas por analogía con CVE documentados (fuentes: FIRST.org CVSS v4.0 y v3.1 Specification Documents).",
    },
    "en": {
        "vanguardia": "Vanguard",
        "no_cumple": "Non-compliant",
        "no_cumple_nist": "Non-compliant with NIST",
        "confiable": "Trusted",
        "no_vulnerable": "Not vulnerable",
        "vulnerable": "VULNERABLE",
        "buena_config": "Good configuration",
        "riesgo": "Risk",
        "correcto": "OK",
        "legado_riesgo": "Legacy / Risk",
        "vigente": "Valid",
        "expirado": "Expired",
        "header_auditoria": "SSL AUDIT TECHNICAL REPORT",
        "header_pqc": ">>> Post-Quantum Cryptography (PQC) Readiness Test FIPS 203/204",
        "header_pci": ">>> PCI DSS 4.0.1 Compliance Test",
        "header_nist": ">>> NIST SP 800-52 & Best Practices Test",
        "header_cvss": ">>> Executive Risk Summary (CVSS 4.0 / 3.1)",
        "item_kex": "Hybrid ML-KEM Key Exchange",
        "item_firma": "PQC Digital Signature (ML-DSA)",
        "item_certs": "Certificates are Trusted",
        "item_heartbleed": "Vulnerability: HEARTBLEED",
        "item_reneg": "Secure Renegotiation",
        "item_tls13": "TLS 1.3 Supported",
        "item_vigencia": "Certificate Validity",
        "ref": "Reference",
        "evidencia": "Evidence",
        "accion": "REQUIRED ACTION",
        "motivo_harvest": "Mitigation of Harvest-now decrypt attacks.",
        "motivo_shor": "Algorithm {algo} vulnerable to Shor's algorithm.",
        "motivo_heartbleed": "Memory leak in server memory.",
        "motivo_reneg": "Protection against data injection during handshake.",
        "motivo_tls13": "Recommended by NIST for forward secrecy.",
        "accion_ml_dsa": "Migrate to ML-DSA on next certificate renewal.",
        "ref_fips203": "FIPS 203",
        "ref_fips204": "FIPS 204",
        "ref_pci": "PCI DSS 4.2",
        "ref_cve_heartbleed": "CVE-2014-0160",
        "ref_rfc5746": "RFC 5746",
        "ref_nist52": "NIST SP 800-52 Rev.2",
        "ref_pci_req": "PCI DSS 4.0.1 req.",
        "evidencia_clasica": "Classic asymmetric cryptography detected.",
        "score_riesgo": "Accumulated Risk Score:",
        "hallazgos_criticos": "Critical Findings:",
        "hallazgos_altos": "High Findings:",
        "hallazgos_medios": "Medium Findings:",
        "ref_cvss40": "CVSS 4.0 Reference:",
        "ref_cvss31": "CVSS 3.1 Reference:",
        "bajo": "LOW",
        "medio": "MEDIUM",
        "alto": "HIGH",
        "provision_ok": "sslscan binary ready.",
        "provision_desc": "Downloading sslscan {ver}...",
        "provision_error": "Critical provisioning error: {e}",
        "analizando": "Running technical analysis on {target}...",
        "no_evidencia": "No evidence log found at specified path.",
        "findings_export": "Findings exported",
        "curls_export": "Curls exported",
        "resumen_ejecucion": "EXECUTION SUMMARY",
        "target": "Target:",
        "fecha": "Date:",
        "estado": "Status:",
        "completado": "COMPLETED",
        "evidencia": "Evidence:",
        "banner_titulo": "SCAN SSL {ver} — SSL/TLS SECURITY AUDITOR",
        "banner_linea2": "PCI DSS 4.0.1 | NIST SP 800-52 | FIPS 203/204 | CVSS 4.0/3.1",
        "uso": "Usage:",
        "ejemplo": "Example:",
        "offline": "Offline:",
        "info": "Info:",
        "version": "Version:",
        "disclaimer_title": "⚠  LEGAL NOTICE / AVISO LEGAL",
        "disclaimer_auth": "This scan MUST only be performed with explicit authorization from the owner or for educational purposes in controlled environments.",
        "disclaimer_no_perjuicio": "Misuse of this tool is the sole responsibility of the user. We are not liable for any damages or harm.",
        "disclaimer_cvss": "CVSS 4.0 and 3.1 scores are REFERENTIAL, assigned by analogy with documented CVEs (sources: FIRST.org CVSS v4.0 and v3.1 Specification Documents).",
    }
}

def _(key, **kwargs):
    t = TR.get(LANG, TR["es"]).get(key, key)
    if kwargs:
        t = t.format(**kwargs)
    return t


# --- [CONFIGURACIÓN Y RUTAS] ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SISTEMA = platform.system()
ARQUITECTURA = platform.machine().lower()
ES_WINDOWS = SISTEMA == "Windows"
BIN_EXT = ".exe" if ES_WINDOWS else ""
TOOLS_BASE = os.path.join(BASE_DIR, "tools", "sslscan")
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

def obtener_ultima_version_sslscan():
    """Obtiene la última versión de sslscan desde GitHub API."""
    url = "https://api.github.com/repos/rbsec/sslscan/releases/latest"
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Scan_SSL/1.0', 'Accept': 'application/vnd.github.v3+json'})
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read().decode("utf-8"))
            tag = data.get("tag_name", "")
            assets = data.get("assets", [])
            return tag.lstrip("v"), assets
    except Exception as e:
        return "2.2.2", []

def provisionar_binario():
    """Garantiza la disponibilidad de sslscan (multiplataforma)."""
    global SSLSCAN_BIN, SSLSCAN_VER
    fallback_ver = "2.2.2"
    fallback_dir = os.path.join(TOOLS_BASE, fallback_ver)
    fallback_bin = os.path.join(fallback_dir, f"sslscan{BIN_EXT}")
    if os.path.exists(fallback_bin):
        SSLSCAN_BIN = fallback_bin
        SSLSCAN_VER = fallback_ver
        print(f"{Fore.GREEN}[✔] {_('provision_ok')} ({fallback_ver}){Style.RESET_ALL}")
        return True

    tag_ver, assets = obtener_ultima_version_sslscan()
    SSLSCAN_VERSION = tag_ver
    SSLSCAN_DIR = os.path.join(TOOLS_BASE, SSLSCAN_VERSION)
    SSLSCAN_BINARY = os.path.join(SSLSCAN_DIR, f"sslscan{BIN_EXT}")
    SSLSCAN_BIN = SSLSCAN_BINARY
    SSLSCAN_VER = SSLSCAN_VERSION

    if os.path.exists(SSLSCAN_BINARY):
        print(f"{Fore.GREEN}[✔] {_('provision_ok')} ({SSLSCAN_VERSION}){Style.RESET_ALL}")
        return True

    os.makedirs(SSLSCAN_DIR, exist_ok=True)
    print(f"{Fore.YELLOW}[*] {_('provision_desc', ver=SSLSCAN_VERSION)}...{Style.RESET_ALL}")

    download_url = None
    for a in assets:
        name = a.get("name", "")
        if ES_WINDOWS and name.endswith(".zip") and "win" in name.lower():
            download_url = a.get("browser_download_url")
            break
        elif not ES_WINDOWS and name.endswith(".tgz"):
            download_url = a.get("browser_download_url")
            break

    if not download_url:
        fallback = "2.2.2"
        base = "https://github.com/rbsec/sslscan/releases/download"
        if ES_WINDOWS:
            download_url = f"{base}/{fallback}/sslscan-{fallback}.zip"
        else:
            download_url = f"{base}/{fallback}/sslscan-{fallback}.tgz"

    try:
        req = urllib.request.Request(download_url, headers={'User-Agent': 'Mozilla/5.0'})
        archivo_temp = os.path.join(SSLSCAN_DIR, "temp" + (".zip" if download_url.endswith(".zip") else ".tgz"))
        with urllib.request.urlopen(req, timeout=60) as r, open(archivo_temp, 'wb') as f:
            f.write(r.read())

        if archivo_temp.endswith(".zip"):
            with zipfile.ZipFile(archivo_temp, 'r') as z:
                z.extractall(SSLSCAN_DIR)
        else:
            with tarfile.open(archivo_temp, 'r:gz') as t:
                t.extractall(SSLSCAN_DIR)

        for root, dirs, files in os.walk(SSLSCAN_DIR):
            for fname in files:
                if fname == f"sslscan{BIN_EXT}" or fname == "sslscan":
                    src = os.path.join(root, fname)
                    if src != SSLSCAN_BINARY:
                        shutil.move(src, SSLSCAN_BINARY)
                    break

        if not ES_WINDOWS and os.path.exists(SSLSCAN_BINARY):
            os.chmod(SSLSCAN_BINARY, 0o755)

        if os.path.exists(archivo_temp):
            os.remove(archivo_temp)

        print(f"{Fore.GREEN}[✔] {_('provision_ok')} ({SSLSCAN_VERSION}){Style.RESET_ALL}")
        return True
    except Exception as e:
        print(f"{Fore.RED}[✘] {_('provision_error', e=e)}{Style.RESET_ALL}")
        SSLSCAN_BIN = None
        return False


SSLSCAN_BIN = None
SSLSCAN_VER = "desconocida"

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
        ok_statuses = [_("buena_config"), _("vanguardia"), _("no_vulnerable"), _("confiable"), _("vigente"), _("correcto")]
        bad_statuses = [_("no_cumple"), _("vulnerable"), _("riesgo"), _("legado_riesgo"), "Inseguro"]
        if any(x in status for x in ok_statuses):
            color = Fore.GREEN + Style.BRIGHT
        elif any(x in status for x in bad_statuses):
            color = Fore.RED + Style.BRIGHT
        else:
            color = Fore.YELLOW
            
        print(f"{item:45} | {color}{status}")
        if ref: print(f"    {Fore.WHITE}{_('ref')}: {ref}")
        if motivo: print(f"    {Fore.WHITE}{Style.DIM}└─ {motivo}")
        if evidencia: print(f"    {Fore.BLUE}{Style.NORMAL}└─ {_('evidencia')}: {evidencia}")
        if accion: print(f"    {Fore.MAGENTA}{Style.BRIGHT}└─ {_('accion')}: {accion}")

    print(f"\n{Fore.MAGENTA}{'='*95}")
    print(f"{_('header_auditoria')} {VERSION} | TARGET: {target_id}")
    tsf = ts_actual.strftime('%d-%m-%Y %H:%M:%S')
    print(f"Fecha: {tsf}" if LANG == "es" else f"Date: {tsf}")
    print(f"{Fore.MAGENTA}{'='*95}")

    # --- SECCIÓN: POST-QUANTUM (FIPS 203/204) ---
    print(f"\n{Fore.CYAN}{_('header_pqc')} ".ljust(95, "-"))
    kex = re.search(r"(X25519MLKEM\d+|MLKEM\d+|Kyber\d+)", texto_analizar, re.I)
    print_h(_("item_kex"), _("vanguardia") if kex else _("no_cumple"),
            ref=_("ref_fips203"), motivo=_("motivo_harvest"),
            evidencia=kex.group(1) if kex else _("evidencia_clasica"))

    sig = re.search(r"Signature Algorithm:\s+(.*)", texto_analizar)
    alg_str = sig.group(1).strip() if sig else (LANG == "es" and "RSA/Classic" or "RSA/Classic")
    is_pqc_sig = not any(x in alg_str.lower() for x in ["rsa", "sha256", "ecdsa"])
    print_h(_("item_firma"), _("vanguardia") if is_pqc_sig else _("no_cumple_nist"),
            ref=_("ref_fips204"), motivo=_("motivo_shor", algo=alg_str),
            evidencia=alg_str, accion=_("accion_ml_dsa"))

    # --- SECCIÓN: PCI DSS 4.0.1 ---
    print(f"\n{Fore.CYAN}{_('header_pci')} ".ljust(95, "-"))
    issuer = re.search(r"Issuer:\s+(.*)", texto_analizar)
    print_h(_("item_certs"), _("confiable") if issuer else _("no_cumple"),
            ref=_("ref_pci"), evidencia=f"CA: {issuer.group(1).strip() if issuer else 'Unknown'}")

    hb = "vulnerable to heartbleed" in texto_analizar.lower() and "not vulnerable" not in texto_analizar.lower()
    print_h(_("item_heartbleed"), _("no_vulnerable") if not hb else _("vulnerable"),
            ref=_("ref_cve_heartbleed"), motivo=_("motivo_heartbleed"))

    reneg = "Insecure client-initiated renegotiation" in texto_analizar and "not supported" not in texto_analizar
    print_h(_("item_reneg"), _("buena_config") if not reneg else _("riesgo"),
            ref=_("ref_rfc5746"), motivo=_("motivo_reneg"))

    # --- SECCIÓN: NIST & MEJORES PRÁCTICAS ---
    print(f"\n{Fore.CYAN}{_('header_nist')} ".ljust(95, "-"))
    tls13_match = re.search(r"TLSv1\.3\s+(\w+)", texto_analizar)
    tls13_on = tls13_match and tls13_match.group(1) == "enabled"
    print_h(_("item_tls13"), _("correcto") if tls13_on else _("legado_riesgo"),
            ref=_("ref_nist52"), motivo=_("motivo_tls13"))

    try:
        exp = re.search(r"Not valid after:\s+(.*) GMT", texto_analizar)
        if exp:
            f_exp = datetime.strptime(exp.group(1).strip(), "%b %d %H:%M:%S %Y")
            dias = (f_exp - ts_actual).days
            plazo = f"{'Vencimiento' if LANG == 'es' else 'Expiry'}: {f_exp.strftime('%d-%m-%Y')}"
            restan = f"{dias} {'días restantes' if LANG == 'es' else 'days remaining'}"
            print_h(_("item_vigencia"), _("vigente") if dias > 0 else _("expirado"),
                    ref=_("ref_pci_req"), motivo=plazo, evidencia=restan)
    except: pass

    # --- RESUMEN EJECUTIVO CON CVSS ---
    print(f"\n{Fore.CYAN}{_('header_cvss')} ".ljust(95, "-"))
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

    no_tls13_label = "TLS 1.3 not enabled" if LANG == "en" else "TLS 1.3 no habilitado"
    no_kex_label = "No PQC KEX" if LANG == "en" else "Sin KEX Post-Cuántico"
    no_firma_label = "No PQC signature" if LANG == "en" else "Sin firma Post-Cuántica"
    reneg_label = "Insecure Renegotiation" if LANG == "en" else "Renegociación insegura"

    if "TLSv1.3   disabled" in texto_analizar:
        hallazgos.append(("MEDIUM", no_tls13_label, CVSS_MAP["TLSv1.3 disabled"]))
        riesgo_total += 5.9; max_score = max(max_score, 5.9)

    if "vulnerable to heartbleed" in texto_analizar.lower() and "not vulnerable" not in texto_analizar.lower():
        hallazgos.append(("HIGH", "Heartbleed", CVSS_MAP["heartbleed vulnerable"]))
        riesgo_total += 7.5; max_score = max(max_score, 7.5)

    if "Insecure client-initiated renegotiation" in texto_analizar and "not supported" not in texto_analizar:
        hallazgos.append(("MEDIUM", reneg_label, CVSS_MAP["insecure renegotiation"]))
        riesgo_total += 6.8; max_score = max(max_score, 6.8)

    if not kex:
        hallazgos.append(("MEDIUM", no_kex_label, CVSS_MAP["no_pqc_kex"]))
        riesgo_total += 4.8; max_score = max(max_score, 4.8)

    if not is_pqc_sig:
        hallazgos.append(("MEDIUM", no_firma_label, CVSS_MAP["no_pqc_sig"]))
        riesgo_total += 5.3; max_score = max(max_score, 5.3)

    for severity, finding, info in hallazgos:
        color_tag = Fore.RED if severity == "CRITICAL" else (Fore.YELLOW if severity == "HIGH" else Fore.CYAN)
        print(f"  {color_tag}[{severity}]{Style.RESET_ALL} {finding:40}")
        print(f"    CVSS 4.0: {info['score40']} | {info['vector40']}")
        print(f"    CVSS 3.1: {info['score31']} | {info['vector31']}")

    riesgo_normalizado = min(riesgo_total / 10.0, 10.0)
    nivel = _("bajo") if riesgo_normalizado < 4 else (_("medio") if riesgo_normalizado < 7 else _("alto"))
    color_nivel = Fore.GREEN if nivel == _("bajo") else (Fore.YELLOW if nivel == _("medio") else Fore.RED)

    print(f"\n  {_('score_riesgo'):50} {color_nivel}{riesgo_normalizado:.1f}/10 ({nivel}){Style.RESET_ALL}")
    print(f"  {_('hallazgos_criticos'):50} {Fore.RED}{sum(1 for s,_,_ in hallazgos if s=='CRITICAL')}{Style.RESET_ALL}")
    print(f"  {_('hallazgos_altos'):50} {Fore.YELLOW}{sum(1 for s,_,_ in hallazgos if s=='HIGH')}{Style.RESET_ALL}")
    print(f"  {_('hallazgos_medios'):50} {Fore.CYAN}{sum(1 for s,_,_ in hallazgos if s=='MEDIUM')}{Style.RESET_ALL}")
    print(f"  {_('ref_cvss40'):50} https://www.first.org/cvss/calculator/4.0")
    print(f"  {_('ref_cvss31'):50} https://www.first.org/cvss/calculator/3.1")
    print(f"\n{Fore.MAGENTA}{'='*95}\n")

    return hallazgos, riesgo_normalizado, nivel


# --- [GENERADOR DE CURLS PARA PRUEBAS SSL] ---

def generar_curls(target, folder=""):
    """Genera comandos curl para verificación manual de SSL/TLS."""
    target_clean = target.replace("https://", "").replace("http://", "").split("/")[0]
    main_lang = LANG
    curls = {
        "meta": {
            "target": target_clean,
            "generado": datetime.now(timezone.utc).isoformat(),
            "herramienta": f"Scan_SSL {VERSION}",
            "propósito": "Comandos curl para verificación manual SSL/TLS" if main_lang == "es" else "Curl commands for manual SSL/TLS verification",
            "idioma": main_lang
        },
        "comandos": [
            {
                "id": "01",
                "descripcion": "Handshake SSL básico (verbose)" if main_lang == "es" else "Basic SSL handshake (verbose)",
                "comando": f"curl -vI https://{target_clean} 2>&1"
            },
            {
                "id": "02",
                "descripcion": "Forzar TLS 1.2 (excluye 1.3/1.1/1.0)" if main_lang == "es" else "Force TLS 1.2 (excludes 1.3/1.1/1.0)",
                "comando": f"curl --tlsv1.2 --tls-max 1.2 -vI https://{target_clean} 2>&1"
            },
            {
                "id": "03",
                "descripcion": "Forzar TLS 1.3 (excluye 1.2/1.1/1.0)" if main_lang == "es" else "Force TLS 1.3 (excludes 1.2/1.1/1.0)",
                "comando": f"curl --tlsv1.3 --tls-max 1.3 -vI https://{target_clean} 2>&1"
            },
            {
                "id": "04",
                "descripcion": "Ver cadena de certificados completa" if main_lang == "es" else "View full certificate chain",
                "comando": f"openssl s_client -connect {target_clean}:443 -showcerts < /dev/null 2>/dev/null | openssl x509 -text -noout"
            },
            {
                "id": "05",
                "descripcion": "Cifrados soportados (nmap)" if main_lang == "es" else "Supported ciphers (nmap)",
                "comando": f"nmap --script ssl-enum-ciphers -p 443 {target_clean}"
            },
            {
                "id": "06",
                "descripcion": "Heartbleed check (nmap)" if main_lang == "es" else "Heartbleed check (nmap)",
                "comando": f"nmap --script ssl-heartbleed -p 443 {target_clean}"
            },
            {
                "id": "07",
                "descripcion": "Fecha de expiración del certificado" if main_lang == "es" else "Certificate expiry date",
                "comando": f"echo | openssl s_client -connect {target_clean}:443 -servername {target_clean} 2>/dev/null | openssl x509 -noout -dates"
            },
            {
                "id": "08",
                "descripcion": "Protocolos y cifrados (curl + openssl)" if main_lang == "es" else "Protocols and ciphers (curl + openssl)",
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
    # Parse --lang first to set language before building full parser
    pre_parser = argparse.ArgumentParser(add_help=False)
    pre_parser.add_argument("--lang", choices=["es", "en"], default="es")
    pre_args, __ = pre_parser.parse_known_args()
    global LANG
    LANG = pre_args.lang

    parser = argparse.ArgumentParser(
        prog="Scan_SSL",
        description=f"SCAN SSL {VERSION} — {'Auditor de seguridad SSL/TLS con PQC' if LANG == 'es' else 'SSL/TLS Security Auditor with PQC'}.",
        epilog=f"{'Documentación' if LANG == 'es' else 'Docs'}: https://github.com/apuromafo/Repositorio_Python/tree/main/069_SSL_Scan",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-t", "--target", help=f"{'Dominio o IP a escanear (ej: example.com)' if LANG == 'es' else 'Domain or IP to scan (e.g. example.com)'}")
    parser.add_argument("-f", "--file", help=f"{'Carga de evidencia offline (carpeta con EVIDENCIA_SSLSCAN.log)' if LANG == 'es' else 'Load offline evidence (folder with EVIDENCIA_SSLSCAN.log)'}")
    parser.add_argument("-c", "--curl", action="store_true", help=f"{'Genera comandos curl para verificación manual SSL/TLS' if LANG == 'es' else 'Generate curl commands for manual SSL/TLS verification'}")
    parser.add_argument("--lang", choices=["es", "en"], default="es", help=f"{'Idioma: es=español, en=english' if LANG == 'es' else 'Language: es=spanish, en=english'}")
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
            print(f"{Fore.RED}[✘] {_('no_evidencia')}{Style.RESET_ALL}")
        return

    if args.target:
        if not provisionar_binario(): return
        print(f"{Fore.YELLOW}[*] {_('analizando', target=args.target)}...{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}{Style.BRIGHT}{_('disclaimer_title')}{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}▶ {_('disclaimer_auth')}{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}▶ {_('disclaimer_no_perjuicio')}{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}▶ {_('disclaimer_cvss')}{Style.RESET_ALL}")
        
        proc = subprocess.run([SSLSCAN_BIN, "--no-colour", args.target], capture_output=True, text=True)
        
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
        print(f"║{_('resumen_ejecucion'):^70}║")
        print(f"╠{'═'*70}╣")
        print(f"║ {_('target'):30} {args.target:<37} ║")
        print(f"║ {_('fecha'):30} {ts_resumen:<37} ║")
        print(f"║ {_('estado'):30} {Fore.GREEN}{_('completado'):<37}{Style.RESET_ALL} ║")
        print(f"║ {_('evidencia'):30} {folder:<37} ║")
        archivos = os.listdir(folder)
        for a in archivos:
            print(f"║ {'':30} {Fore.YELLOW}├─ {a:<35}{Style.RESET_ALL} ║")
        print(f"╚{'═'*70}╝{Style.RESET_ALL}")
    else:
        b1 = _("banner_titulo", ver=VERSION)
        b2 = _("banner_linea2")
        print(f"\n{Fore.CYAN}{Style.BRIGHT}╔{'═'*70}╗")
        print(f"║{b1:^70}║")
        print(f"║{b2:^70}║")
        print(f"╚{'═'*70}╝{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}{Style.BRIGHT}{_('disclaimer_title')}{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}▶ {_('disclaimer_auth')}{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}▶ {_('disclaimer_no_perjuicio')}{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}▶ {_('disclaimer_cvss')}{Style.RESET_ALL}")
        print(f"\n  {Fore.GREEN}{_('uso')}:{Style.RESET_ALL} python Scan_ssl_v3.py -t <{'dominio' if LANG == 'es' else 'domain'}>")
        print(f"  {Fore.GREEN}{_('ejemplo')}:{Style.RESET_ALL}  python Scan_ssl_v3.py -t example.com")
        print(f"  {Fore.GREEN}{_('offline')}:{Style.RESET_ALL} python Scan_ssl_v3.py -f ./Resultados_SSL/example_20260625_120000")
        print(f"  {Fore.GREEN}{_('info')}:{Style.RESET_ALL}  python Scan_ssl_v3.py -h")
        print(f"  {Fore.GREEN}{_('version')}:{Style.RESET_ALL} python Scan_ssl_v3.py --version\n")

if __name__ == "__main__":
    main()