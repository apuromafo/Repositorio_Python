import subprocess
import os
import json
import sys
from datetime import datetime

# =================================================================
# CONFIGURACIÓN DE TEXTOS (Soporte Multi-idioma futuro)
# =================================================================
TEXTS = {
    "error_docker": "[!] Error: Docker no está corriendo o no está instalado.",
    "error_path": "[!] Error: La ruta '{}' no existe.",
    "sync_db": "[*] Sincronizando base de datos de Grype...",
    "warn_timeout": "[!] Advertencia: Tiempo de espera agotado al actualizar. Usando versión local...",
    "warn_update": "[!] Advertencia: No se pudo actualizar Grype, usando versión local.",
    "scanning": "[*] Analizando código fuente en: {}",
    "error_exec": "[!] Error de ejecución en Grype: {}",
    "error_unexpected": "[!] Error inesperado durante el análisis: {}",
    "no_vulns": "[!] Grype no encontró vulnerabilidades.",
    "report_generated": "\n[OK] Reporte generado: {}",
    "cancel": "\n\n[!] Escaneo cancelado por el usuario (Ctrl+C).",
    "error_permission": "\n[!] Error: No tienes permisos para escribir o acceder.",
    "error_critical": "\n[!] Error crítico no controlado: {}",
    "process_end": "[*] Proceso finalizado.",
    "table_header_sev": "SEVERIDAD",
    "table_header_qty": "CANTIDAD",
    "table_total": "TOTAL ÚNICOS",
    "fix_msg": "Revisar referencias para mitigación o workaround",
    "label_ref": "REFERENCIAS",
    "label_desc": "DESCRIPCIÓN",
    "label_sol": "SOLUCIÓN",
    "label_affects": "AFECTA A"
}

# =================================================================
# FUNCIONES DE UTILIDAD
# =================================================================

def check_docker():
    try:
        subprocess.run(["docker", "info"], capture_output=True, check=True)
        return True
    except:
        print(TEXTS["error_docker"])
        return False

def get_vulnerability_links(cve_id, data_source):
    """Construye la lista de referencias basada en el ID."""
    links = []
    if str(data_source).startswith("http"):
        links.append(data_source)
    
    if cve_id.startswith("GHSA-") or cve_id.startswith("CVE-"):
        links.append(f"https://osv.dev/vulnerability/{cve_id}")

    if cve_id.startswith("GHSA-"):
        links.append(f"https://github.com/advisories/{cve_id}")
    elif cve_id.startswith("CVE-"):
        if not any("nvd.nist.gov" in l for l in links):
            links.append(f"https://nvd.nist.gov/vuln/detail/{cve_id}")
    
    return list(dict.fromkeys(links))

def write_summary_table(f, summary_counts, total_unique):
    """Escribe la tabla de resumen inicial en el archivo."""
    f.write("RESUMEN DE HALLAZGOS\n")
    f.write("+" + "-"*20 + "+" + "-"*15 + "+\n")
    f.write(f"| {TEXTS['table_header_sev']:<18} | {TEXTS['table_header_qty']:<13} |\n")
    f.write("+" + "-"*20 + "+" + "-"*15 + "+\n")
    for s in ["Critical", "High", "Medium", "Low", "Negligible", "Unknown"]:
        f.write(f"| {s:<18} | {summary_counts.get(s, 0):<13} |\n")
    f.write("+" + "-"*20 + "+" + "-"*15 + "+\n")
    f.write(f"| {TEXTS['table_total']:<18} | {total_unique:<13} |\n")
    f.write("+" + "-"*20 + "+" + "-"*15 + "+\n\n")

# =================================================================
# LÓGICA PRINCIPAL
# =================================================================

def run_grype_scan(target_path):
    abs_path = os.path.abspath(target_path)
    if not os.path.exists(abs_path):
        print(TEXTS["error_path"].format(abs_path)); return None

    GRYPE_IMAGE = "anchore/grype:latest"
    print(TEXTS["sync_db"])
    
    try:
        subprocess.run(["docker", "pull", GRYPE_IMAGE], check=True, stdout=subprocess.DEVNULL, timeout=60)
    except subprocess.TimeoutExpired:
        print(TEXTS["warn_timeout"])
    except Exception:
        print(TEXTS["warn_update"])
    
    print(TEXTS["scanning"].format(abs_path))
    command = ["docker", "run", "--rm", "-v", f"{abs_path}:/scandir", GRYPE_IMAGE, "dir:/scandir", "-o", "json"]

    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        print(TEXTS["error_exec"].format(e.stderr)); return None
    except Exception as e:
        print(TEXTS["error_unexpected"].format(e)); return None

def generate_report(data, original_path):
    if not data or 'matches' not in data:
        print(TEXTS["no_vulns"]); return

    now = datetime.now()
    folder_name = os.path.basename(original_path.rstrip(os.sep))
    filename = f"auditoria_grype_{folder_name}_{now.strftime('%Y%m%d_%H%M')}.txt"
    
    severity_rank = {"Critical": 1, "High": 2, "Medium": 3, "Low": 4, "Negligible": 5, "Unknown": 6}
    grouped_findings = {}
    summary_counts = {s: 0 for s in severity_rank.keys()}
    
    for m in data['matches']:
        v = m['vulnerability']
        a = m['artifact']
        cve_id = v.get('id', 'Unknown-ID')
        sev = v.get('severity', 'Unknown')

        if cve_id not in grouped_findings:
            summary_counts[sev] = summary_counts.get(sev, 0) + 1
            
            fix_versions = v.get('fix', {}).get('versions', [])
            fix_str = ', '.join(fix_versions) if fix_versions and fix_versions[0] else TEXTS["fix_msg"]

            grouped_findings[cve_id] = {
                "severity": sev,
                "description": v.get('description', 'Sin detalles'),
                "fix": fix_str,
                "references": get_vulnerability_links(cve_id, v.get('dataSource', "")),
                "affected_artifacts": set()
            }
        
        clean_path = a.get('locations', [{}])[0].get('path', 'N/A').replace("/scandir", ".")
        grouped_findings[cve_id]["affected_artifacts"].add(f"{a.get('name')} (v{a.get('version')}) en {clean_path}")

    sorted_cves = sorted(grouped_findings.keys(), key=lambda x: severity_rank.get(grouped_findings[x]['severity'], 99))

    with open(filename, "w", encoding="utf-8") as f:
        f.write("="*80 + "\n")
        f.write(f"REPORTE DE SEGURIDAD GRYPE - {folder_name.upper()}\n")
        f.write(f"FECHA: {now.strftime('%d/%m/%Y %H:%M:%S')}\n")
        f.write("="*80 + "\n\n")

        write_summary_table(f, summary_counts, len(grouped_findings))

        f.write(f"DETALLE DE VULNERABILIDADES (ORDENADO POR SEVERIDAD)\n" + "="*80 + "\n")
        for i, cve in enumerate(sorted_cves, 1):
            info = grouped_findings[cve]
            f.write(f"ID #{i} | {cve} | [{info['severity'].upper()}]\n")
            f.write(f"  - {TEXTS['label_ref']}:\n")
            for link in info['references']:
                f.write(f"      -> {link}\n")
            f.write(f"  - {TEXTS['label_desc']}: {info['description'][:300]}...\n")
            f.write(f"  - {TEXTS['label_sol']}:    {info['fix']}\n")
            f.write(f"  - {TEXTS['label_affects']}:\n")
            for art in sorted(info['affected_artifacts']):
                f.write(f"      [!] {art}\n")
            f.write("-" * 60 + "\n")

    print(TEXTS["report_generated"].format(filename))

if __name__ == "__main__":
    try:
        if check_docker():
            target = sys.argv[2] if len(sys.argv) > 2 and sys.argv[1] == "-f" else (sys.argv[1] if len(sys.argv) > 1 else ".")
            raw_results = run_grype_scan(target)
            if raw_results:
                generate_report(raw_results, target)
    except KeyboardInterrupt:
        print(TEXTS["cancel"]); sys.exit(0)
    except PermissionError:
        print(TEXTS["error_permission"])
    except Exception as e:
        print(TEXTS["error_critical"].format(e))
    finally:
        print(TEXTS["process_end"])