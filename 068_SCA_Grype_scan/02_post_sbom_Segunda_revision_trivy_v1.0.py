
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

import subprocess
import os
import json
import sys
import re
from datetime import datetime, timezone

# =================================================================
# CONFIGURACIÓN GLOBAL
# =================================================================
DB_PATH = os.path.join(os.environ.get('SYSTEMDRIVE', 'C:'), 'grype_db_cache')
TEXTS = {
    "sync_db": "[*] Validando Base de Datos de Vulnerabilidades...",
    "mode_sbom": "[*] Modo SBOM detectado: Cargando componentes desde archivo...",
    "mode_project": "[!] Modo Proyecto detectado: Analizando archivos fuente...",
    "scanning": "[*] Iniciando Escaneo Triangulado (Grype + Trivy + OSV)...",
    "report_generated": "\n[OK] Auditoría consolidada generada con éxito.",
}

# =================================================================
# UTILIDADES
# =================================================================
def check_grype_db_status():
    if not os.path.exists(DB_PATH): os.makedirs(DB_PATH, exist_ok=True)
    cmd = ["docker", "run", "--rm", "-v", f"{DB_PATH}:/db_cache", "-e", "GRYPE_DB_CACHE_DIR=/db_cache", "anchore/grype:latest", "db", "status"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
        return "valid" in result.stdout.lower()
    except: return False

# =================================================================
# CARGA DE DATOS (ARCHIVO O CARPETA)
# =================================================================
def load_input_data(path):
    # SI ES UN ARCHIVO JSON (SBOM)
    if os.path.isfile(path) and path.endswith('.json'):
        print(TEXTS["mode_sbom"])
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                return data.get('components', []), path
        except Exception as e:
            print(f"[!] Error leyendo SBOM: {e}")
            return [], None

    # SI ES UNA CARPETA (PROYECTO)
    elif os.path.isdir(path):
        print(TEXTS["mode_project"])
        # Aquí iría tu lógica de extract_dependencies que ya tienes
        # Por brevedad, asumo que ya sabes que esta parte busca el build.gradle
        return [], None # (Implementar si es necesario volver a extraer)
    
    return [], None

# =================================================================
# MOTORES DE ESCANEO (DOCKER)
# =================================================================
def run_engine(engine_name, sbom_path):
    abs_path = os.path.abspath(sbom_path)
    work_dir = os.path.dirname(abs_path)
    fname = os.path.basename(abs_path)
    
    if engine_name == "grype":
        cmd = ["docker", "run", "--rm", "-v", f"{DB_PATH}:/db_cache:ro", "-v", f"{work_dir}:/work",
               "-e", "GRYPE_DB_CACHE_DIR=/db_cache", "anchore/grype:latest", f"sbom:/work/{fname}", "-o", "json", "--quiet"]
    elif engine_name == "trivy":
        cmd = ["docker", "run", "--rm", "-v", f"{work_dir}:/work", "aquasec/trivy:latest", "sbom", f"/work/{fname}", "--format", "json", "--quiet"]
    elif engine_name == "osv":
        cmd = ["docker", "run", "--rm", "-v", f"{work_dir}:/work", "ghcr.io/google/osv-scanner:latest", f"--sbom=/work/{fname}", "--format=json"]
    
    try:
        print(f"  [>] Ejecutando {engine_name.upper()}...")
        r = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
        return json.loads(r.stdout) if r.stdout else {}
    except:
        return {}

# =================================================================
# REPORTE CONSOLIDADO
# =================================================================
def consolidate_and_report(original_sbom_path, res_g, res_t, res_o, out_dir):
    findings = {}
    
    # Procesar GRYPE
    for m in res_g.get('matches', []):
        vid = m['vulnerability']['id']
        findings[vid] = {"id": vid, "sev": m['vulnerability'].get('severity', 'Unknown').capitalize(), 
                         "pkg": f"{m['artifact']['name']} ({m['artifact']['version']})", "src": "Grype"}

    # Procesar TRIVY
    for res in res_t.get('Results', []):
        for v in res.get('Vulnerabilities', []):
            vid = v['VulnerabilityID']
            if vid in findings: findings[vid]["src"] += "+Trivy"
            else: findings[vid] = {"id": vid, "sev": v.get('Severity','Unknown').capitalize(), "pkg": v.get('PkgName'), "src": "Trivy"}

    # Procesar OSV
    for res in res_o.get('results', []):
        for v in res.get('vulns', []):
            vid = v['id']
            if vid in findings: findings[vid]["src"] += "+OSV"
            else: findings[vid] = {"id": vid, "sev": "Review", "pkg": res['package']['name'], "src": "OSV"}

    # Generar Salida
    report_path = os.path.join(out_dir, f"Reporte_Consolidado_SCA.txt")
    
    # Orden de severidad para la tabla
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Review": 4, "Unknown": 5}
    sorted_f = sorted(findings.values(), key=lambda x: order.get(x['sev'], 6))

    with open(report_path, "w", encoding="utf-8") as f:
        f.write("="*90 + "\n")
        f.write(f"REPORTE CONSOLIDADO DE VULNERABILIDADES (SCA)\n")
        f.write(f"ENTRADA: {original_sbom_path}\n")
        f.write(f"FECHA: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("="*90 + "\n\n")
        
        f.write(f"{'ID VULNERABILIDAD':<22} | {'SEVERIDAD':<12} | {'DETECTOR':<20} | {'COMPONENTE'}\n")
        f.write("-" * 90 + "\n")
        for v in sorted_f:
            f.write(f"{v['id']:<22} | {v['sev']:<12} | {v['src']:<20} | {v['pkg']}\n")

    return report_path

# =================================================================
# MAIN
# =================================================================

print("\n[!] AVISO LEGAL: Use solo con autorizacion. / LEGAL NOTICE: Authorized use only.\n")
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python script.py <ruta_archivo_sbom.json>")
        sys.exit(1)

    input_path = sys.argv[1]
    out_dir = f"auditoria_final_{datetime.now().strftime('%H%M%S')}"
    os.makedirs(out_dir, exist_ok=True)

    print(TEXTS["sync_db"])
    if check_grype_db_status(): print("[OK] DB Grype lista.")

    # Cargar componentes
    components, sbom_to_scan = load_input_data(input_path)
    
    if components and sbom_to_scan:
        print(f"[*] Se cargaron {len(components)} componentes del SBOM.")
        print(TEXTS["scanning"])
        
        # Ejecución
        rg = run_engine("grype", sbom_to_scan)
        rt = run_engine("trivy", sbom_to_scan)
        ro = run_engine("osv", sbom_to_scan)
        
        final_rep = consolidate_and_report(input_path, rg, rt, ro, out_dir)
        print(f"{TEXTS['report_generated']}\nArchivo: {os.path.abspath(final_rep)}")
    else:
        print("[!] No se pudieron cargar datos válidos del archivo proporcionado.")