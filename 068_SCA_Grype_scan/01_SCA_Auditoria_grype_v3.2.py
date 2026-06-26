
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
import shutil
from datetime import datetime, timezone

# =================================================================
# CONFIGURACIÓN DE TEXTOS
# =================================================================
TEXTS = {
    "error_docker": "[!] Error: Docker no está funcionando o no está instalado.",
    "error_path": "[!] Error: La ruta '{}' no existe.",
    "sync_db": "[*] Preparando imagen y base de datos de Grype...",
    "heuristic_mode": "[!] Modo Auditoría: Extrayendo dependencias manualmente...",
    "scanning": "[*] Buscando vulnerabilidades...",
    "no_vulns": "[!] No se encontraron vulnerabilidades en los componentes detectados.",
    "report_generated": "\n[OK] Auditoría completada. Resultados en: {}",
    "error_critical": "[!] Error crítico: {}",
    "process_end": "[*] Proceso finalizado."
}
#local_db_cache = "C:\\grype_db_cache"
# =================================================================
# CONFIGURACIÓN GLOBAL
# =================================================================
# Ruta donde descargaste la DB manualmente
DB_PATH = os.path.join(os.environ.get('SYSTEMDRIVE', 'C:'), 'grype_db_cache')


# =================================================================
# UTILIDADES DE ENLACES
# =================================================================
def get_vulnerability_links(cve_id, data_source):
    links = []
    if cve_id.startswith(("GHSA-", "CVE-")):
        links.append(f"https://osv.dev/vulnerability/{cve_id}")
    if cve_id.startswith("GHSA-"):
        links.append(f"https://github.com/advisories/{cve_id}")
    elif cve_id.startswith("CVE-"):
        links.append(f"https://nvd.nist.gov/vuln/detail/{cve_id}")
    
    if data_source and str(data_source).startswith("http"):
        links.append(data_source)
    
    return list(dict.fromkeys(links))
    
# =================================================================
# UTILIDADES DE SISTEMA
# =================================================================
def check_grype_db_status():
    """Verifica si la base de datos en DB_PATH es válida y muestra su estado"""
    if not os.path.exists(DB_PATH):
        print(f"[!] Advertencia: La ruta de DB {DB_PATH} no existe.")
        return False
    
    cmd = [
        "docker", "run", "--rm",
        "-v", f"{DB_PATH}:/db_cache",
        "-e", "GRYPE_DB_CACHE_DIR=/db_cache",
        "anchore/grype:latest", "db", "status"
    ]
    
    try:
        # Usamos check_output para asegurar que capturamos todo
        result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
        output = result.stdout.lower() # Convertimos a minúsculas para comparar mejor
        
        if "status: valid" in output or "valid" in output:
            # Extraer la fecha para el log (ahora buscando con más flexibilidad)
            date_match = re.search(r"built:\s+([^\n]+)", output)
            build_date = date_match.group(1).strip() if date_match else "Reciente"
            print(f"[OK] Base de Datos vinculada correctamente. (Construida: {build_date})")
            return True
        else:
            print("[!] Error: La base de datos no parece válida.")
            print(result.stdout)
            return False
    except Exception as e:
        print(f"[!] No se pudo verificar el estado de la DB: {e}")
        return False  
# =================================================================
# FUNCIÓN CRITICA: CREACIÓN DE SBOM   
# =================================================================
def create_sbom(deps, output_folder):
    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    sbom = {
        "bomFormat": "CycloneDX", "specVersion": "1.4", "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": [{"vendor": "SCA", "name": "SCA-Parser", "version": "3.0.0"}]
        },
        "components": []
    }
    for d in deps:
        v_original = str(d['version']).strip()
        
        # --- NORMALIZACIÓN PARA GRYPE ---
        # Si la versión es 2.17.0.redhat-630254, clean_v será 2.17.0
        # Esto permite que Grype encuentre los CVEs en las bases de datos estándar.
        clean_v = v_original.split('.redhat-')[0] if '.redhat-' in v_original else v_original
        
        # Construimos el PURL con la versión limpia para maximizar detección
        if d['type'] == "npm":
            purl = f"pkg:npm/{d['name']}@{clean_v}"
        else:
            purl = f"pkg:maven/{d['group']}/{d['name']}@{clean_v}"
            
        sbom["components"].append({
            "group": d.get("group", ""), 
            "name": d["name"], 
            "version": v_original, # Mantenemos la original para el reporte visual
            "type": "library", 
            "purl": purl
        })
    
    file_path = os.path.join(output_folder, "inventory_sbom.json")
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(sbom, f, indent=2, ensure_ascii=False)
    return file_path
# =================================================================
# ANALIZADORES ESTÁTICOS (Soporte Multi-Lenguaje)
# =================================================================
def extract_static_dependencies(folder_path):
    dependencies = []
    
    # --- 1. MAVEN (pom.xml) - CON FIX DE VARIABLES ---
    pom_xml = os.path.join(folder_path, "pom.xml")
    if os.path.exists(pom_xml):
        try:
            import xml.etree.ElementTree as ET
            tree = ET.parse(pom_xml)
            root = tree.getroot()
            ns_url = root.tag.split('}')[0].strip('{') if '}' in root.tag else ""
            ns = {'m': ns_url} if ns_url else {}
            prefix = "m:" if ns_url else ""

            # Mapear propiedades para resolver variables (Camel, Fuse, etc)
            props_map = {}
            props_elem = root.find(f".//{prefix}properties", ns)
            if props_elem is not None:
                for prop in props_elem:
                    tag = prop.tag.split('}')[-1] if '}' in prop.tag else prop.tag
                    props_map[tag] = prop.text.strip() if prop.text else ""

            fuse_ver = props_map.get("jboss.fuse.bom.version", "6.3.0.redhat-262")
            camel_ver = props_map.get("camel.version", "2.17.0.redhat-630254")

            for d in root.findall(f".//{prefix}dependency", ns):
                g = d.find(f"{prefix}groupId", ns).text.strip() if d.find(f"{prefix}groupId", ns) is not None else ""
                a = d.find(f"{prefix}artifactId", ns).text.strip() if d.find(f"{prefix}artifactId", ns) is not None else ""
                v_el = d.find(f"{prefix}version", ns)
                
                if v_el is not None:
                    version = v_el.text.strip()
                    if version.startswith("${"):
                        version = props_map.get(version.strip("${}"), "0.0.1")
                else:
                    version = camel_ver if "camel" in a else fuse_ver
                
                if a: dependencies.append({"group": g, "name": a, "version": version, "type": "maven"})
        except Exception as e: print(f"[!] Error Maven: {e}")
    
    # --- 2. BLOQUE JAVA (Gradle) ---Revisión 24.04.2026
    gradle_file = os.path.join(folder_path, "build.gradle")
    if os.path.exists(gradle_file):
        try:
            with open(gradle_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Detectar versión de Spring Boot del bloque plugins
            sb_match = re.findall(r"id\s+['\"]org\.springframework\.boot['\"]\s+version\s+['\"]([^'\"]+)['\"]", content)
            spring_boot_ver = sb_match[0] if sb_match else "3.4.0"

            # Detectar versión de AWS Cloud si está explícita
            aws_match = re.findall(r"io\.awspring\.cloud:spring-cloud-aws-starter:([^'\"]+)", content)
            aws_ver = aws_match[0] if aws_match else "3.4.0"

            # Regex para capturar implementaciones (soporta comillas simples y dobles)
            # Captura group:name:version o solo group:name
            std_pattern = re.compile(r"(?:implementation|compile|testImplementation|compileOnly|annotationProcessor)\s+['\"]([^'\"\s:]+):([^'\"\s:]+)(?::([^'\"\s:]+))?['\"]")

            for m in std_pattern.finditer(content):
                group, name, version = m.groups()
                
                if not version:
                    # Asignación inteligente para evitar el 0.0.1
                    if "org.springframework" in group or "com.fasterxml.jackson" in group:
                        version = spring_boot_ver
                    elif "io.awspring.cloud" in group:
                        version = aws_ver
                    elif "software.amazon.awssdk" in group:
                        version = "2.29.0" # Alineado con SB 3.4.0
                    else:
                        version = "1.0.0"

                dependencies.append({"group": group, "name": name, "version": version, "type": "maven"})

        except Exception as e:
            print(f"[!] Error en el parser Gradle: {e}")
    # --- 3. NODE.JS ---
    pkg_json = os.path.join(folder_path, "package.json")
    if os.path.exists(pkg_json):
        try:
            with open(pkg_json, 'r', encoding='utf-8') as f:
                data = json.load(f)
                deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
                for n, v in deps.items():
                    clean_v = re.sub(r'[^\d.]', '', str(v).split(' ')[0])
                    dependencies.append({"group": "", "name": n, "version": clean_v or "0.0.1", "type": "npm"})
        except: pass

    # --- 4. PYTHON ---
    req_txt = os.path.join(folder_path, "requirements.txt")
    if os.path.exists(req_txt):
        try:
            with open(req_txt, 'r', encoding='utf-8') as f:
                for line in f:
                    if "==" in line and not line.strip().startswith("#"):
                        parts = line.strip().split("==")
                        dependencies.append({"group": "", "name": parts[0].strip(), "version": parts[1].strip(), "type": "pypi"})
        except: pass

    # --- 5. .NET ---
    for file in os.listdir(folder_path):
        if file.endswith(".csproj"):
            try:
                with open(os.path.join(folder_path, file), 'r', encoding='utf-8') as f:
                    content = f.read()
                    matches = re.findall(r'PackageReference Include="([^"]+)" Version="([^"]+)"', content)
                    for n, v in matches:
                        dependencies.append({"group": "", "name": n, "version": v, "type": "nuget"})
            except: pass

    # --- 6. GO ---
    go_mod = os.path.join(folder_path, "go.mod")
    if os.path.exists(go_mod):
        try:
            with open(go_mod, 'r', encoding='utf-8') as f:
                for line in f:
                    match = re.search(r"^\s*([^\s\/]+/[^\s]+|[^\s]+)\s+(v\d+\.\d+\.\d+)", line)
                    if match:
                        dependencies.append({"group": "", "name": match.group(1), "version": match.group(2), "type": "golang"})
        except: pass

    # --- 7. RUBY ---
    gemfile = os.path.join(folder_path, "Gemfile")
    if os.path.exists(gemfile):
        try:
            with open(gemfile, 'r', encoding='utf-8') as f:
                for line in f:
                    match = re.search(r"gem\s+['\"]([^'\"]+)['\"](?:\s*,\s*['\"]([^'\"]+)['\"])?", line)
                    if match:
                        dependencies.append({"group": "", "name": match.group(1), "version": match.group(2) or "0.0.1", "type": "gem"})
        except: pass

    # --- 8. RUST ---
    cargo_toml = os.path.join(folder_path, "Cargo.toml")
    if os.path.exists(cargo_toml):
        try:
            with open(cargo_toml, 'r', encoding='utf-8') as f:
                content = f.read()
                matches = re.findall(r'^([a-zA-Z0-9_-]+)\s*=\s*(?:[\'"]([^\'"]+)[\'"]|\{\s*version\s*=\s*[\'"]([^\'"]+)[\'"])', content, re.MULTILINE)
                for name, v1, v2 in matches:
                    dependencies.append({"group": "", "name": name, "version": v1 or v2, "type": "cargo"})
        except: pass

    # --- 9. PHP ---
    composer_json = os.path.join(folder_path, "composer.json")
    if os.path.exists(composer_json):
        try:
            with open(composer_json, 'r', encoding='utf-8') as f:
                data = json.load(f)
                deps = {**data.get("require", {}), **data.get("require-dev", {})}
                for n, v in deps.items():
                    if n == "php": continue
                    clean_v = re.sub(r'[^\d.]', '', str(v).split('|')[0].split(',')[0])
                    dependencies.append({"group": "", "name": n, "version": clean_v or "0.0.1", "type": "composer"})
        except: pass

    # --- 10. DART/FLUTTER ---
    pubspec = os.path.join(folder_path, "pubspec.yaml")
    if os.path.exists(pubspec):
        try:
            with open(pubspec, 'r', encoding='utf-8') as f:
                for line in f:
                    match = re.search(r"^\s+([a-z0-9_]+):\s+\^?(\d+\.\d+\.\d+)", line)
                    if match:
                        dependencies.append({"group": "", "name": match.group(1), "version": match.group(2), "type": "pub"})
        except: pass

    return dependencies # ÚNICO RETURN AL FINAL
# =================================================================
# LÓGICA DE ESCANEO (Multi-proceso safe)
# =================================================================
# =================================================================
# ESCANEO Y SBOM
# =================================================================


def run_grype(sbom_path, output_folder=None, is_sbom=True):
    abs_sbom = os.path.abspath(sbom_path)
    mount_dir = os.path.dirname(abs_sbom)
    filename = os.path.basename(abs_sbom)
    # OPTIMIZACIÓN: Montamos la DB como Solo Lectura (:ro) para evitar bloqueos de Windows
    command = ["docker", "run", "--rm", "-v", f"{DB_PATH}:/db_cache:ro", "-v", f"{mount_dir}:/work",
               "-e", "GRYPE_DB_CACHE_DIR=/db_cache", "anchore/grype:latest", f"sbom:/work/{filename}", "-o", "json", "--quiet"]
    try:
        result = subprocess.run(command, capture_output=True, text=True, encoding='utf-8')
        return json.loads(result.stdout) if result.returncode == 0 else None
    except: return None

# =================================================================
# REPORTE FINAL MEJORADO
# =================================================================
# =================================================================
# REPORTE FINAL ORDENADO
# =================================================================
def generate_final_report(data, target_path, dep_count, output_folder):
    now = datetime.now()
    abs_target = os.path.abspath(target_path)
    abs_output = os.path.abspath(output_folder)
    report_name = f"Auditoria_SCA_{now.strftime('%H%M%S')}.txt"
    report_path = os.path.join(output_folder, report_name)
    
    summary = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Unknown": 0}
    findings = []

    # 1. Procesamiento de hallazgos
    matches = data.get('matches', [])
    total_hallazgos = len(matches)

    for m in matches:
        v = m['vulnerability']
        a = m['artifact']
        sev = v.get('severity', 'Unknown').capitalize()
        if sev in summary: summary[sev] += 1
        
        findings.append({
            "id": v.get('id'),
            "sev": sev,
            "pkg": f"{a.get('name')} ({a.get('version')})",
            "fix": ", ".join(v.get('fix', {}).get('versions', ["No disponible"])),
            "links": get_vulnerability_links(v.get('id'), v.get('dataSource'))
        })

    # Ordenar por criticidad
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Unknown": 4}
    findings.sort(key=lambda x: order.get(x['sev'], 5))

    # 2. Escritura del reporte
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("="*80 + "\n")
        f.write(f"REPORTE DE SEGURIDAD SCA - {now.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"PROYECTO: {os.path.basename(abs_target)}\n")
        f.write(f"RUTA: {abs_target}\n")
        f.write(f"DEPENDENCIAS TOTALES DETECTADAS: {dep_count}\n")
        f.write("="*80 + "\n\n")
        
        # --- TABLA DE RESUMEN ---
        f.write("RESUMEN GENERAL DE HALLAZGOS\n")
        f.write(f"> TOTAL DE HALLAZGOS: {total_hallazgos}\n\n")
        
        # Encabezado de la tabla
        f.write(f"{'NIVEL DE RIESGO':<18} | {'CANTIDAD':<10} | {'% DEL TOTAL':<12}\n")
        f.write("-" * 45 + "\n")
        
        for sev_name, count in summary.items():
            # Cálculo de porcentaje seguro
            percentage = (count / total_hallazgos * 100) if total_hallazgos > 0 else 0.0
            f.write(f"{sev_name:<18} | {count:<10} | {percentage:>10.1f}%\n")
            
        f.write("-" * 45 + "\n\n")
        f.write("="*80 + "\n")
        f.write("DETALLES TÉCNICOS DE VULNERABILIDADES\n")
        f.write("="*80 + "\n")
        
        if not findings:
            f.write("\n[OK] No se detectaron vulnerabilidades conocidas.\n")
        else:
            for fnd in findings:
                f.write(f"\n[{fnd['sev'].upper()}] {fnd['id']}\n")
                f.write(f"  Componente: {fnd['pkg']}\n")
                f.write(f"  Fix Version: {fnd['fix']}\n")
                f.write(f"  Referencias:\n")
                for link in fnd['links']:
                    f.write(f"    -> {link}\n")
                f.write("-" * 50 + "\n")

    return report_path

# =================================================================
# MAIN
# =================================================================

print("\n[!] AVISO LEGAL: Use solo con autorizacion. / LEGAL NOTICE: Authorized use only.\n")
if __name__ == "__main__":
    try:
        # 1. Determinar el objetivo del escaneo
        target = sys.argv[2] if len(sys.argv) > 2 and sys.argv[1] == "-f" else "."
        if not os.path.exists(target): 
            print(TEXTS["error_path"].format(target))
            sys.exit(1)

        # 2. Crear carpeta de salida con timestamp
        out_dir = f"reporte_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(out_dir, exist_ok=True)
        
        # Guardamos la ruta absoluta para el reporte visual
        abs_target = os.path.abspath(target)
        abs_out_dir = os.path.abspath(out_dir)

        # 3. Sincronizar Base de Datos
        print(TEXTS["sync_db"])
        db_ready = check_grype_db_status()
        if not db_ready:
            print("[!] La base de datos no está lista. El escaneo podría no devolver resultados.")

        # 4. Extracción de dependencias (Modo Heurístico)
        print(TEXTS["heuristic_mode"])
        print(f"[*] Analizando directorio: {abs_target}")
        deps = extract_static_dependencies(target)
        
        if deps:
            print(f"[*] Se detectaron {len(deps)} dependencias. Generando SBOM...")
            sbom_file = create_sbom(deps, out_dir)
            
            print(TEXTS["scanning"])
            # Nota: run_grype ahora solo recibe sbom_file según la última firma de función
            res = run_grype(sbom_file)
            
            if res:
                # Generar el reporte usando la ruta absoluta para que quede impreso dentro del archivo
                path = generate_final_report(res, abs_target, len(deps), out_dir)
                
                # REPORTE VISUAL EN CONSOLA (Mejorado)
                print("-" * 60)
                print(TEXTS["report_generated"].format(path))
                print(f"[*] Carpeta de resultados: {abs_out_dir}")
                print(f"[*] Proyecto analizado: {abs_target}")
                print("-" * 60)
            else:
                print("[!] Grype no pudo procesar el SBOM.")
        else:
            print("[!] No se detectaron archivos procesables en la ruta indicada.")

    except Exception as e:
        print(TEXTS["error_critical"].format(e))
    finally:
        print(TEXTS["process_end"])