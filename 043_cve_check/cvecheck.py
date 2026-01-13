import requests
import os
from datetime import datetime, date
from urllib.parse import urlencode

# === Configuración ===
DATA_DIR = "cve_data"
os.makedirs(DATA_DIR, exist_ok=True)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

HEADERS = {
    "User-Agent": "CVE-Date-Downloader/1.0"
}

# === Descargar CVEs por mes ===
def download_cves_by_month(year, month):
    # Fechas: inicio y fin del mes
    start_date = datetime(year, month, 1)
    if month == 12:
        end_date = datetime(year + 1, 1, 1)
    else:
        end_date = datetime(year, month + 1, 1)

    params = {
        "pubStartDate": start_date.strftime("%Y-%m-%dT00:00:00.000"),
        "pubEndDate": end_date.strftime("%Y-%m-%dT00:00:00.000"),
        "resultsPerPage": 2000  # Máximo permitido
    }

    url = f"{NVD_API_URL}?{urlencode(params)}"
    print(f"[↓] Descargando CVEs de {year}-{month:02d}...")

    try:
        response = requests.get(url, headers=HEADERS)
        response.raise_for_status()
        data = response.json()

        total_results = data.get("totalResults", 0)
        print(f"  → {total_results} CVEs encontrados.")

        if total_results == 0:
            return

        # Crear carpeta: cve_data/2024/
        year_dir = os.path.join(DATA_DIR, str(year))
        os.makedirs(year_dir, exist_ok=True)
        filepath = os.path.join(year_dir, f"{month:02d}.txt")

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(f"# CVEs publicados en {year}-{month:02d}\n")
            f.write(f"# Total: {total_results}\n")
            f.write("# ID | Descripción | CVSS | Severidad | URL\n")
            f.write("-" * 100 + "\n")

            for item in data.get("vulnerabilities", []):
                cve = item["cve"]
                cve_id = cve["id"]
                description = next((desc["value"] for desc in cve.get("descriptions", []) if desc["lang"] == "en"), "Sin descripción")
                url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

                # Extraer CVSS (priorizando v3.1, luego v3.0, luego v2.0)
                cvss_data = None
                severity = "UNKNOWN"
                metrics = cve.get("metrics", {})
                for ver in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    if ver in metrics and len(metrics[ver]) > 0:
                        cvss_data = metrics[ver][0]["cvssData"]
                        severity = metrics[ver][0].get("baseSeverity", "UNKNOWN")
                        break

                cvss_str = f"{cvss_data['version']}:{cvss_data['baseScore']}" if cvss_data else "No CVSS"

                # Limpiar descripción
                description = description.replace("\n", " ").strip()

                f.write(f"{cve_id} | {description} | {cvss_str} | {severity} | {url}\n")

        print(f"[✓] Guardado: {filepath}")

    except Exception as e:
        print(f"[ERROR] Falló descarga de {year}-{month:02d}: {e}")


# === Descargar todos los CVEs de un rango de años/meses ===
def download_range(start_year, start_month, end_year, end_month):
    current = date(start_year, start_month, 1)
    end = date(end_year, end_month, 1)

    while current <= end:
        month_dir = os.path.join(DATA_DIR, str(current.year), f"{current.month:02d}.txt")
        if os.path.exists(month_dir):
            print(f"[=] Ya existe {current.year}-{current.month:02d}, omitiendo...")
        else:
            download_cves_by_month(current.year, current.month)
            time.sleep(6)  # Evitar rate-limit (NVD permite ~10-15 req/min)
        # Siguiente mes
        if current.month == 12:
            current = date(current.year + 1, 1, 1)
        else:
            current = date(current.year, current.month + 1, 1)


# === Listar meses disponibles localmente ===
def list_local_months():
    if not os.path.exists(DATA_DIR):
        print("[!] No hay datos locales.")
        return []
    months = []
    for year_dir in os.listdir(DATA_DIR):
        year_path = os.path.join(DATA_DIR, year_dir)
        if os.path.isdir(year_path) and year_dir.isdigit():
            for file in os.listdir(year_path):
                if file.endswith(".txt") and file[:-4].isdigit():
                    month = int(file[:-4])
                    months.append(f"{year_dir}-{month:02d}")
    months.sort(reverse=True)
    return months


# === Mostrar CVEs de un mes ===
def show_cves(year, month):
    filepath = os.path.join(DATA_DIR, str(year), f"{month:02d}.txt")
    if not os.path.exists(filepath):
        print(f"[!] No existe el archivo: {filepath}")
        return

    with open(filepath, "r", encoding="utf-8") as f:
        lines = f.readlines()

    print("\n" + "=" * 100)
    print(f" CVEs - {year}-{month:02d}")
    print("=" * 100)
    for line in lines:
        if line.startswith("#") or line.strip() == "":
            continue
        print(line.strip())


# === Menú interactivo ===
def menu():
    while True:
        print("\n" + "=" * 60)
        print("   Descargador de CVEs por Fecha - NVD")
        print("=" * 60)
        print("1. Descargar CVEs por mes (año y mes)")
        print("2. Descargar rango de meses (ej: 2024-01 a 2024-12)")
        print("3. Listar meses disponibles localmente")
        print("4. Mostrar CVEs de un mes")
        print("5. Salir")

        choice = input("\nSelecciona una opción: ").strip()

        if choice == "1":
            try:
                year = int(input("Año (ej: 2024): "))
                month = int(input("Mes (1-12): "))
                if 1 <= month <= 12:
                    download_cves_by_month(year, month)
                else:
                    print("[!] Mes inválido.")
            except ValueError:
                print("[!] Ingresa números válidos.")

        elif choice == "2":
            try:
                print("Introduce el rango de fechas (inicio → fin)")
                s_year = int(input("Año inicial: "))
                s_month = int(input("Mes inicial (1-12): "))
                e_year = int(input("Año final: "))
                e_month = int(input("Mes final (1-12): "))

                if s_month < 1 or s_month > 12 or e_month < 1 or e_month > 12:
                    print("[!] Meses inválidos.")
                else:
                    download_range(s_year, s_month, e_year, e_month)
            except ValueError:
                print("[!] Ingresa números válidos.")

        elif choice == "3":
            months = list_local_months()
            if months:
                print("\n[✓] Meses disponibles:")
                for m in months:
                    print(f"  → {m}")
            else:
                print("[!] No hay datos descargados.")

        elif choice == "4":
            try:
                year = int(input("Año (ej: 2024): "))
                month = int(input("Mes (1-12): "))
                if 1 <= month <= 12:
                    show_cves(year, month)
                else:
                    print("[!] Mes inválido.")
            except ValueError:
                print("[!] Ingresa números válidos.")

        elif choice == "5":
            print("[👋] Hasta luego.")
            break
        else:
            print("[!] Opción inválida.")


if __name__ == "__main__":
    import time  # Asegúrate de importarlo
    menu()