import requests
import time
from config import VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY, MAX_AGE_IN_DAYS, API_REQUEST_DELAY

# Definición de colores ANSI para mejorar la presentación en consola
RED = "\033[91m"
GREEN = "\033[92m"
WHITE = "\033[97m"
CYAN = "\033[96m"
RESET = "\033[0m"

# Colores de fondo para representar niveles de riesgo
BG_GREEN = "\033[42m"       # Bajo riesgo
BG_YELLOW = "\033[43m"      # Riesgo moderado
BG_ORANGE = "\033[48;5;208m"  # Riesgo alto
BG_RED = "\033[41m"         # Riesgo crítico
BG_LIGHT_BLUE = "\033[44m"  # Sin riesgo aparente

def leer_ips_desde_archivo(archivo):
    """
    Lee un archivo de texto que contiene una lista de IPs separadas por líneas.
    Retorna una lista de IPs válidas.
    """
    try:
        with open(archivo, "r") as file:
            ips = [line.strip() for line in file.readlines() if line.strip()]
        return ips
    except FileNotFoundError:
        print(f"{RED}Archivo no encontrado: {archivo}{RESET}")
        return []

def consultar_virustotal(ip):
    """
    Consulta la API de VirusTotal para obtener información sobre una IP.
    Retorna un resumen de detecciones maliciosas y sospechosas.
    """
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        malicious = data["data"]["attributes"]["last_analysis_stats"]["malicious"]
        suspicious = data["data"]["attributes"]["last_analysis_stats"]["suspicious"]
        
        # Asignar color según el nivel de riesgo
        if malicious == 0 and suspicious == 0:
            score_color = BG_GREEN
        elif malicious == 0 and suspicious > 0:
            score_color = BG_YELLOW
        elif malicious > 0:
            score_color = BG_RED
        else:
            score_color = WHITE

        return f"{score_color}Maliciosa: {malicious} | Sospechosa: {suspicious}{RESET}"
    
    return "Error al consultar"

def consultar_abuseipdb(ip):
    """
    Consulta la API de AbuseIPDB para obtener información sobre una IP.
    Retorna un resumen del puntaje de confianza de abuso y el número de reportes.
    """
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    params = {"ipAddress": ip, "maxAgeInDays": MAX_AGE_IN_DAYS}
    response = requests.get(url, headers=headers, params=params)

    if response.status_code == 200:
        data = response.json()
        abuse_score = data["data"]["abuseConfidenceScore"]
        reports = data["data"]["totalReports"]
        
        # Asignar color según el nivel de riesgo
        if abuse_score <= 39:
            score_color = BG_LIGHT_BLUE
        elif abuse_score <= 49:
            score_color = BG_YELLOW
        elif abuse_score <= 69:
            score_color = BG_ORANGE
        else:
            score_color = BG_RED

        return f"{score_color}Abuse Score: {abuse_score} | Reports: {reports}{RESET}"
    
    return "Error al consultar"

def mostrar_resultados(ips, opcion):
    """
    Muestra los resultados en una tabla bien alineada.
    """
    if not ips:
        print(f"{RED}No hay IPs para analizar.{RESET}")
        return

    # Anchura fija para cada columna
    IP_WIDTH = 20
    COLUMN_WIDTH = 35

    # Encabezado de la tabla
    header = f"{'IP'.ljust(IP_WIDTH)} | "
    if opcion in ["1", "3"]:
        header += f"{'VirusTotal'.ljust(COLUMN_WIDTH)} | "
    if opcion in ["2", "3"]:
        header += f"{'AbuseIPDB'.ljust(COLUMN_WIDTH)}"
    print("=" * 90)
    print(header)
    print("=" * 90)

    # Filas de la tabla
    for ip in ips:
        vt_resultado = consultar_virustotal(ip) if opcion in ["1", "3"] else ""
        abuse_resultado = consultar_abuseipdb(ip) if opcion in ["2", "3"] else ""

        # Asegurarse de que los resultados no excedan el ancho de la columna
        vt_resultado = (vt_resultado[:COLUMN_WIDTH - 3] + "...") if len(vt_resultado) > COLUMN_WIDTH else vt_resultado
        abuse_resultado = (abuse_resultado[:COLUMN_WIDTH - 3] + "...") if len(abuse_resultado) > COLUMN_WIDTH else abuse_resultado

        row = f"{ip.ljust(IP_WIDTH)} | "
        if opcion in ["1", "3"]:
            row += f"{vt_resultado.ljust(COLUMN_WIDTH)} | "
        if opcion in ["2", "3"]:
            row += f"{abuse_resultado.ljust(COLUMN_WIDTH)}"
        print(row)

        # Espera para evitar sobrecargar las APIs
        time.sleep(API_REQUEST_DELAY)

    print("=" * 90)

def mostrar_menu():
    """
    Muestra un menú interactivo para seleccionar qué API utilizar.
    """
    while True:
        print(f"\n{CYAN}Menú de opciones:{RESET}")
        print(f"{GREEN}1.{RESET} Consultar VirusTotal")
        print(f"{GREEN}2.{RESET} Consultar AbuseIPDB")
        print(f"{GREEN}3.{RESET} Consultar ambas APIs")
        print(f"{GREEN}4.{RESET} Salir")

        opcion = input(f"\n{CYAN}Seleccione una opción (1-4): {RESET}")
        
        if opcion in ["1", "2", "3"]:
            ips = leer_ips_desde_archivo("listaIP.txt")
            mostrar_resultados(ips, opcion)
        elif opcion == "4":
            print(f"{GREEN}Saliendo del programa...{RESET}")
            break
        else:
            print(f"{RED}Opción inválida. Intente nuevamente.{RESET}")

# Ejecución del programa
if __name__ == "__main__":
    mostrar_menu()