import requests
import os
import json
import shlex
import sys
import argparse
from datetime import datetime
from urllib.parse import urlparse

__version__ = "5.0.0"

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class CORSAuditorMaster:
    def __init__(self, url, headers, proxy_url=None):
        # Limpieza básica de URL
        if not url.startswith('http'):
            url = 'https://' + url
        self.url = url
        self.original_headers = headers
        self.domain = urlparse(self.url).netloc
        self.proxy = {"http": f"http://{proxy_url}", "https": f"http://{proxy_url}"} if proxy_url else None
        
        self.session_dir = f"audit_{self.domain.replace(':', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        if not os.path.exists(self.session_dir): os.makedirs(self.session_dir)
        
        self.report_path = os.path.join(self.session_dir, "REPORTE_TECNICO_AUDITORIA.txt")
        self.summary_table = []
        self.init_report()

    def init_report(self):
        with open(self.report_path, "w", encoding="utf-8") as f:
            f.write(f"{'='*100}\n")
            f.write(f"INFORME DE AUDITORÍA TÉCNICA - CONTROL DE ACCESO Y CORS\n")
            f.write(f"OBJETIVO: {self.url}\n")
            f.write(f"FECHA: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"{'='*100}\n\n")
            
            f.write("DICCIONARIO DE ESCENARIOS Y RIESGOS:\n")
            f.write("-" * 40 + "\n")
            f.write("1. ROBO DE SESIÓN (CORS + CREDS): Acceso total a datos privados del usuario.\n")
            f.write("2. REFLEJO DE ORIGIN: El servidor confía en cualquier atacante.\n")
            f.write("3. EJECUCIÓN SIN FILTRO: El server procesa la acción aunque el navegador bloquee la lectura.\n\n")
            f.write(f"{'='*100}\n\n")

    def generate_curl(self, attack_origin):
        curl_cmd = f"curl -i -s -k -X GET '{self.url}'"
        curl_cmd += f" -H 'Origin: {attack_origin}'"
        for k, v in self.original_headers.items():
            if k.lower() != 'origin':
                val = str(v).replace("'", "'\\''")
                curl_cmd += f" -H '{k}: {val}'"
        return curl_cmd

    def run_test(self, test_id, attack_origin):
        test_headers = self.original_headers.copy()
        test_headers['Origin'] = attack_origin
        ts_start = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        
        try:
            resp = requests.get(self.url, headers=test_headers, proxies=self.proxy, verify=False, timeout=12, allow_redirects=False)
            
            aca_header = resp.headers.get('Access-Control-Allow-Origin')
            acac_header = resp.headers.get('Access-Control-Allow-Credentials')
            is_reflected = (aca_header == attack_origin or aca_header == "*" or aca_header == "null")
            has_credentials = (acac_header.lower() == "true") if acac_header else False
            server_blocked = (resp.status_code >= 400)
            
            if is_reflected and has_credentials:
                verdict, color = "VULN: ROBO DE SESIÓN (CORS + CREDS)", "\033[91m"
            elif is_reflected:
                verdict, color = "VULN: REFLEJO DE ORIGIN", "\033[93m"
            elif not server_blocked:
                verdict, color = "VULN: EJECUCIÓN SIN FILTRO (CSRF/CORS-BYPASS)", "\033[35m"
            else:
                verdict, color = "CONTROLADO: BLOQUEO POR STATUS", "\033[92m"

            self.summary_table.append((test_id, attack_origin, resp.status_code, verdict))

            with open(self.report_path, "a", encoding="utf-8") as f:
                f.write(f"--- PRUEBA: {test_id} | {ts_start} ---\n")
                f.write(f"VERDICTO: {verdict}\n")
                f.write(f"STATUS HTTP: {resp.status_code}\n\n")
                f.write(">> REPRODUCCIÓN (CURL):\n")
                f.write(f"{self.generate_curl(attack_origin)}\n\n")
                f.write("<< HEADERS DE RESPUESTA:\n")
                for k, v in resp.headers.items():
                    f.write(f"{k}: {v}\n")
                f.write(f"\n{'-'*100}\n\n")

            print(f"[{ts_start.split()[1]}] {test_id.ljust(22)} | {color}{verdict.ljust(35)}\033[0m | Status: {resp.status_code}")

        except Exception as e:
            print(f"[!] Error en {test_id}: {e}")

    def finalize(self):
        with open(self.report_path, "a", encoding="utf-8") as f:
            f.write(f"\nRESUMEN FINAL\n{'='*100}\n")
            for row in self.summary_table:
                f.write(f"{row[0]:<25} | {row[1]:<35} | {row[2]:<7} | {row[3]}\n")
        print(f"\n[+] Auditoría terminada. Reporte en: {self.report_path}")

    def start(self, collaborator=None):
        # El dominio base para pruebas de sufijo/prefijo
        base_domain = self.domain

        vectors = [
            ("Reflejo_Directo", "https://attacker.com"),
            ("Origen_Null", "null"),
            # Bypasses detectados en tu log de Burp:
            ("Suffix_Bypass", f"https://{base_domain}.attacker.com"),
            ("Prefix_Bypass", f"https://attacker{base_domain}"),
            ("Subdomain_Bypass", f"https://attackerapiappqa.{base_domain}"),
            
            # Vectores de evasión de Regex comunes:
            ("Underscore_Bypass", f"https://{base_domain.replace('.', '_')}.com"),
            ("Dot_Suffix_Bypass", f"https://{base_domain}_.attacker.com"),
            ("Backtick_Bypass", f"https://{base_domain}`.attacker.com"),
            
            # Protocolos e IPs:
            ("Insecure_HTTP", f"http://{base_domain}"),
            ("Localhost_Test", "http://localhost"),
            ("IP_Reflect", "http://127.0.0.1"),
        ]

        if collaborator:
            vectors.append(("Out_Of_Band_Test", collaborator))

        print(f"[*] Iniciando auditoría extendida para: {self.url}")
        print(f"{'-'*85}")
        
        for tid, origin in vectors:
            self.run_test(tid, origin)
            
        # Prueba Extra: X-Forwarded-Host (A veces causa reflejo indirecto)
        self.test_forwarded_headers()
        
        self.finalize()

    def test_forwarded_headers(self):
        """Prueba si el servidor refleja el origen mediante headers de forwarding"""
        test_id = "X-Forwarded-Host-Test"
        attack_origin = "attacker.com"
        headers = self.original_headers.copy()
        headers['X-Forwarded-Host'] = attack_origin
        
        try:
            resp = requests.get(self.url, headers=headers, proxies=self.proxy, verify=False, timeout=10)
            aca_header = resp.headers.get('Access-Control-Allow-Origin')
            if aca_header == attack_origin:
                verdict = "VULN: REFLEJO POR X-FORWARDED-HOST"
                print(f"[!] {test_id.ljust(22)} | \033[91m{verdict}\033[0m")
                self.summary_table.append((test_id, f"X-FH: {attack_origin}", resp.status_code, verdict))
        except:
            pass

def parse_input(data):
    if not data: return None, None
    data = data.strip()
    if data.lower().startswith("curl"):
        try:
            args = shlex.split(data.replace('\\\n', ' '))
            headers = {}
            url = ""
            for i, arg in enumerate(args):
                if arg in ['-H', '--header']:
                    parts = args[i+1].split(':', 1)
                    if len(parts) == 2: headers[parts[0].strip()] = parts[1].strip()
                elif arg.startswith('http'): url = arg
            return url, headers
        except: pass
    
    lines = data.splitlines()
    headers = {}
    for line in lines:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()
    return None, headers

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CORS Forensic Auditor Master")
    parser.add_argument("-u", "--url", help="URL objetivo (Modo Manual)")
    parser.add_argument("-H", "--header", action='append', help="Añadir Header manual (Ej: -H 'Authorization: Bearer...')")
    parser.add_argument("-i", "--input", help="Archivo con cURL o Raw Headers")
    parser.add_argument("-p", "--proxy", help="Proxy (127.0.0.1:8080)")
    parser.add_argument("-c", "--collaborator", help="URL Collaborator")
    args = parser.parse_args()

    url, headers = None, {}

    # Lógica de entrada inteligente
    if args.url:
        # MODO MANUAL POR ARGUMENTOS
        url = args.url
        if args.header:
            for h in args.header:
                if ":" in h:
                    k, v = h.split(":", 1)
                    headers[k.strip()] = v.strip()
    elif args.input and os.path.exists(args.input):
        # MODO ARCHIVO
        with open(args.input, "r") as f:
            url, headers = parse_input(f.read())
    else:
        # MODO INTERACTIVO (STDOUT)
        print("[*] No se detectó URL. Pegue cURL/Headers y presione Ctrl+D (o use -u):")
        raw_data = sys.stdin.read()
        if raw_data.strip():
            url, headers = parse_input(raw_data)
            if not url:
                url = input("\n[?] URL objetivo: ").strip()

    # Validar y Ejecutar
    if url:
        # Asegurar User-Agent básico si no existe
        if 'User-Agent' not in headers:
            headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Auditor/5.0'
        
        auditor = CORSAuditorMaster(url, headers, args.proxy)
        auditor.start(collaborator=args.collaborator)
    else:
        print("\n[!] Error: Se requiere al menos una URL (-u) o una entrada válida.")