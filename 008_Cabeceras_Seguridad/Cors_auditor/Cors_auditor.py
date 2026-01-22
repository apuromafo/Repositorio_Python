import requests
import os
import json
import shlex
import sys
import argparse
from datetime import datetime
from urllib.parse import urlparse

__version__ = "1.6.0"

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class CORSAuditorMaster:
    def __init__(self, url, headers, proxy_url=None, original_data=""):
        print(f"[*] CORS Auditor Master v{__version__}")
        self.url = url
        self.original_headers = headers
        self.domain = urlparse(self.url).netloc
        self.proxy = {"http": f"http://{proxy_url}", "https": f"http://{proxy_url}"} if proxy_url else None
        
        self.session_dir = f"audit_{self.domain.replace(':', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.vuln_dir = os.path.join(self.session_dir, "Vulnerables")
        self.safe_dir = os.path.join(self.session_dir, "No_Vulnerables")
        
        for d in [self.session_dir, self.vuln_dir, self.safe_dir]:
            if not os.path.exists(d): os.makedirs(d)
            
        with open(f"{self.session_dir}/audit_source.txt", "w") as f:
            f.write(original_data)

    def run_test(self, test_id, attack_origin):
        test_headers = self.original_headers.copy()
        test_headers['Origin'] = attack_origin
        
        try:
            resp = requests.get(self.url, headers=test_headers, proxies=self.proxy, verify=False, timeout=15, allow_redirects=False)
            
            allow_origin = resp.headers.get('Access-Control-Allow-Origin')
            is_vuln = (resp.status_code < 400 and allow_origin == attack_origin)
            
            evidence = {
                "test_id": test_id,
                "verdict": "VULNERABLE" if is_vuln else "NO VULNERABLE",
                "request": {"url": self.url, "origin_sent": attack_origin, "headers": test_headers},
                "response": {"status_code": resp.status_code, "headers": dict(resp.headers)}
            }

            target_folder = self.vuln_dir if is_vuln else self.safe_dir
            with open(f"{target_folder}/{test_id}.json", "w") as f:
                json.dump(evidence, f, indent=4)

            status_color = "\033[91m[ VULNERABLE ]\033[0m" if is_vuln else "[ NO VULNERABLE ]"
            print(f"ID: {test_id.ljust(25)} | Status: {str(resp.status_code).ljust(4)} | {status_color}")

        except Exception as e:
            print(f"[!] Error en {test_id}: {e}")

    def start(self, collaborator=None):
        print(f"[*] Objetivo: {self.url}")
        print(f"[*] Evidencias en: ./{self.session_dir}/\n")
        
        vectors = [
            ("origin_reflected", "https://attacker.com"),
            ("null_origin", "null"),
            ("post_domain_wildcard", f"https://{self.domain}.attacker.com"),
            ("pre_domain_wildcard", f"https://attacker{self.domain}"),
            ("unescaped_dot_regex", f"https://{self.domain.replace('.', 'x')}"),
            ("underscore_bypass", f"https://{self.domain}_.attacker.com"),
            ("broken_parser_backtick", f"https://{self.domain}`.attacker.com"),
            ("http_downgrade", f"http://{self.domain}")
        ]
        if collaborator: vectors.append(("collaborator_exploit", collaborator))

        for tid, origin in vectors:
            self.run_test(tid, origin)

def parse_input(data):
    """Motor de detección inteligente para 3 formatos: JSON, cURL o Raw Headers."""
    data = data.strip()
    
    # CASO 1: JSON (convert_headers.py)
    try:
        js = json.loads(data)
        if "url" in js and "headers" in js:
            return js["url"], js["headers"]
    except: pass

    # CASO 2: cURL (Copy as cURL)
    if data.lower().startswith("curl"):
        try:
            args = shlex.split(data.replace('\\\n', ' '))
            headers = {}
            url = ""
            for i, arg in enumerate(args):
                if arg in ['-H', '--header']:
                    k, v = args[i+1].split(':', 1)
                    headers[k.strip()] = v.strip()
                elif arg.startswith('http'): url = arg
            if url: return url, headers
        except: pass

    # CASO 3: Raw Request / Headers Copy-Paste
    try:
        lines = data.splitlines()
        headers = {}
        for line in lines:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()
        
        # Si es raw headers, pedimos la URL por consola ya que no suele venir en el bloque de headers solo
        if headers:
            url = input("\n[?] Se detectaron Raw Headers. Introduce la URL objetivo: ").strip()
            return url, headers
    except: pass
    
    return None, None

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=f"CORS Auditor Master v{__version__}")
    parser.add_argument("-i", "--input", help="Archivo de entrada (cURL, JSON o Raw)", default="input.txt")
    parser.add_argument("-p", "--proxy", help="Proxy (ej: 127.0.0.1:8080)")
    parser.add_argument("-c", "--collaborator", help="URL Collaborator")
    args = parser.parse_args()

    raw_data = ""
    if os.path.exists(args.input):
        with open(args.input, "r") as f: raw_data = f.read()
    else:
        print(f"[*] Pegue el contenido (cURL, JSON o Headers) y presione Ctrl+D:")
        raw_data = sys.stdin.read()

    if raw_data.strip():
        url, headers = parse_input(raw_data)
        if url and headers:
            if args.collaborator and not args.collaborator.startswith("http"):
                args.collaborator = f"https://{args.collaborator}"
            auditor = CORSAuditorMaster(url, headers, args.proxy, raw_data)
            auditor.start(collaborator=args.collaborator)
        else:
            sys.exit("[!] Error: No se reconoció el formato de entrada.")