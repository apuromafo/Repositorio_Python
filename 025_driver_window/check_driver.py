#!/usr/bin/env python
description = 'Herramienta para validar drivers vulnerables en windows'
author = 'Apuromafo'
version = '0.0.1'
date = '22.01.2025'
# ======================================
# Requires the following deps:
# pip install xmltodict, requests, bs4
# ======================================
from argparse import ArgumentParser
from pathlib import Path
import requests
import zipfile
import xmltodict
from bs4 import BeautifulSoup
from dataclasses import dataclass

@dataclass
class Driver:
    name: str
    sha: str = ""
    
    def __post_init__(self):
        self.name = self.name.lower().split(" ")[0].strip()
        self.sha = self.sha.lower().strip() if self.sha else ""
    
    def __eq__(self, other):
        if not isinstance(other, Driver):
            return False
        return self.name == other.name or self.sha == other.sha
    
    def __hash__(self):
        # Necesario para usar Driver en conjuntos (sets)
        return hash((self.name, self.sha))
    
    def __str__(self):
        return f"Driver (name='{self.name}', hash='{self.sha}')"

class DriverBlockListChecker:
    def __init__(self, target="Enforced", verbose=False):
        self.verbose = verbose
        self.lol_url = "https://www.loldrivers.io/"
        self.win_url = "https://aka.ms/VulnerableDriverBlockList"
        self.lol_drivers = []
        self.win_bl_drivers = set()  # Usamos un conjunto para búsquedas más rápidas
        self.temp_dir = Path("temp")
        self.temp_dir.mkdir(exist_ok=True)
        self.win_block_policy_zip = self.temp_dir.joinpath("blocklist.zip")
        self.win_block_policy_xml = self.temp_dir.joinpath(f"VulnerableDriverBlockList/SiPolicy_{target}.xml")

    def get_lol_blocklist(self):
        """Obtiene la lista de bloqueos de LoL y la almacena en `lol_drivers`."""
        try:
            print("[*] Getting LoL Blocklist...")
            r = requests.get(self.lol_url)
            r.raise_for_status()
            soup = BeautifulSoup(r.text, features="html.parser")
            rows = soup.find_all("tr", {"class": "row"})
            for row in rows:
                tds = row.find_all("td")
                details = [td.get_text().strip() for td in tds]
                self.lol_drivers.append(Driver(details[0], details[1]))
        except requests.RequestException as e:
            print(f"Error al obtener la lista de bloqueos de LoL: {e}")

    def get_windows_blocklist(self):
        """Obtiene la lista de bloqueos de Windows y la almacena en `win_bl_drivers`."""
        try:
            print("[*] Getting Windows Blocklist...")
            r = requests.get(self.win_url, allow_redirects=True)
            r.raise_for_status()
            with open(self.win_block_policy_zip, "wb") as _out:
                _out.write(r.content)
            with zipfile.ZipFile(self.win_block_policy_zip, "r") as zip_ref:
                zip_ref.extractall("temp")
            self.win_block_policy_zip.unlink(missing_ok=True)
            with open(self.win_block_policy_xml, "r", encoding="utf-8", errors="ignore") as _in:
                text = _in.read()
            policies = xmltodict.parse(text).get("SiPolicy", {}).get("FileRules", {}).get("Deny", {})
            for policy in policies:
                self.win_bl_drivers.add(
                    Driver(policy.get("@FriendlyName"), policy.get("@Hash"))
                )
        except (requests.RequestException, zipfile.BadZipFile, FileNotFoundError) as e:
            print(f"Error al obtener la lista de bloqueos de Windows: {e}")

    def is_driver_blocked(self, driver):
        """Verifica si un driver está bloqueado por Microsoft."""
        return driver in self.win_bl_drivers

    def print_drivers(self, drivers, blocked=True):
        """Imprime los drivers según si están bloqueados o no."""
        counter = 0
        for driver in drivers:
            if self.is_driver_blocked(driver) == blocked:
                counter += 1
                if self.verbose:
                    status = "blocked" if blocked else "not blocked"
                    print(f"[-] Driver {driver} {status} by Microsoft")
        return counter

    def get_missing(self):
        """Imprime los drivers de LoL que no están bloqueados por Microsoft."""
        counter = self.print_drivers(self.lol_drivers, blocked=False)
        print(f"[+] Microsoft does not block {counter} vulnerable drivers")

    def get_matching(self):
        """Imprime los drivers de LoL que están bloqueados por Microsoft."""
        counter = self.print_drivers(self.lol_drivers, blocked=True)
        print(f"[+] Microsoft does block {counter} vulnerable drivers")

    def cleanup(self):
        """Limpia los archivos temporales creados durante la ejecución."""
        if self.win_block_policy_zip.exists():
            self.win_block_policy_zip.unlink(missing_ok=True)
        if self.win_block_policy_xml.exists():
            self.win_block_policy_xml.unlink(missing_ok=True)

if __name__ == "__main__":
    parser = ArgumentParser(description="Simple Driver Blocklist Checker")
    parser.add_argument("-v", "--verbose", action="store_true", help="Print verbose output")
    parser.add_argument("-t", "--target", choices=["Enforced", "Audit"], default="Enforced",
                        help="Select Driver Blocklist to check against")
    args = parser.parse_args()
    dblchk = DriverBlockListChecker(target=args.target, verbose=args.verbose)
    dblchk.get_lol_blocklist()
    dblchk.get_windows_blocklist()
    dblchk.get_missing()
    dblchk.get_matching()
    dblchk.cleanup()