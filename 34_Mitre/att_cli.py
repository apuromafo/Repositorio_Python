#!/usr/bin/env python3
import os
import json
import re
from pathlib import Path
from typing import Optional, List, Dict, Any
from rich.console import Console
from rich.table import Table

console = Console()

# Rutas locales
MITRE_DIR = Path("mitre")
MATRIX_PATH = MITRE_DIR / "matrix.json"
MITRE_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json" 


def descargar_json_mitre(force: bool = False):
    """Descargar el archivo JSON de MITRE ATT&CK"""
    if MATRIX_PATH.exists() and not force:
        console.print("[green][*] El archivo MITRE ya existe. Saltando descarga...[/]")
        return

    try:
        console.print("[-] Creando directorio ./mitre/")
        MITRE_DIR.mkdir(exist_ok=True)

        console.print("[-] Descargando MITRE ATT&CK Matrix JSON...")
        import requests
        respuesta = requests.get(MITRE_URL, stream=True)
        respuesta.raise_for_status()

        with open(MATRIX_PATH, 'wb') as f:
            for chunk in respuesta.iter_content(chunk_size=8192):
                f.write(chunk)

        console.print(f"[+] Archivo descargado y guardado en {MATRIX_PATH}")

    except Exception as e:
        console.print(f"[red][!] Error al descargar el archivo JSON: {e}[/]")
        exit(1)


def cargar_datos_ataque():
    """Cargar los datos desde el archivo JSON"""
    if not MATRIX_PATH.exists():
        console.print(f"[red][!] No se encontró el archivo {MATRIX_PATH}[/]")
        console.print("[yellow][*] Usa --update para descargarlo primero.[/]")
        exit(1)

    try:
        with open(MATRIX_PATH, "r", encoding="utf-8") as f:
            datos = json.load(f)
        return datos
    except json.JSONDecodeError as e:
        console.print(f"[red][!] Error al leer el archivo JSON: {e}[/]")
        exit(1)


def obtener_id_mitre(obj: dict) -> Optional[str]:
    """Obtener el MITRE ID desde las referencias externas"""
    refs = obj.get("external_references")
    if not refs or not isinstance(refs, list):
        return None
    for ref in refs:
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def obtener_tecnicas_relacionadas(id_grupo: str, datos: dict) -> list:
    ids_tecnicas = []
    for obj in datos["objects"]:
        if obj["type"] == "relationship" and obj.get("source_ref") == id_grupo and obj.get("relationship_type") == "uses":
            if target := obj.get("target_ref"):
                ids_tecnicas.append(target)

    tecnicas = []
    for obj in datos["objects"]:
        if obj["type"] == "attack-pattern" and obj["id"] in ids_tecnicas:
            tecnicas.append(obj)
    return tecnicas


def obtener_grupos_relacionados(id_tecnica: str, datos: dict) -> list:
    ids_grupos = []
    for obj in datos["objects"]:
        if obj["type"] == "relationship" and obj.get("target_ref") == id_tecnica and obj.get("relationship_type") == "uses":
            if source := obj.get("source_ref"):
                ids_grupos.append(source)

    grupos = []
    for obj in datos["objects"]:
        if obj["type"] == "intrusion-set" and obj["id"] in ids_grupos:
            grupos.append(obj)
    return grupos


def imprimir_separador():
    console.print("[bright_black]" + "─" * 80 + "[/bright_black]")


def imprimir_info_tecnica(obj: dict, datos: dict):
    nombre = obj.get("name", "Desconocido")
    console.print(f"[bright_cyan bold]Nombre:[/] {nombre}")
    mitre_id = obtener_id_mitre(obj)
    if mitre_id:
        console.print(f"[bright_green]ID MITRE:[/] {mitre_id}")
    console.print(f"[bright_yellow]Tipo:[/] {obj['type']}")
    if descripcion := obj.get("description"):
        console.print("\n[bright_white bold]Descripción:[/]\n" + descripcion)

    if tacticas := obj.get("kill_chain_phases"):
        console.print("\n[bright_white bold]Tácticas:[/]")
        for t in tacticas:
            if t["kill_chain_name"] == "mitre-attack":
                console.print(f"  • [bright_magenta]{t['phase_name'].title()}[/]")

    if plataformas := obj.get("x_mitre_platforms"):
        console.print("\n[bright_white bold]Plataformas:[/]")
        for p in plataformas:
            console.print(f"  • [bright_blue]{p}[/]")

    if permisos := obj.get("x_mitre_permissions_required"):
        console.print("\n[bright_white bold]Permisos requeridos:[/]")
        for p in permisos:
            console.print(f"  • [bright_red]{p}[/]")

    if deteccion := obj.get("x_mitre_detection"):
        console.print("\n[bright_white bold]Detección:[/]\n" + deteccion)

    if fuentes := obj.get("x_mitre_data_sources"):
        console.print("\n[bright_white bold]Fuentes de Datos:[/]")
        for f in fuentes:
            console.print(f"  • [bright_cyan]{f}[/]")

    grupos_usan = obtener_grupos_relacionados(obj["id"], datos)
    if grupos_usan:
        console.print("\n[bright_white bold]Grupos que la usan:[/]")
        for g in grupos_usan:
            nombre_grupo = g.get("name", "Desconocido")
            grupo_id = obtener_id_mitre(g) or "N/A"
            console.print(f"  [bright_green][{grupo_id}][/bright_green] {nombre_grupo}")

    if referencias := obj.get("external_references"):
        console.print("\n[bright_white bold]Referencias:[/]")
        for ref in referencias:
            url = ref.get("url")
            if url:
                console.print(f"  • [bright_green]{ref['source_name']}[/bright_green] - [bright_blue underline]{url}[/]")


def imprimir_info_grupo(obj: dict, datos: dict):
    nombre = obj.get("name", "Desconocido")
    console.print(f"[bright_cyan bold]Nombre:[/] {nombre}")
    mitre_id = obtener_id_mitre(obj)
    if mitre_id:
        console.print(f"[bright_green]ID MITRE:[/] {mitre_id}")
    console.print(f"[bright_yellow]Tipo:[/] {obj['type']}")

    if aliases := obj.get("aliases"):
        console.print("\n[bright_white bold]Alias:[/]")
        for a in aliases:
            console.print(f"  • [bright_magenta]{a}[/]")

    if descripcion := obj.get("description"):
        console.print("\n[bright_white bold]Descripción:[/]\n" + descripcion)

    tecnicas_usadas = obtener_tecnicas_relacionadas(obj["id"], datos)
    if tecnicas_usadas:
        mapa_tacticas = {}
        for tecnica in tecnicas_usadas:
            if tacticas := tecnica.get("kill_chain_phases"):
                for phase in tacticas:
                    if phase["kill_chain_name"] == "mitre-attack":
                        tactica_nombre = phase["phase_name"].replace("-", " ").title()
                        mapa_tacticas.setdefault(tactica_nombre, []).append(tecnica)

        tacticas_ordenadas = sorted(mapa_tacticas.items())
        for tactica, tecnicas in tacticas_ordenadas:
            console.print(f"\n[bright_magenta bold]{tactica}:[/]")
            for tech in sorted(tecnicas, key=lambda x: x.get("name", "").lower()):
                nombre_tech = tech.get("name", "Desconocido")
                tech_id = obtener_id_mitre(tech) or "N/A"
                console.print(f"  [bright_green][{tech_id}][/bright_green] {nombre_tech}")
        console.print(f"\n[bright_cyan]Total de Técnicas: {len(tecnicas_usadas)}[/]")

    if referencias := obj.get("external_references"):
        console.print("\n[bright_white bold]Referencias:[/]")
        for ref in referencias:
            url = ref.get("url")
            if url:
                console.print(f"  • [bright_green]{ref['source_name']}[/bright_green] - [bright_blue underline]{url}[/]")


def imprimir_info_tactica(obj: dict):
    nombre = obj.get("name", "Desconocido")
    shortname = obj.get("x_mitre_shortname", "N/A")
    console.print(f"[bright_cyan bold]Nombre:[/] {nombre}")
    console.print(f"[bright_green]Nombre Corto:[/] {shortname}")
    console.print(f"[bright_yellow]Tipo:[/] {obj['type']}")
    if descripcion := obj.get("description"):
        console.print("\n[bright_white bold]Descripción:[/]\n" + descripcion)

    if referencias := obj.get("external_references"):
        console.print("\n[bright_white bold]Referencias:[/]")
        for ref in referencias:
            url = ref.get("url")
            if url:
                console.print(f"  • [bright_green]{ref['source_name']}[/bright_green] - [bright_blue underline]{url}[/]")


def buscar_y_mostrar_tecnica_por_id(tid: str, datos: dict):
    tid_upper = tid.upper()
    encontrado = False
    for obj in datos["objects"]:
        if obj["type"] == "attack-pattern" and obtener_id_mitre(obj) == tid_upper:
            imprimir_info_tecnica(obj, datos)
            encontrado = True
            break
    if not encontrado:
        console.print(f"[red]No se encontró ninguna técnica con el ID '{tid}'[/red]")


def buscar_y_mostrar_tecnica_por_nombre(nombre: str, datos: dict):
    nombre_lower = nombre.lower()
    encontrado = False
    for obj in datos["objects"]:
        if obj["type"] == "attack-pattern" and obj.get("name", "").lower().find(nombre_lower) >= 0:
            if encontrado:
                imprimir_separador()
            imprimir_info_tecnica(obj, datos)
            encontrado = True
    if not encontrado:
        console.print(f"[red]No se encontró ninguna técnica que coincida con '{nombre}'[/red]")


def buscar_y_mostrar_grupo(nombre: str, datos: dict):
    nombre_lower = nombre.lower()
    encontrados = []
    for obj in datos["objects"]:
        if obj["type"] != "intrusion-set":
            continue
        coincide = False
        if obj.get("name", "").lower().find(nombre_lower) >= 0:
            coincide = True
        else:
            for alias in obj.get("aliases", []):
                if alias.lower().find(nombre_lower) >= 0:
                    coincide = True
                    break
        if coincide:
            encontrados.append(obj)

    if not encontrados:
        console.print(f"[red]No se encontró ningún grupo APT que coincida con '{nombre}'[/red]")
    else:
        for i, obj in enumerate(encontrados):
            if i > 0:
                imprimir_separador()
            imprimir_info_grupo(obj, datos)


def mostrar_lista_grupos(datos: dict):
    tabla = Table(title="Grupos APT", show_lines=True)
    tabla.add_column("ID", style="green")
    tabla.add_column("Nombre", style="white")
    tabla.add_column("Alias", style="magenta")

    grupos = [g for g in datos["objects"] if g["type"] == "intrusion-set"]
    grupos.sort(key=lambda x: x.get("name", "").lower())

    for g in grupos:
        nombre = g.get("name", "Desconocido")
        grupo_id = obtener_id_mitre(g) or "N/A"
        alias = ', '.join(g.get("aliases", [])) or "-"
        tabla.add_row(grupo_id, nombre, alias)

    console.print(tabla)


def mostrar_lista_tacitcas(datos: dict):
    tabla = Table(title="Tácticas MITRE", show_lines=True)
    tabla.add_column("Nombre", style="cyan")
    tabla.add_column("Nombre Corto", style="green")
    tabla.add_column("Descripción", style="white")

    tacitcas = [t for t in datos["objects"] if t["type"] == "x-mitre-tactic"]
    tacitcas.sort(key=lambda x: x.get("name", "").lower())

    for t in tacitcas:
        nombre = t.get("name", "Desconocido")
        short = t.get("x_mitre_shortname", "N/A")
        desc = t.get("description", "-")
        tabla.add_row(nombre, short, desc[:100] + "..." if len(desc) > 100 else desc)

    console.print(tabla)


def mostrar_info_tacitca(nombre: str, datos: dict):
    nombre_lower = nombre.lower().replace('-', '_').replace(' ', '_')
    encontrados = []

    for obj in datos["objects"]:
        if obj["type"] != "x-mitre-tactic":
            continue
        match_nombre = obj.get("name", "").lower().replace('-', '_').replace(' ', '_')
        match_short = obj.get("x_mitre_shortname", "").lower().replace('-', '_')
        if nombre_lower in match_nombre or nombre_lower in match_short:
            encontrados.append(obj)

    if not encontrados:
        console.print(f"[red]No se encontró ninguna táctica que coincida con '{nombre}'[/red]")
        mostrar_lista_tacitcas(datos)
        return

    for i, obj in enumerate(encontrados):
        if i > 0:
            imprimir_separador()
        imprimir_info_tactica(obj)

        fase_nombre = obj.get("name", "").lower().replace('-', '_').replace(' ', '_')
        tecnicas_relacionadas = []
        for tech in datos["objects"]:
            if tech["type"] != "attack-pattern":
                continue
            phases = tech.get("kill_chain_phases", [])
            for p in phases:
                if p["kill_chain_name"] == "mitre-attack" and p["phase_name"].lower().replace('-', '_').find(fase_nombre) >= 0:
                    tecnicas_relacionadas.append(tech)
                    break

        if tecnicas_relacionadas:
            console.print(f"\n[bright_white bold]Técnicas relacionadas con {obj['name']}:[/]")
            imprimir_separador()
            tecnicas_relacionadas.sort(key=lambda x: x.get("name", "").lower())
            for tech in tecnicas_relacionadas:
                tech_nombre = tech.get("name", "Desconocido")
                tech_id = obtener_id_mitre(tech) or "N/A"
                console.print(f"[bright_green][{tech_id}][/bright_green] {tech_nombre}")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Herramienta CLI para navegar la matriz MITRE ATT&CK")
    parser.add_argument("--update", action="store_true", help="Forzar descarga del archivo MITRE ATT&CK")

    subparsers = parser.add_subparsers(dest="comando", required=False)

    subparsers.add_parser("apt-list", help="Listar todos los grupos APT")

    apt_parser = subparsers.add_parser("apt", help="Mostrar información de un grupo APT")
    apt_parser.add_argument("nombre", help="Nombre o alias del grupo APT")

    tid_parser = subparsers.add_parser("tid", help="Buscar técnica por ID (ej. T1055)")
    tid_parser.add_argument("id", help="ID de la técnica")

    tn_parser = subparsers.add_parser("tn", help="Buscar técnica por nombre")
    tn_parser.add_argument("nombre", help="Nombre de la técnica")

    tactic_parser = subparsers.add_parser("tactic", help="Mostrar información de una táctica")
    tactic_parser.add_argument("nombre", help="Nombre de la táctica")

    args = parser.parse_args()

    if args.update:
        descargar_json_mitre(force=True)
        return

    if not args.comando:
        parser.print_help()
        return

    datos = cargar_datos_ataque()

    if args.comando == "apt-list":
        mostrar_lista_grupos(datos)
    elif args.comando == "apt":
        buscar_y_mostrar_grupo(args.nombre, datos)
    elif args.comando == "tid":
        buscar_y_mostrar_tecnica_por_id(args.id, datos)
    elif args.comando == "tn":
        buscar_y_mostrar_tecnica_por_nombre(args.nombre, datos)
    elif args.comando == "tactic":
        mostrar_info_tacitca(args.nombre, datos)


if __name__ == "__main__":
    main()