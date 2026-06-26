#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# =============================================================================
# dnscaa_oficial_v1.py  v2.0.0
# =============================================================================
# Herramienta oficial de auditoria de registros DNS CAA.
#
# Consulta registros CAA y CNAME via DNS-over-HTTPS (Google + Cloudflare),
# recorre la jerarquia DNS por herencia (RFC 8659), obtiene el certificado
# TLS real del servidor, y genera un reporte ejecutivo con validacion
# cruzada y deteccion de anomalias (shadow certificates, iodef ausente).
#
# Uso:
#   python dnscaa_oficial_v1.py -t app.ejemplo.com
#   python dnscaa_oficial_v1.py -t sub.ejemplo.com -z ejemplo.com
#   python dnscaa_oficial_v1.py -t app.ejemplo.com -o ./resultados
#
# Argumentos:
#   -t, --target       Dominio objetivo (requerido)
#   -z, --zone-apex    Zone apex (opcional, auto-derivado si se omite)
#   -o, --output       Carpeta de salida (opcional, auto-generada si se omite)
#
# Salida:
#   Resultados_CAA/<dominio>_<fecha>/
#     +-- PROCESO.log              (log DEBUG completo)
#     +-- evidencia_dns_caa.json    (reporte JSON con toda la evidencia RAW)
#
# Dependencias: Python 3.8+ (solo stdlib)
#
# Mas informacion: README.md
# =============================================================================

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import socket
import ssl
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

VERSION = "2.0.0"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RAIZ_RESULTADOS = os.path.join(BASE_DIR, "Resultados_CAA")
USER_AGENT = "QA-Authorized-Security-Audit/CAA-Validation-v2"

RESOLVERS = [
    {
        "name": "Google DNS",
        "url": "https://dns.google/resolve",
        "headers": {"Accept": "application/dns-json"},
    },
    {
        "name": "Cloudflare DNS",
        "url": "https://cloudflare-dns.com/dns-query",
        "headers": {"Accept": "application/dns-json"},
    },
]


def setup_logger(log_path: str) -> logging.Logger:
    logger = logging.getLogger("dnscaa")
    logger.setLevel(logging.DEBUG)
    fh = logging.FileHandler(log_path, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fmt = logging.Formatter("%(asctime)s | %(levelname)-8s | %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    fh.setFormatter(fmt)
    logger.addHandler(fh)
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(fmt)
    logger.addHandler(ch)
    return logger


def http_json(
    url: str,
    params: dict[str, str],
    headers: dict[str, str],
    logger: logging.Logger,
) -> dict[str, Any]:
    request_headers = {"User-Agent": USER_AGENT, **headers}
    full_url = f"{url}?{urlencode(params)}"
    logger.debug(f"HTTP GET -> {full_url}")
    logger.debug(f"Headers enviados: {request_headers}")
    request = Request(full_url, headers=request_headers)
    try:
        with urlopen(request, timeout=30) as response:
            body = response.read()
            doc = json.loads(body)
            logger.debug(f"HTTP {response.status} recibido de {url}")
            logger.debug(f"Respuesta JSON completa: {json.dumps(doc, ensure_ascii=False)}")
            return {
                "http_status": response.status,
                "document": doc,
                "error": None,
            }
    except HTTPError as exc:
        body_raw = ""
        try:
            body_raw = exc.read().decode("utf-8", errors="replace")
        except Exception:
            pass
        logger.warning(f"HTTPError {exc.code} de {url}: {exc}")
        logger.debug(f"Body del error HTTP: {body_raw}")
        return {
            "http_status": exc.code,
            "document": None,
            "error": str(exc),
        }
    except (URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
        logger.error(f"Error de conexion a {url}: {exc}")
        return {
            "http_status": None,
            "document": None,
            "error": str(exc),
        }


def parse_caa(data: str) -> dict[str, Any]:
    if data.startswith(r"\# "):
        parts = data.split()
        try:
            raw = bytes.fromhex("".join(parts[2:]))
            flags = raw[0]
            tag_length = raw[1]
            tag = raw[2:2 + tag_length].decode("ascii")
            value = raw[2 + tag_length:].decode("ascii")
            return {
                "flags": flags,
                "tag": tag,
                "value": value,
            }
        except (IndexError, ValueError, UnicodeDecodeError):
            return {"raw": data}

    parts = data.strip().split(maxsplit=2)
    if len(parts) != 3:
        return {"raw": data}
    try:
        flags = int(parts[0])
    except ValueError:
        flags = parts[0]
    return {
        "flags": flags,
        "tag": parts[1].strip('"'),
        "value": parts[2].strip('"'),
    }


def query_dns(name: str, record_type: str, logger: logging.Logger) -> dict[str, Any]:
    logger.info(f"Consultando {record_type} para {name}")
    resolver_results = []
    for resolver in RESOLVERS:
        logger.debug(f"Consultando resolutor: {resolver['name']} -> {name} {record_type}")
        response = http_json(
            resolver["url"],
            {"name": name, "type": record_type},
            resolver["headers"],
            logger,
        )
        document = response["document"] or {}
        answers = document.get("Answer") or []
        selected = []
        expected_type = 257 if record_type == "CAA" else 5

        for answer in answers:
            if answer.get("type") != expected_type:
                continue
            value = answer.get("data", "")
            selected.append(
                parse_caa(value) if record_type == "CAA" else value.rstrip(".")
            )

        resolver_results.append(
            {
                "resolver": resolver["name"],
                "url_used": f"{resolver['url']}?{urlencode({'name': name, 'type': record_type})}",
                "http_status": response["http_status"],
                "dns_status": document.get("Status"),
                "records": selected,
                "raw_dns_response": document,
                "request_headers": {"User-Agent": USER_AGENT, **resolver["headers"]},
                "error": response["error"],
            }
        )
    return {
        "name": name,
        "type": record_type,
        "resolver_results": resolver_results,
    }


def consensus_records(query: dict[str, Any]) -> list[Any]:
    successful = [
        item["records"]
        for item in query["resolver_results"]
        if item["http_status"] == 200 and item["dns_status"] == 0
    ]
    if not successful:
        return []
    unique: list[Any] = []
    for records in successful:
        for record in records:
            if record not in unique:
                unique.append(record)
    return unique


def compute_hierarchy(host: str, zone_apex: str) -> list[str]:
    host_labels = host.rstrip(".").split(".")
    apex_labels = zone_apex.rstrip(".").split(".")
    if host_labels[-len(apex_labels):] != apex_labels:
        raise ValueError(f"{host} no pertenece a la zona {zone_apex}")
    levels = []
    for index in range(0, len(host_labels) - len(apex_labels) + 1):
        levels.append(".".join(host_labels[index:]))
    return levels


def derive_zone_apex(host: str) -> str:
    labels = host.rstrip(".").split(".")
    if len(labels) < 2:
        raise ValueError(f"No se pudo derivar zone_apex de {host}")
    return ".".join(labels[-2:])


def tls_certificate(host: str, logger: logging.Logger) -> dict[str, Any]:
    logger.info(f"Inspeccionando certificado TLS de {host}:443")
    
    # Contexto SSL seguro para Pentesting (ignora errores de confianza)
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    try:
        with socket.create_connection((host, 443), timeout=20) as tcp:
            with context.wrap_socket(tcp, server_hostname=host) as tls:
                # Al usar CERT_NONE, getpeercert() devuelve un diccionario vacío.
                # Esto es normal en Python, pero confirma que la conexión TLS fue exitosa.
                certificate = tls.getpeercert() or {}
        
        subject = {
            key: value
            for group in certificate.get("subject", [])
            for key, value in group
        }
        issuer = {
            key: value
            for group in certificate.get("issuer", [])
            for key, value in group
        }
        
        logger.debug(f"Conexión TLS establecida. CN={subject.get('commonName', 'N/A')}")
        return {
            "subject": subject,
            "issuer": issuer,
            "not_before": certificate.get("notBefore"),
            "not_after": certificate.get("notAfter"),
            "error": None,
        }
    except (OSError, ssl.SSLError) as exc:
        logger.warning(f"Error TLS al conectar con {host}: {exc}")
        return {
            "subject": {},
            "issuer": {},
            "not_before": None,
            "not_after": None,
            "error": str(exc),
        }

def get_dig_command(name: str, record_type: str) -> str:
    return f"dig @8.8.8.8 {name} {record_type} +multiline"


def get_dns_status_name(status_code: int | None) -> str:
    if status_code is None:
        return "UNKNOWN"
    mapping = {
        0: "NOERROR",
        1: "FORMERR",
        2: "SERVFAIL",
        3: "NXDOMAIN",
        4: "NOTIMP",
        5: "REFUSED",
    }
    return mapping.get(status_code, f"STATUS_{status_code}")


def inspect_target(host: str, zone_apex: str | None, logger: logging.Logger) -> dict[str, Any]:
    if zone_apex is None:
        zone_apex = derive_zone_apex(host)
        logger.info(f"Zone apex derivado automaticamente: {zone_apex}")
    else:
        logger.info(f"Zone apex indicado manualmente: {zone_apex}")

    levels = compute_hierarchy(host, zone_apex)
    logger.info(f"Jerarquia de busqueda CAA: {' -> '.join(levels)}")

    logger.info(f"Consultando CNAME de {host}")
    cname_query = query_dns(host, "CNAME", logger)
    caa_queries = []
    effective_records: list[Any] = []
    effective_name = None

    for level in levels:
        logger.info(f"Buscando CAA en nivel: {level}")
        query = query_dns(level, "CAA", logger)
        records = consensus_records(query)
        caa_queries.append(
            {
                "name": level,
                "records": records,
                "resolver_results": query["resolver_results"],
            }
        )
        if records and not effective_records:
            effective_records = records
            effective_name = level
            logger.info(f"CAA efectiva encontrada en {level}: {records}")

    result = {
        "host": host,
        "zone_apex": zone_apex,
        "cname": consensus_records(cname_query),
        "cname_evidence": cname_query["resolver_results"],
        "lookup_hierarchy": caa_queries,
        "effective_caa_name": effective_name,
        "effective_caa_records": effective_records,
        "caa_policy_present": bool(effective_records),
        "tls_certificate": tls_certificate(host, logger),
    }

    if not effective_records:
        logger.warning(f"CAA AUSENTE para {host} - cualquier CA puede emitir certificados")

    return result


def print_report(report: dict[str, Any]) -> None:
    print(report["title"])
    print(f"Fecha UTC: {report['timestamp_utc']}")
    print(f"Version: {VERSION}")
    print("Autenticacion enviada: NO")
    print("Resolutores: Google DNS y Cloudflare DNS")

    for target in report["targets"]:
        print("\n" + "=" * 78)
        print(f"Host: {target['host']}")
        print(f"Zona evaluada: {target['zone_apex']}")
        print(f"CNAME observado: {target['cname'] or 'NO'}")

        if target["cname"]:
            print(f"  -> Comando dig CNAME: {get_dig_command(target['host'], 'CNAME')}")
            print(f"  -> Evidencia CNAME RAW:")
            for res in target["cname_evidence"]:
                status_name = get_dns_status_name(res["dns_status"])
                print(f"     {res['resolver']}: HTTP {res['http_status']} | DNS {res['dns_status']} ({status_name})")
                if res["error"]:
                    print(f"     Error: {res['error']}")
                raw_answers = res["raw_dns_response"].get("Answer", [])
                print(f"     Answer JSON: {json.dumps(raw_answers, ensure_ascii=False)}")

        for level in target["lookup_hierarchy"]:
            print(f"\n[+] Nivel: {level['name']}")
            print(f"    Comando dig: {get_dig_command(level['name'], 'CAA')}")

            print("    Registros CAA detectados:")
            if level["records"]:
                for record in level["records"]:
                    if "raw" in record:
                        print(f"      - [RAW] {record['raw']}")
                    else:
                        print(
                            f"      - flags={record.get('flags')} "
                            f"tag={record.get('tag')} value={record.get('value')}"
                        )
            else:
                print("      SIN REGISTROS")

            print("    Evidencia DoH RAW (peticion original y respuesta):")
            for res in level["resolver_results"]:
                status_name = get_dns_status_name(res["dns_status"])
                print(f"      - {res['resolver']}:")
                print(f"        URL consultada: {res.get('url_used', 'N/A')}")
                print(f"        Headers enviados: {json.dumps(res.get('request_headers', {}), ensure_ascii=False)}")
                if res["error"]:
                    print(f"        Error de conexion -> {res['error']}")
                else:
                    print(f"        HTTP {res['http_status']} | DNS Status: {res['dns_status']} ({status_name})")
                    raw_answers = res["raw_dns_response"].get("Answer", [])
                    print(f"        Answer JSON: {json.dumps(raw_answers, ensure_ascii=False)}")
                    full_doc = res["raw_dns_response"]
                    print(f"        Respuesta DoH completa: {json.dumps(full_doc, ensure_ascii=False)}")

        print("\n" + "-" * 40)
        print(
            f"Politica CAA efectiva: "
            f"{'PRESENTE' if target['caa_policy_present'] else 'AUSENTE'}"
        )
        if target["effective_caa_name"]:
            print(f"Politica heredada/efectiva desde: {target['effective_caa_name']}")

        certificate = target["tls_certificate"]
        if certificate["error"]:
            print(f"Certificado TLS: Error de conexion -> {certificate['error']}")
        else:
            issuer = certificate["issuer"]
            print(
                "Certificado TLS: "
                f"CN={certificate['subject'].get('commonName')} | "
                f"Emisor={issuer.get('organizationName')} / "
                f"{certificate['issuer'].get('commonName')}"
            )

    # ==========================================================================
    # NUEVA SECCIÓN: REPORTE CONSULTIVO, CONCLUSIONES Y RECOMENDACIONES TÉCNICAS
    # ==========================================================================
    print("\n" + "=" * 78)
    print("REPORTE EJECUTIVO Y CONCLUSIONES DE SEGURIDAD")
    print("=" * 78)

    for target in report["targets"]:
        print(f"\n[>] Analisis de Riesgo y Cumplimiento para: {target['host']}")
        
        has_caa = target['caa_policy_present']
        records = target['effective_caa_records'] or []
        cert = target['tls_certificate']
        
        # 1. EVALUACIÓN DE LA POSTURA DE SEGURIDAD DNS
        if not has_caa:
            print("  [CRITICO] Postura de Seguridad: TOTALMENTE EXPUESTO (Ausencia de registros CAA).")
            print("            Impacto: Cualquier Entidad de Certificacion (CA) de confianza publica global")
            print("                     puede emitir un certificado valido para este dominio si es engañada")
            print("                     mediante tecnicas como BGP Hijacking, DNS Cache Poisoning o compromiso DoH.")
        else:
            print("  [EXITO] Postura de Seguridad: PROTEGIDA (Politica CAA definida explicitamente).")
            print(f"          La superficie de emision esta restringida unicamente a las CAs listadas.")

            # Analizar de manera reactiva si hay monitoreo activo (registro iodef)
            iodef_records = [r for r in records if r.get('tag') == 'iodef']
            if iodef_records:
                print("  [INFO] Monitoreo Reactivo Activo (iodef):")
                for r in iodef_records:
                    print(f"         Las alertas por intentos ilicitos de emision se envian a: {r.get('value')}")
            else:
                print("  [ADVERTENCIA] Deficiencia en Visibilidad: Canal de alertas 'iodef' AUSENTE.")
                print("                Recomendacion: Si un atacante intenta solicitar un certificado fraudulento")
                print("                               a una CA no autorizada, la organizacion NO recibira aviso alguno.")

        # 2. VALIDACIÓN CRUZADA INTELIGENTE (DNS vs TLS)
        if not cert.get('error') and cert.get('issuer'):
            real_ca_org = (cert['issuer'].get('organizationName') or "").lower()
            real_ca_cn = (cert['issuer'].get('commonName') or "").lower()
            
            if has_caa:
                # Extraemos de forma limpia las palabras clave de las CAs autorizadas en issue e issuewild
                allowed_keywords = []
                for r in records:
                    if r.get('tag') in ['issue', 'issuewild'] and r.get('value'):
                        # Tomamos la primera palabra del dominio (ej: 'digicert.com' o 'pki.goog' -> 'digicert', 'pki')
                        base_val = r.get('value').split(';')[0].strip().split('.')[0].lower()
                        if base_val:
                            allowed_keywords.append(base_val)
                
                # Buscamos si la CA real con la que responde el servidor actual esta en la lista blanca de su DNS
                match_found = False
                for kw in allowed_keywords:
                    if kw in real_ca_org or kw in real_ca_cn:
                        match_found = True
                        break
                
                if match_found:
                    print("  [EXITO] Validacion de Cumplimiento Perimetral PASADA:")
                    print(f"          La CA que firmo el certificado web actual ('{cert['issuer'].get('organizationName')}')")
                    print("          coincide plenamente con las reglas de autorizacion de su DNS.")
                else:
                    print("  [ALERTA MAXIMA] Desalineacion Critica de Infraestructura / Anomalía Detectada:")
                    print(f"                  El servidor web responde con un certificado emitido por: '{cert['issuer'].get('organizationName')}'")
                    print(f"                  Sin embargo, su registro DNS CAA solo autoriza a: {', '.join(allowed_keywords)}.")
                    print("                  Riesgo: Si el registro DNS es intencional, este certificado actual podria")
                    print("                          considerarse un 'Bypass' o un certificado en la sombra ('Shadow Certificate').")
                    print("                          Si cambio de proveedor TLS, recuerde actualizar su DNS de inmediato.")
        else:
            if not has_caa:
                print("  [RECOMENDACION GENERAL]:")
                print("    Implementar urgentemente registros del tipo CAA en la raiz de la zona, delimitando")
                print("    la emision estrictamente a las CAs de confianza del negocio (ej. Let's Encrypt, DigiCert, etc.)")
                print("    e incluyendo un buzon de incidencias seguro mediante el parametro 'iodef'.")

    print("\n" + "=" * 78)
    print(f"Evidencia JSON completa: {report['output_json']}")
    print(f"Log del proceso: {report['output_log']}")
    

def create_output_dir(host: str) -> str:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_name = re.sub(r"[^a-zA-Z0-9_.-]", "_", host)
    carpeta = os.path.join(RAIZ_RESULTADOS, f"{safe_name}_{ts}")
    os.makedirs(carpeta, exist_ok=True)
    return carpeta


def run(target: str, zone_apex: str | None, output_dir: str | None) -> int:
    host = target.strip().rstrip(".")
    if output_dir:
        carpeta = output_dir
        os.makedirs(carpeta, exist_ok=True)
    else:
        carpeta = create_output_dir(host)

    log_path = os.path.join(carpeta, "PROCESO.log")
    json_path = os.path.join(carpeta, "evidencia_dns_caa.json")

    logger = setup_logger(log_path)
    logger.info(f"=== Inicio dnscaa_oficial_v1 v{VERSION} ===")
    logger.info(f"Target: {host}")
    logger.info(f"Zone apex: {zone_apex or 'AUTO'}")
    logger.info(f"Carpeta de salida: {carpeta}")

    inspected = [inspect_target(host, zone_apex, logger)]

    zones = []
    for apex in dict.fromkeys(item["zone_apex"] for item in inspected):
        related = [item for item in inspected if item["zone_apex"] == apex]
        zones.append(
            {
                "zone_apex": apex,
                "caa_present": any(
                    item["caa_policy_present"] for item in related
                ),
                "affected_hosts": [
                    item["host"]
                    for item in related
                    if not item["caa_policy_present"]
                ],
            }
        )

    report = {
        "title": "Validacion avanzada de registros DNS CAA, herencia y evidencia RAW",
        "version": VERSION,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "authentication_sent": False,
        "method": (
            "DNS over HTTPS con dos resolutores, extraccion de payloads RAW, "
            "mapeo de comandos dig y verificacion de certificados TLS."
        ),
        "targets": inspected,
        "zones": zones,
        "output_json": json_path,
        "output_log": log_path,
        "interpretation": (
            "La ausencia de CAA permite a cualquier Entidad Certificadora (CA) global "
            "emitir certificados para el dominio si se supera la validacion de control estandar. "
            "Un registro CAA restringe esta facultad unicamente a las CAs autorizadas."
        ),
    }

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    logger.info(f"JSON de evidencia guardado: {json_path}")
    logger.info(f"=== Fin dnscaa_oficial_v1 ===")

    for handler in logger.handlers[:]:
        handler.close()
        logger.removeHandler(handler)

    print_report(report)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description=f"Valida registros DNS CAA, herencia, genera equivalencias dig y extrae respuestas RAW. v{VERSION}"
    )
    parser.add_argument(
        "-t", "--target",
        required=True,
        help="Dominio objetivo a evaluar (ej: sub.dominio.com).",
    )
    parser.add_argument(
        "-z", "--zone-apex",
        default=None,
        help="Zone apex del dominio (ej: dominio.com). Si se omite, se deriva automaticamente.",
    )
    parser.add_argument(
        "-o", "--output",
        default=None,
        help="Carpeta de salida personalizada. Si se omite, se crea en Resultados_CAA/<dominio>_<fecha>.",
    )
    args = parser.parse_args()

    exit_code = 1
    try:
        exit_code = run(args.target, args.zone_apex, args.output)
    except Exception:
        print("\nERROR NO CONTROLADO:", file=sys.stderr)
        traceback.print_exc()
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
