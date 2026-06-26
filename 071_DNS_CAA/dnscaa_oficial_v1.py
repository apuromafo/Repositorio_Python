#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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
#   python dnscaa_oficial_v1.py -t example.com --lang en
#
# Argumentos:
#   -t, --target       Dominio objetivo (requerido)
#   -z, --zone-apex    Zone apex (opcional, auto-derivado si se omite)
#   -o, --output       Carpeta de salida (opcional, auto-generada si se omite)
#   --lang             Idioma: es (espanol) / en (english) [default: es]
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

VERSION = "2.1.0"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RAIZ_RESULTADOS = os.path.join(BASE_DIR, "Resultados_CAA")
USER_AGENT = "QA-Authorized-Security-Audit/CAA-Validation-v2"

LANG = "es"

TR: dict[str, dict[str, str]] = {
    "es": {
        "title": "Validacion avanzada de registros DNS CAA, herencia y evidencia RAW",
        "fecha_utc": "Fecha UTC",
        "version": "Version",
        "auth_no": "Autenticacion enviada: NO",
        "resolutores": "Resolutores: Google DNS y Cloudflare DNS",
        "host": "Host",
        "zona_evaluada": "Zona evaluada",
        "cname_obs": "CNAME observado",
        "si": "SI",
        "no": "NO",
        "dig_cname": "Comando dig CNAME",
        "evidencia_cname_raw": "Evidencia CNAME RAW",
        "error": "Error",
        "nivel": "Nivel",
        "dig_caa": "Comando dig CAA",
        "registros_caa": "Registros CAA detectados",
        "sin_registros": "SIN REGISTROS",
        "header_peticion": "Evidencia DoH RAW (peticion original y respuesta)",
        "url_consultada": "URL consultada",
        "headers_enviados": "Headers enviados",
        "error_conexion": "Error de conexion",
        "respuesta_completa": "Respuesta DoH completa",
        "politica_efectiva": "Politica CAA efectiva",
        "presente": "PRESENTE",
        "ausente": "AUSENTE",
        "politica_heredada": "Politica heredada/efectiva desde",
        "cert_tls_error": "Certificado TLS: Error de conexion",
        "cert_tls": "Certificado TLS",
        "emisor": "Emisor",
        "reporte_ejecutivo": "REPORTE EJECUTIVO Y CONCLUSIONES DE SEGURIDAD",
        "analisis_riesgo": "Analisis de Riesgo y Cumplimiento para",
        "critico_expuesto": "[CRITICO] Postura de Seguridad: TOTALMENTE EXPUESTO (Ausencia de registros CAA).",
        "critico_impacto": "Impacto: Cualquier Entidad de Certificacion (CA) de confianza publica global",
        "critico_impacto2": "puede emitir un certificado valido para este dominio si es enganada",
        "critico_impacto3": "mediante tecnicas como BGP Hijacking, DNS Cache Poisoning o compromiso DoH.",
        "exito_protegida": "[EXITO] Postura de Seguridad: PROTEGIDA (Politica CAA definida explicitamente).",
        "exito_restringida": "La superficie de emision esta restringida unicamente a las CAs listadas.",
        "monitoreo_activo": "[INFO] Monitoreo Reactivo Activo (iodef):",
        "monitoreo_alerta": "Las alertas por intentos ilicitos de emision se envian a",
        "iodef_ausente": "[ADVERTENCIA] Deficiencia en Visibilidad: Canal de alertas 'iodef' AUSENTE.",
        "iodef_recomendacion": "Recomendacion: Si un atacante intenta solicitar un certificado fraudulento",
        "iodef_recomendacion2": "a una CA no autorizada, la organizacion NO recibira aviso alguno.",
        "validacion_pasada": "[EXITO] Validacion de Cumplimiento Perimetral PASADA:",
        "validacion_pasada_ca": "La CA que firmo el certificado web actual",
        "validacion_pasada_coincide": "coincide plenamente con las reglas de autorizacion de su DNS.",
        "alerta_shadow": "[ALERTA MAXIMA] Desalineacion Critica de Infraestructura / Anomalia Detectada:",
        "alerta_shadow_servidor": "El servidor web responde con un certificado emitido por",
        "alerta_shadow_dns": "Sin embargo, su registro DNS CAA solo autoriza a",
        "alerta_shadow_riesgo": "Riesgo: Si el registro DNS es intencional, este certificado actual podria",
        "alerta_shadow_riesgo2": "considerarse un 'Bypass' o un certificado en la sombra ('Shadow Certificate').",
        "alerta_shadow_riesgo3": "Si cambio de proveedor TLS, recuerde actualizar su DNS de inmediato.",
        "recomendacion_general": "[RECOMENDACION GENERAL]:",
        "recomendacion_implementar": "Implementar urgentemente registros del tipo CAA en la raiz de la zona, delimitando",
        "recomendacion_implementar2": "la emision estrictamente a las CAs de confianza del negocio (ej. Let's Encrypt, DigiCert, etc.)",
        "recomendacion_implementar3": "e incluyendo un buzon de incidencias seguro mediante el parametro 'iodef'.",
        "evidencia_json": "Evidencia JSON completa",
        "log_proceso": "Log del proceso",
        "respuesta_json": "Answer JSON",
        "separador": "=",
        "separador_corto": "-",
    },
    "en": {
        "title": "Advanced DNS CAA record validation, inheritance and RAW evidence",
        "fecha_utc": "UTC Date",
        "version": "Version",
        "auth_no": "Authentication sent: NO",
        "resolutores": "Resolvers: Google DNS and Cloudflare DNS",
        "host": "Host",
        "zona_evaluada": "Zone evaluated",
        "cname_obs": "CNAME observed",
        "si": "YES",
        "no": "NO",
        "dig_cname": "dig CNAME command",
        "evidencia_cname_raw": "CNAME RAW evidence",
        "error": "Error",
        "nivel": "Level",
        "dig_caa": "dig CAA command",
        "registros_caa": "Detected CAA records",
        "sin_registros": "NO RECORDS",
        "header_peticion": "DoH RAW evidence (original request and response)",
        "url_consultada": "Queried URL",
        "headers_enviados": "Sent headers",
        "error_conexion": "Connection error",
        "respuesta_completa": "Complete DoH response",
        "politica_efectiva": "Effective CAA policy",
        "presente": "PRESENT",
        "ausente": "ABSENT",
        "politica_heredada": "Inherited/effective policy from",
        "cert_tls_error": "TLS Certificate: Connection error",
        "cert_tls": "TLS Certificate",
        "emisor": "Issuer",
        "reporte_ejecutivo": "EXECUTIVE REPORT AND SECURITY CONCLUSIONS",
        "analisis_riesgo": "Risk and Compliance Analysis for",
        "critico_expuesto": "[CRITICAL] Security Posture: FULLY EXPOSED (No CAA records found).",
        "critico_impacto": "Impact: Any globally trusted public Certificate Authority (CA)",
        "critico_impacto2": "can issue a valid certificate for this domain if deceived",
        "critico_impacto3": "via BGP Hijacking, DNS Cache Poisoning or DoH compromise.",
        "exito_protegida": "[PASS] Security Posture: PROTECTED (Explicit CAA policy defined).",
        "exito_restringida": "Issuance surface is restricted to the listed CAs only.",
        "monitoreo_activo": "[INFO] Reactive Monitoring Active (iodef):",
        "monitoreo_alerta": "Alerts for unauthorized issuance attempts are sent to",
        "iodef_ausente": "[WARNING] Visibility Deficiency: 'iodef' alert channel ABSENT.",
        "iodef_recomendacion": "Recommendation: If an attacker attempts to request a fraudulent certificate",
        "iodef_recomendacion2": "from an unauthorized CA, the organization will receive NO notification.",
        "validacion_pasada": "[PASS] Perimeter Compliance Validation PASSED:",
        "validacion_pasada_ca": "The CA that signed the current web certificate",
        "validacion_pasada_coincide": "fully matches the authorization rules in your DNS.",
        "alerta_shadow": "[MAX ALERT] Critical Infrastructure Misalignment / Anomaly Detected:",
        "alerta_shadow_servidor": "The web server responds with a certificate issued by",
        "alerta_shadow_dns": "However, your DNS CAA record only authorizes",
        "alerta_shadow_riesgo": "Risk: If the DNS record is intentional, this current certificate could",
        "alerta_shadow_riesgo2": "be considered a 'Bypass' or a 'Shadow Certificate'.",
        "alerta_shadow_riesgo3": "If you changed TLS providers, remember to update your DNS immediately.",
        "recomendacion_general": "[GENERAL RECOMMENDATION]:",
        "recomendacion_implementar": "Urgently implement CAA records at the zone root, restricting",
        "recomendacion_implementar2": "issuance strictly to your trusted CAs (e.g. Let's Encrypt, DigiCert, etc.)",
        "recomendacion_implementar3": "and include a secure incident mailbox via the 'iodef' parameter.",
        "evidencia_json": "Full JSON evidence",
        "log_proceso": "Process log",
        "respuesta_json": "Answer JSON",
        "separador": "=",
        "separador_corto": "-",
    },
}


def _(key: str, **kwargs: Any) -> str:
    t = TR.get(LANG, TR["es"]).get(key, key)
    if kwargs:
        t = t.format(**kwargs)
    return t


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

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, 443), timeout=20) as tcp:
            with context.wrap_socket(tcp, server_hostname=host) as tls:
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

        logger.debug(f"Conexion TLS establecida. CN={subject.get('commonName', 'N/A')}")
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
    sep = _("separador") * 78
    sep_short = _("separador_corto") * 40

    print(report["title"])
    print(f"{_('fecha_utc')}: {report['timestamp_utc']}")
    print(f"{_('version')}: {VERSION}")
    print(_("auth_no"))
    print(_("resolutores"))

    for target in report["targets"]:
        print(f"\n{sep}")
        print(f"{_('host')}: {target['host']}")
        print(f"{_('zona_evaluada')}: {target['zone_apex']}")
        print(f"{_('cname_obs')}: {target['cname'] or _('no')}")

        if target["cname"]:
            print(f"  -> {_('dig_cname')}: {get_dig_command(target['host'], 'CNAME')}")
            print(f"  -> {_('evidencia_cname_raw')}:")
            for res in target["cname_evidence"]:
                status_name = get_dns_status_name(res["dns_status"])
                print(f"     {res['resolver']}: HTTP {res['http_status']} | DNS {res['dns_status']} ({status_name})")
                if res["error"]:
                    print(f"     {_('error')}: {res['error']}")
                raw_answers = res["raw_dns_response"].get("Answer", [])
                print(f"     {_('respuesta_json')}: {json.dumps(raw_answers, ensure_ascii=False)}")

        for level in target["lookup_hierarchy"]:
            print(f"\n[+] {_('nivel')}: {level['name']}")
            print(f"    {_('dig_caa')}: {get_dig_command(level['name'], 'CAA')}")

            print(f"    {_('registros_caa')}:")
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
                print(f"      {_('sin_registros')}")

            print(f"    {_('header_peticion')}:")
            for res in level["resolver_results"]:
                status_name = get_dns_status_name(res["dns_status"])
                print(f"      - {res['resolver']}:")
                print(f"        {_('url_consultada')}: {res.get('url_used', 'N/A')}")
                print(f"        {_('headers_enviados')}: {json.dumps(res.get('request_headers', {}), ensure_ascii=False)}")
                if res["error"]:
                    print(f"        {_('error_conexion')} -> {res['error']}")
                else:
                    print(f"        HTTP {res['http_status']} | DNS Status: {res['dns_status']} ({status_name})")
                    raw_answers = res["raw_dns_response"].get("Answer", [])
                    print(f"        {_('respuesta_json')}: {json.dumps(raw_answers, ensure_ascii=False)}")
                    full_doc = res["raw_dns_response"]
                    print(f"        {_('respuesta_completa')}: {json.dumps(full_doc, ensure_ascii=False)}")

        print(f"\n{sep_short}")
        print(
            f"{_('politica_efectiva')}: "
            f"{_('presente') if target['caa_policy_present'] else _('ausente')}"
        )
        if target["effective_caa_name"]:
            print(f"{_('politica_heredada')}: {target['effective_caa_name']}")

        certificate = target["tls_certificate"]
        if certificate["error"]:
            print(f"{_('cert_tls_error')} -> {certificate['error']}")
        else:
            issuer = certificate["issuer"]
            print(
                f"{_('cert_tls')}: "
                f"CN={certificate['subject'].get('commonName')} | "
                f"{_('emisor')}={issuer.get('organizationName')} / "
                f"{certificate['issuer'].get('commonName')}"
            )

    print(f"\n{sep}")
    print(_("reporte_ejecutivo"))
    print(sep)

    for target in report["targets"]:
        print(f"\n[>] {_('analisis_riesgo')}: {target['host']}")

        has_caa = target['caa_policy_present']
        records = target['effective_caa_records'] or []
        cert = target['tls_certificate']

        if not has_caa:
            print(f"  {_('critico_expuesto')}")
            print(f"            {_('critico_impacto')}")
            print(f"                     {_('critico_impacto2')}")
            print(f"                     {_('critico_impacto3')}")
        else:
            print(f"  {_('exito_protegida')}")
            print(f"          {_('exito_restringida')}")

            iodef_records = [r for r in records if r.get('tag') == 'iodef']
            if iodef_records:
                print(f"  {_('monitoreo_activo')}")
                for r in iodef_records:
                    print(f"         {_('monitoreo_alerta')}: {r.get('value')}")
            else:
                print(f"  {_('iodef_ausente')}")
                print(f"                {_('iodef_recomendacion')}")
                print(f"                               {_('iodef_recomendacion2')}")

        if not cert.get('error') and cert.get('issuer'):
            real_ca_org = (cert['issuer'].get('organizationName') or "").lower()
            real_ca_cn = (cert['issuer'].get('commonName') or "").lower()

            if has_caa:
                allowed_keywords = []
                for r in records:
                    if r.get('tag') in ['issue', 'issuewild'] and r.get('value'):
                        base_val = r.get('value').split(';')[0].strip().split('.')[0].lower()
                        if base_val:
                            allowed_keywords.append(base_val)

                match_found = False
                for kw in allowed_keywords:
                    if kw in real_ca_org or kw in real_ca_cn:
                        match_found = True
                        break

                if match_found:
                    print(f"  {_('validacion_pasada')}")
                    print(f"          {_('validacion_pasada_ca')} ('{cert['issuer'].get('organizationName')}')")
                    print(f"          {_('validacion_pasada_coincide')}")
                else:
                    print(f"  {_('alerta_shadow')}")
                    print(f"                  {_('alerta_shadow_servidor')}: '{cert['issuer'].get('organizationName')}'")
                    print(f"                  {_('alerta_shadow_dns')}: {', '.join(allowed_keywords)}.")
                    print(f"                  {_('alerta_shadow_riesgo')}")
                    print(f"                  {_('alerta_shadow_riesgo2')}")
                    print(f"                  {_('alerta_shadow_riesgo3')}")
        else:
            if not has_caa:
                print(f"  {_('recomendacion_general')}")
                print(f"    {_('recomendacion_implementar')}")
                print(f"    {_('recomendacion_implementar2')}")
                print(f"    {_('recomendacion_implementar3')}")

    print(f"\n{sep}")
    print(f"{_('evidencia_json')}: {report['output_json']}")
    print(f"{_('log_proceso')}: {report['output_log']}")


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
        "title": _("title"),
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
    global LANG
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
    parser.add_argument(
        "--lang",
        choices=["es", "en"],
        default="es",
        help="Idioma: es (espanol) / en (english) [default: es]",
    )
    args = parser.parse_args()
    LANG = args.lang

    exit_code = 1
    try:
        exit_code = run(args.target, args.zone_apex, args.output)
    except Exception:
        print("\nERROR NO CONTROLADO:", file=sys.stderr)
        traceback.print_exc()
    return exit_code



print("\n[!] AVISO LEGAL: Use solo con autorizacion. / LEGAL NOTICE: Authorized use only.\n")
if __name__ == "__main__":
    sys.exit(main())
