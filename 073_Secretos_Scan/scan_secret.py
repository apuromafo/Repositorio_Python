#!/usr/bin/env python3
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
#
# Autor / Author: Apuromafo
# Repo: https://github.com/apuromafo/Repositorio_Python
# =============================================================================
import sys
import os
import json
import subprocess
import base64
import platform
import shutil
import urllib.request
import zipfile
import tarfile
from datetime import datetime, timezone
from collections import defaultdict
import argparse
import logging
import re

HERRAMIENTA = "scan_secret"
CATEGORIA = "sca"
VERSION_TOOL = "2.1.0"
_TEMA = "SCA / Secretos / Gitleaks + Trufflehog"
_AUTOR = "Apuromafo"
_COMANDO = " ".join(sys.argv)
_LOG_HEADER = f"{_TEMA} | {CATEGORIA}/{HERRAMIENTA} | {VERSION_TOOL} | {_AUTOR} | {_COMANDO}"
_logger = logging.getLogger(__name__)


class _ConsolaFormatter(logging.Formatter):
    """Consola limpia (linea 6): mensaje directo sin timestamps ni
    cabecera; errores/advertencias marcados con prefijo [WARNING]/[ERROR]."""

    def format(self, record):
        msg = record.getMessage()
        if record.levelno >= logging.WARNING:
            return "[%s] %s" % (record.levelname, msg)
        return msg


_handler_consola = logging.StreamHandler()
_handler_consola.setFormatter(_ConsolaFormatter())
_logger.addHandler(_handler_consola)
_logger.setLevel(logging.INFO)

# El reporte.log es canal de evidencia: primera fila con cabecera de
# trazabilidad completa, luego solo "tiempo | nivel | contenido".
_LOGGER_ARCHIVO_ACTIVO = False
_handler_log = None


def _configurar_log_archivo(ruta_reporte_log):
    """Activa el canal de archivo de logging (reporte.log).

    Escribe la cabecera de trazabilidad (tema | tiempo | herramienta |
    version | autor | comando) como primera fila y registra cada evento
    posterior como "tiempo | nivel | contenido".

    Entrada:
        ruta_reporte_log (str): ruta al archivo reporte.log

    Salida: ninguna. Activa el FileHandler global y marca la flag.

    Ejemplo:
        _configurar_log_archivo("./out/reporte.log")
    """
    global _LOGGER_ARCHIVO_ACTIVO, _handler_log
    if _LOGGER_ARCHIVO_ACTIVO:
        return
    os.makedirs(os.path.dirname(ruta_reporte_log) or ".", exist_ok=True)
    try:
        with open(ruta_reporte_log, "w", encoding="utf-8") as f:
            f.write(_LOG_HEADER + "\n")
        _handler_log = logging.FileHandler(ruta_reporte_log, mode="a", encoding="utf-8")
        _handler_log.setFormatter(logging.Formatter('%(asctime)s | %(levelname)s | %(message)s'))
        _logger.addHandler(_handler_log)
        _LOGGER_ARCHIVO_ACTIVO = True
    except OSError as e:
        _logger.error("No se pudo crear reporte.log en %s: %s", ruta_reporte_log, str(e))

# ---- Textos bilingues ----
# Diccionario con todas las cadenas de interfaz en espanol e ingles.
# Cada clave es un identificador usado por _t() para obtener el texto
# en el idioma seleccionado.
_TEXTOS = {
    "es": {
        "desc": "Escaner unificado de secretos (Gitleaks + Trufflehog)",
        "h_f": "Directorio a escanear (busqueda recursiva)",
        "h_a": "Archivo individual a escanear",
        "h_o": "Directorio de salida (se crea si no existe)",
        "h_l": "Idioma de salida (es/en)",
        "h_i": "Carpetas adicionales a ignorar (residuos de herramientas, se puede repetir)",
        "exclusiones_log": "Exclusiones activas: {0}",
        "err_mutual": "-f (directorio) y -a (archivo) son mutuamente excluyentes",
        "err_required": "Debe especificar -f <directorio> o -a <archivo>",
        "err_not_found": "Error: '{0}' no existe",
        "err_not_dir": "Error: '{0}' no es un directorio",
        "err_not_file": "Error: '{0}' no es un archivo",
        "err_output_not_dir": "Error: '{0}' existe pero no es un directorio",
        "err_output_create": "Error: no se pudo crear el directorio de salida '{0}': {1}",
        "err_output_perms": "Error: no hay permisos de escritura en '{0}'",
        "err_tools_missing": "Error: las siguientes herramientas no estan disponibles y no se pudieron descargar: {0}. Instalalas manualmente o verifica tu conexion a internet.",
        "running_gitleaks": "[*] Ejecutando Gitleaks...",
        "running_trufflehog": "[*] Ejecutando Trufflehog...",
        "consolidating": "[*] Consolidando hallazgos...",
        "report_generated": "[+] Artefactos generados en {0}:",
        "finding_json_desc": "  finding.json  — datos estructurados del hallazgo",
        "reporte_md_desc": "  reporte.md    — resumen legible",
        "reporte_log_desc": "  reporte.log   — log operacional (secretos enmascarados)",
        "title": "REPORTE UNIFICADO DE SEGURIDAD",
        "path": "Ruta analizada",
        "date": "Fecha",
        "total": "Total hallazgos",
        "file_header": "[ARCHIVO]",
        "line": "Linea",
        "tool": "Herramienta",
        "rule": "Regla",
        "secret": "Secreto",
        "severity": "Severidad",
        "severity_critical": "Critica",
        "severity_high": "Alta",
        "severity_medium": "Media",
        "severity_low": "Baja",
        "remediation": "Remediacion",
        "summary_title": "RESUMEN FINAL",
        "summary_files": "Archivos unicos afectados",
        "summary_gitleaks": "Secretos (Gitleaks)",
        "summary_trufflehog": "Secretos (Trufflehog)",
        "summary_total": "TOTAL",
        "jwt_decoded": "[JWT DECODIFICADO]",
        "jwt_expired": "[ESTADO]: EXPIRADO (hace {0} dia(s) - {1})",
        "jwt_active": "[ESTADO]: ACTIVO (expira en {0} dia(s) - {1})",
    },
    "en": {
        "desc": "Unified secret scanner (Gitleaks + Trufflehog)",
        "h_f": "Directory to scan (recursive)",
        "h_a": "Single file to scan",
        "h_o": "Output directory (created if not exists)",
        "h_l": "Output language (es/en)",
        "h_i": "Extra folders to ignore (tool residue, can be repeated)",
        "exclusiones_log": "Active exclusions: {0}",
        "err_mutual": "-f (directory) and -a (file) are mutually exclusive",
        "err_required": "Must specify -f <directory> or -a <file>",
        "err_not_found": "Error: '{0}' not found",
        "err_not_dir": "Error: '{0}' is not a directory",
        "err_not_file": "Error: '{0}' is not a file",
        "err_output_not_dir": "Error: '{0}' exists but is not a directory",
        "err_output_create": "Error: could not create output directory '{0}': {1}",
        "err_output_perms": "Error: no write permission in '{0}'",
        "err_tools_missing": "Error: the following tools are not available and could not be downloaded: {0}. Install them manually or check your internet connection.",
        "running_gitleaks": "[*] Running Gitleaks...",
        "running_trufflehog": "[*] Running Trufflehog...",
        "consolidating": "[*] Consolidating findings...",
        "report_generated": "[+] Artifacts generated in {0}:",
        "finding_json_desc": "  finding.json  — structured finding data",
        "reporte_md_desc": "  reporte.md    — readable summary",
        "reporte_log_desc": "  reporte.log   — operational log (masked secrets)",
        "title": "UNIFIED SECURITY REPORT",
        "path": "Scanned path",
        "date": "Date",
        "total": "Total findings",
        "file_header": "[FILE]",
        "line": "Line",
        "tool": "Tool",
        "rule": "Rule",
        "secret": "Secret",
        "severity": "Severity",
        "severity_critical": "Critical",
        "severity_high": "High",
        "severity_medium": "Medium",
        "severity_low": "Low",
        "remediation": "Remediation",
        "summary_title": "FINAL SUMMARY",
        "summary_files": "Unique affected files",
        "summary_gitleaks": "Secrets (Gitleaks)",
        "summary_trufflehog": "Secrets (Trufflehog)",
        "summary_total": "TOTAL",
        "jwt_decoded": "[JWT DECODED]",
        "jwt_expired": "[STATUS]: EXPIRED ({0} day(s) ago - {1})",
        "jwt_active": "[STATUS]: ACTIVE (expires in {0} day(s) - {1})",
    },
}

# Directorio donde esta este script, usado como default para output
DIR_SCRIPT = os.path.dirname(os.path.abspath(__file__))

# Idioma activo (se cambia via -l en runtime)
_IDIOMA = "es"


def _t(key, *args):
    """Traduce una clave al idioma activo.

    Entrada:
        key (str): identificador del texto en _TEXTOS
        *args: valores para formatear con str.format()

    Salida:
        str: texto traducido, o la propia key si no encuentra traduccion

    Ejemplo:
        _t("err_not_found", "/ruta/x") -> "Error: '/ruta/x' no existe"
    """
    s = _TEXTOS[_IDIOMA].get(key, key)
    return s.format(*args) if args else s


# ---- Exclusiones ----
# Funciones para filtrar directorios/archivos que no deben escanearse
# (carpetas de dependencias, control de versiones, etc.)


def obtener_exclusiones_directorios():
    """Retorna lista de nombres de directorio a excluir del escaneo.

    Incluye carpetas de dependencias, control de versiones y residuos de
    herramientas de analisis (SonarQube, contenedores, caches) para
    evitar hallazgos duplicados o falsos positivos del propio tooling.

    Entrada: ninguna

    Salida:
        list[str]: nombres de carpeta a ignorar (sin ruta completa)

    Ejemplo:
        obtener_exclusiones_directorios() -> [".git", "node_modules", ".scannerwork"]

    Uso interno: debe_excluir() chequea si una ruta contiene alguno de estos.
    """
    return [".git", "node_modules", ".scannerwork",
            ".sonarqube", ".sonar", ".sonar-scanner",
            ".gradle", ".m2", ".cache", ".pytest_cache", ".tox", ".eggs",
            "coverage", "__pycache__"]


def debe_excluir(ruta, exclusiones):
    """Verifica si una ruta debe excluirse segun la lista de directorios.

    Entrada:
        ruta (str): ruta absoluta o relativa a evaluar
        exclusiones (list[str]): nombres de directorio a considerar

    Salida:
        bool: True si la ruta contiene algun directorio de exclusion,
              False en caso contrario o si ruta es None/vacia

    Ejemplo:
        debe_excluir("/proyecto/.git/config", [".git"]) -> True
        debe_excluir("/proyecto/src/main.py", [".git"]) -> False
    """
    if not ruta:
        return False
    ruta = ruta.replace("\\", "/")
    for exc in exclusiones:
        pattern = "/" + exc + "/"
        if pattern in ruta or ruta.endswith("/" + exc) or ruta == exc:
            return True
    return False


# Archivos temporales de salida que no deben escanearse (evita bucles)
ARCHIVOS_TEMP_SALIDA = {"gitleaks_raw.json", "trufflehog_raw.json"}


# ---- Mapeo de referencias (CWE, OWASP, severidad) ----
# Cada entrada asocia una regla (Gitleaks RuleID / Trufflehog DetectorName)
# con su clasificacion y recomendacion. Ambos idiomas incluidos.
_REFERENCIAS = {
    "aws-access-key": {
        "severidad": "Critical",
        "cwe": "CWE-798",
        "owasp": "A07:2021",
        "desc_es": "Clave de acceso AWS en texto plano",
        "desc_en": "AWS access key in plain text",
        "remed_es": "Rotar la clave inmediatamente. Usar roles IAM o Secrets Manager.",
        "remed_en": "Rotate the key immediately. Use IAM roles or Secrets Manager.",
    },
    "aws-secret-key": {
        "severidad": "Critical",
        "cwe": "CWE-798",
        "owasp": "A07:2021",
        "desc_es": "Clave secreta AWS en texto plano",
        "desc_en": "AWS secret key in plain text",
        "remed_es": "Rotar la clave inmediatamente. Usar roles IAM o Secrets Manager.",
        "remed_en": "Rotate the key immediately. Use IAM roles or Secrets Manager.",
    },
    "github-pat": {
        "severidad": "High",
        "cwe": "CWE-798",
        "owasp": "A07:2021",
        "desc_es": "Token de acceso personal de GitHub",
        "desc_en": "GitHub personal access token",
        "remed_es": "Revocar el token desde GitHub.com/settings/tokens. Usar acciones OIDC o GitHub Apps.",
        "remed_en": "Revoke the token at GitHub.com/settings/tokens. Use OIDC or GitHub Apps.",
    },
    "github-oauth": {
        "severidad": "High",
        "cwe": "CWE-798",
        "owasp": "A07:2021",
        "desc_es": "Token OAuth de GitHub",
        "desc_en": "GitHub OAuth token",
        "remed_es": "Revocar el token. Usar GitHub Apps con permisos minimos.",
        "remed_en": "Revoke the token. Use GitHub Apps with minimal permissions.",
    },
    "gitlab-pat": {
        "severidad": "High",
        "cwe": "CWE-798",
        "owasp": "A07:2021",
        "desc_es": "Token de acceso personal de GitLab",
        "desc_en": "GitLab personal access token",
        "remed_es": "Revocar desde GitLab User Settings. Usar CI/CD tokens temporales.",
        "remed_en": "Revoke from GitLab User Settings. Use temporary CI/CD tokens.",
    },
    "google-api-key": {
        "severidad": "High",
        "cwe": "CWE-798",
        "owasp": "A07:2021",
        "desc_es": "API key de Google expuesta",
        "desc_en": "Exposed Google API key",
        "remed_es": "Restringir la key por IP/HTTP referer en Google Cloud Console. Rotar si es necesario.",
        "remed_en": "Restrict the key by IP/HTTP referer in Google Cloud Console. Rotate if needed.",
    },
    "google-oauth": {
        "severidad": "High",
        "cwe": "CWE-798",
        "owasp": "A07:2021",
        "desc_es": "Token OAuth de Google expuesto",
        "desc_en": "Exposed Google OAuth token",
        "remed_es": "Revocar desde Google Cloud Console. Usar service accounts con workload identity.",
        "remed_en": "Revoke from Google Cloud Console. Use service accounts with workload identity.",
    },
    "slack-access-token": {
        "severidad": "Critical",
        "cwe": "CWE-798",
        "owasp": "A07:2021",
        "desc_es": "Token de acceso de Slack",
        "desc_en": "Slack access token",
        "remed_es": "Revocar el token desde api.slack.com. Rotar inmediatamente.",
        "remed_en": "Revoke the token at api.slack.com. Rotate immediately.",
    },
    "slack-webhook-url": {
        "severidad": "High",
        "cwe": "CWE-200",
        "owasp": "A01:2021",
        "desc_es": "Webhook URL de Slack expuesta",
        "desc_en": "Exposed Slack webhook URL",
        "remed_es": "Eliminar y recrear el webhook desde Slack. No incluirlo en el codigo.",
        "remed_en": "Delete and recreate the webhook from Slack. Do not embed in code.",
    },
    "private-key": {
        "severidad": "Critical",
        "cwe": "CWE-312",
        "owasp": "A02:2021",
        "desc_es": "Clave privada criptografica expuesta",
        "desc_en": "Exposed private cryptographic key",
        "remed_es": "Rotar el par de claves inmediatamente. Usar HSM o vault.",
        "remed_en": "Rotate the key pair immediately. Use HSM or vault.",
    },
    "ssh-private-key": {
        "severidad": "Critical",
        "cwe": "CWE-312",
        "owasp": "A02:2021",
        "desc_es": "Clave privada SSH expuesta",
        "desc_en": "Exposed SSH private key",
        "remed_es": "Rotar la clave SSH inmediatamente. Revisar authorized_keys.",
        "remed_en": "Rotate the SSH key immediately. Review authorized_keys.",
    },
    "pgp-private-key": {
        "severidad": "Critical",
        "cwe": "CWE-312",
        "owasp": "A02:2021",
        "desc_es": "Clave privada PGP expuesta",
        "desc_en": "Exposed PGP private key",
        "remed_es": "Rotar la clave PGP inmediatamente. Revocar la anterior.",
        "remed_en": "Rotate the PGP key immediately. Revoke the old one.",
    },
    "jwt": {
        "severidad": "High",
        "cwe": "CWE-798",
        "owasp": "A07:2021",
        "desc_es": "Token JWT en texto plano",
        "desc_en": "JWT token in plain text",
        "remed_es": "Verificar si es un token valido. Rotar inmediatamente. No almacenar JWTs en codigo.",
        "remed_en": "Verify if token is valid. Rotate immediately. Do not store JWTs in code.",
    },
    "password": {
        "severidad": "Critical",
        "cwe": "CWE-259",
        "owasp": "A07:2021",
        "desc_es": "Contrasena en texto plano",
        "desc_en": "Password in plain text",
        "remed_es": "Eliminar del codigo. Usar variables de entorno o un vault de secretos.",
        "remed_en": "Remove from code. Use environment variables or a secret vault.",
    },
    "generic-api-key": {
        "severidad": "High",
        "cwe": "CWE-798",
        "owasp": "A07:2021",
        "desc_es": "API key generica expuesta",
        "desc_en": "Generic API key exposed",
        "remed_es": "Rotar la key. Usar un vault de secretos o variables de entorno.",
        "remed_en": "Rotate the key. Use a secret vault or environment variables.",
    },
    "npm-token": {
        "severidad": "High",
        "cwe": "CWE-798",
        "owasp": "A07:2021",
        "desc_es": "Token de npm expuesto",
        "desc_en": "Exposed npm token",
        "remed_es": "Revocar desde npmjs.com/settings/tokens. Usar npm publish con OTP.",
        "remed_en": "Revoke at npmjs.com/settings/tokens. Use npm publish with OTP.",
    },
    "nuget-api-key": {
        "severidad": "High",
        "cwe": "CWE-798",
        "owasp": "A07:2021",
        "desc_es": "API key de NuGet expuesta",
        "desc_en": "Exposed NuGet API key",
        "remed_es": "Revocar desde nuget.org. Usar Azure Artifacts con tokens temporales.",
        "remed_en": "Revoke at nuget.org. Use Azure Artifacts with temporary tokens.",
    },
    "pypi-api-token": {
        "severidad": "High",
        "cwe": "CWE-798",
        "owasp": "A07:2021",
        "desc_es": "Token de PyPI expuesto",
        "desc_en": "Exposed PyPI API token",
        "remed_es": "Revocar desde pypi.org. Usar trusted publishers con OIDC.",
        "remed_en": "Revoke at pypi.org. Use trusted publishers with OIDC.",
    },
    "heroku-api-key": {
        "severidad": "High",
        "cwe": "CWE-798",
        "owasp": "A07:2021",
        "desc_es": "API key de Heroku expuesta",
        "desc_en": "Exposed Heroku API key",
        "remed_es": "Revocar desde dashboard.heroku.com. Usar OAuth tokens temporales.",
        "remed_en": "Revoke at dashboard.heroku.com. Use temporary OAuth tokens.",
    },
    "docker-config": {
        "severidad": "High",
        "cwe": "CWE-312",
        "owasp": "A02:2021",
        "desc_es": "Configuracion Docker con credenciales expuesta",
        "desc_en": "Docker config with exposed credentials",
        "remed_es": "Rotar credenciales. Usar docker login con tokens efimeros.",
        "remed_en": "Rotate credentials. Use docker login with ephemeral tokens.",
    },
    "telegram-bot-api-token": {
        "severidad": "High",
        "cwe": "CWE-798",
        "owasp": "A07:2021",
        "desc_es": "Token de bot de Telegram expuesto",
        "desc_en": "Exposed Telegram bot token",
        "remed_es": "Revocar desde @BotFather. Usar variables de entorno.",
        "remed_en": "Revoke via @BotFather. Use environment variables.",
    },
    "database-connection-string": {
        "severidad": "Critical",
        "cwe": "CWE-798",
        "owasp": "A07:2021",
        "desc_es": "Cadena de conexion a base de datos con credenciales",
        "desc_en": "Database connection string with credentials",
        "remed_es": "Rotar credenciales de BD. Usar variables de entorno o vault.",
        "remed_en": "Rotate database credentials. Use environment variables or vault.",
    },
}


def _referencias_hallazgo(regla, herramienta):
    """Busca CWE, OWASP y severidad para una regla/detector.

    Entrada:
        regla (str): RuleID de Gitleaks o DetectorName de Trufflehog
        herramienta (str): "Gitleaks" o "Trufflehog"

    Salida:
        dict con claves: severidad, cwe, owasp, desc, remed
        (desc y remed en el idioma activo via _IDIOMA)
        Si no hay mapeo, retorna un dict con valores por defecto.
    """
    ref = _REFERENCIAS.get(regla)
    if not ref:
        # Fallback: buscar por subcadena
        clave = regla.lower()
        for k, v in _REFERENCIAS.items():
            if k in clave or clave in k:
                ref = v
                break
    if not ref:
        return {
            "severidad": "Medium",
            "cwe": "N/A",
            "owasp": "N/A",
            "desc": regla,
            "remed": "Revisar manualmente y rotar si corresponde.",
        }
    sufijo = "es" if _IDIOMA == "es" else "en"
    return {
        "severidad": ref["severidad"],
        "cwe": ref["cwe"],
        "owasp": ref["owasp"],
        "desc": ref.get("desc_" + sufijo, ref.get("desc_en", regla)),
        "remed": ref.get("remed_" + sufijo, ref.get("remed_en", "Revisar manualmente.")),
    }


# ---- Decodificador JWT ----
# Toma un token JWT encontrado como secreto, extrae el payload y
# muestra su contenido legible + estado de expiracion.


def decodificar_jwt(token):
    """Decodifica un token JWT y retorna su payload legible + estado.

    Entrada:
        token (str): token JWT completo (header.payload.signature)

    Salida:
        str | None: texto formateado con payload JSON y estado de
                     expiracion, o None si no es un JWT valido
                     o hay error de decodificacion

    Ejemplo de salida:
        [JWT DECODIFICADO]:
        {
            "sub": "1234567890",
            "name": "John Doe",
            "exp": 1900000000
        }
        [ESTADO]: ACTIVO (expira en 365 dia(s) - 2030-03-15 12:00:00 UTC)
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        payload_b64 = parts[1]
        pad = 4 - len(payload_b64) % 4
        if pad != 4:
            payload_b64 += "=" * pad
        payload_b64 = payload_b64.replace("-", "+").replace("_", "/")
        decoded = base64.b64decode(payload_b64)
        data = json.loads(decoded)
        result = json.dumps(data, indent=4)
        exp_info = ""
        if "exp" in data:
            exp_val = data["exp"]
            if isinstance(exp_val, (int, float)):
                exp_time = datetime.fromtimestamp(exp_val, tz=timezone.utc)
                now = datetime.now(timezone.utc)
                diff = exp_time - now
                if diff.total_seconds() < 0:
                    exp_info = "    " + _t("jwt_expired", abs(diff.days), exp_time.strftime("%Y-%m-%d %H:%M:%S UTC"))
                else:
                    exp_info = "    " + _t("jwt_active", diff.days, exp_time.strftime("%Y-%m-%d %H:%M:%S UTC"))
        jwt_line = "    " + _t("jwt_decoded") + ":\n    " + result
        if exp_info:
            jwt_line += "\n" + exp_info
        return jwt_line
    except Exception:
        return None


def _jwt_estructurado(token):
    """Decodifica JWT y retorna dict estructurado para finding.json.

    Entrada:
        token (str): token JWT completo

    Salida:
        dict | None: payload decodificado, expiracion y estado,
                     o None si no es JWT valido

    Ejemplo:
        _jwt_estructurado(token) -> {"payload": {...}, "expiracion": "...", "expirado": false}
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        payload_b64 = parts[1]
        pad = 4 - len(payload_b64) % 4
        if pad != 4:
            payload_b64 += "=" * pad
        payload_b64 = payload_b64.replace("-", "+").replace("_", "/")
        decoded = base64.b64decode(payload_b64)
        data = json.loads(decoded)
        result = {"payload": data}
        if "exp" in data and isinstance(data["exp"], (int, float)):
            exp_time = datetime.fromtimestamp(data["exp"], tz=timezone.utc)
            now = datetime.now(timezone.utc)
            diff = exp_time - now
            result["expiracion"] = exp_time.strftime("%Y-%m-%d %H:%M:%S UTC")
            result["expirado"] = diff.total_seconds() < 0
            result["dias_restantes"] = diff.days if diff.total_seconds() >= 0 else -abs(diff.days)
        return result
    except Exception:
        return None


# ---- Ejecutor de herramientas externas ----
# Corre Gitleaks o Trufflehog como subprocesos y captura su salida.


def ejecutar_herramienta(cmd):
    """Ejecuta un comando externo y retorna su salida concatenada.

    Entrada:
        cmd (list[str]): comando y argumentos (ej: ["gitleaks", "detect", ...])

    Salida:
        str: stdout + stderr del proceso, o cadena vacia si hay error
             (timeout, proceso no encontrado, etc.)

    Nota: Timeout de 300s. No usa text=True por compatibilidad
          con encoding en Windows (ver AGENTS.md).
    """
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=300)
        return r.stdout.decode("utf-8", errors="replace") + r.stderr.decode("utf-8", errors="replace")
    except Exception:
        return ""


# ---- Configuracion de herramientas externas ----
# Cada herramienta define su repo de GitHub, asset pattern por plataforma
# y version de fallback si la API de GitHub no responde.

_DIR_TOOLS = os.path.join(DIR_SCRIPT, "tools")
_DIR_CONFIG = os.path.join(DIR_SCRIPT, "config")
ARCHIVO_CONFIG = os.path.join(_DIR_CONFIG, "herramientas.json")

_HERRAMIENTAS_CONFIG = {
    "gitleaks": {
        "repo": "gitleaks/gitleaks",
        "cmd": "gitleaks",
        "version_fallback": "8.21.2",
"asset_patterns": {
            "Windows": "gitleaks_{version}_windows_x64.zip",
            "Linux": "gitleaks_{version}_linux_x64.tar.gz",
            "Darwin": "gitleaks_{version}_darwin_arm64.tar.gz",
        },
        "binary_name": {
            "Windows": "gitleaks.exe",
            "Linux": "gitleaks",
            "Darwin": "gitleaks",
        },
        "version_flag": "--version",
    },
    "trufflehog": {
        "repo": "trufflesecurity/trufflehog",
        "cmd": "trufflehog",
        "version_fallback": "3.82.13",
        "asset_patterns": {
            "Windows": "trufflehog_{version}_windows_amd64.tar.gz",
            "Linux": "trufflehog_{version}_linux_amd64.tar.gz",
            "Darwin": "trufflehog_{version}_darwin_amd64.tar.gz",
        },
"binary_name": {
            "Windows": "trufflehog.exe",
            "Linux": "trufflehog",
            "Darwin": "trufflehog",
        },
        "version_flag": "--version",
    },
}


def _obtener_binario_local(nombre):
    """Busca el binario de una herramienta en la carpeta local tools/.

    Entrada:
        nombre (str): nombre de la herramienta ("gitleaks", "trufflehog")

    Salida:
        str | None: ruta absoluta al binario si existe, None si no

    Ejemplo:
        _obtener_binario_local("gitleaks") -> "C:/.../sca/003_Secretos/tools/gitleaks/gitleaks.exe"
    """
    config = _HERRAMIENTAS_CONFIG.get(nombre)
    if not config:
        return None
    sistema = platform.system()
    bin_name = config["binary_name"].get(sistema, nombre)
    path = os.path.join(_DIR_TOOLS, nombre, bin_name)
    if os.path.isfile(path):
        return path
    return None


def _validar_binario(path_binario, version_flag):
    """Ejecuta el binario con --version para confirmar que funciona.

    Entrada:
        path_binario (str): ruta al binario
        version_flag (str): flag para obtener version (ej: "--version")

Salida:
        str | None: numero de version si funciona, None si falla

    Ejemplo:
        _validar_binario("/usr/bin/gitleaks", "--version") -> "8.21.2"
    """
    try:
        r = subprocess.run(
            [path_binario, version_flag],
            capture_output=True, timeout=15,
        )
        out = (r.stdout.decode("utf-8", errors="replace")
               + r.stderr.decode("utf-8", errors="replace"))
        if r.returncode == 0 and out.strip():
            m = re.search(r"\d+\.\d+(?:\.\d+)?", out)
            return m.group(0) if m else out.strip().split("\n")[0]
        return None
    except Exception:
        return None


def _buscar_en_path(nombre):
    """Busca el binario en PATH del sistema via shutil.which.

    Entrada:
        nombre (str): nombre del ejecutable (ej: "gitleaks")

    Salida:
        str | None: ruta al ejecutable si esta en PATH, None si no

Ejemplo:
        _buscar_en_path("gitleaks") -> "C:/Users/x/bin/gitleaks.exe"
    """
    found = shutil.which(nombre)
    return found if found and os.path.isfile(found) else None


def _leer_config_herramientas():
    """Carga config/herramientas.json con las ubicaciones conocidas.

    Entrada: ninguna

    Salida:
        dict | None: con la estructura
            {"sistema_operativo": "...", "herramientas": {nombre: {"ruta": "...", "version": "..."}}}
            o None si el config no existe, esta corrupto o el SO no coincide.

    Ejemplo:
        _leer_config_herramientas()
        -> {"sistema_operativo": "Windows", "herramientas": {"gitleaks": {...}, "trufflehog": {...}}}
    """
    try:
        with open(ARCHIVO_CONFIG, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return None
    if data.get("sistema_operativo") != platform.system():
        return None
    return data


def _guardar_config_herramientas(gitleaks_bin, trufflehog_bin, versiones):
    """Registra en config/herramientas.json el SO detectado y las
    ubicaciones de los binarios en uso, para mantener el orden.

    Entrada:
        gitleaks_bin (str|None): ruta al binario de gitleaks
        trufflehog_bin (str|None): ruta al binario de trufflehog
        versiones (dict): {"gitleaks": "8.24.2", "trufflehog": "3.95.9"}

    Salida: ninguna. Escribe config/herramientas.json en el directorio
    de la herramienta (no usa %TEMP%).

    Ejemplo:
        _guardar_config_herramientas("C:/.../gitleaks.exe", None, {"gitleaks": "8.24.2"})
    """
    try:
        os.makedirs(_DIR_CONFIG, exist_ok=True)
        data = {
            "sistema_operativo": platform.system(),
            "herramientas": {
                "gitleaks": {"ruta": gitleaks_bin, "version": versiones.get("gitleaks")},
                "trufflehog": {"ruta": trufflehog_bin, "version": versiones.get("trufflehog")},
            },
        }
        with open(ARCHIVO_CONFIG, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    except OSError as e:
        _logger.error("No se pudo escribir %s: %s", ARCHIVO_CONFIG, str(e))


def _seleccionar_asset_github(assets, nombre, version):
    """Selecciona el asset correcto de una release de GitHub segun plataforma.

    Entrada:
        assets (list[dict]): lista de assets de la release (GitHub API)
        nombre (str): nombre de la herramienta
        version (str): version a buscar

    Salida:
        str | None: URL de descarga del asset correcto, None si no encontrado

    Ejemplo:
        _seleccionar_asset_github([...], "gitleaks", "8.21.2")
        -> "https://github.com/.../gitleaks_8.21.2_windows_x64.zip"
    """
    config = _HERRAMIENTAS_CONFIG[nombre]
    sistema = platform.system()
    pattern = config["asset_patterns"].get(sistema)
    if not pattern:
        return None
    expected = pattern.format(version=version)
    for asset in assets:
        if asset.get("name") == expected:
            return asset.get("browser_download_url")
    for asset in assets:
        name = asset.get("name", "")
        if sistema == "Windows" and ("windows" in name.lower()
                                     and (name.endswith(".zip") or name.endswith(".tar.gz"))):
            return asset.get("browser_download_url")
        if sistema == "Linux" and name.endswith(".tar.gz") and "linux" in name.lower():
            return asset.get("browser_download_url")
        if sistema == "Darwin" and name.endswith(".tar.gz") and "darwin" in name.lower():
            return asset.get("browser_download_url")
    return None


def _descargar_con_reintentos(url, destino, reintentos=3):
    """Descarga un archivo con reintentos usando urllib (stdlib).

    Entrada:
        url (str): URL a descargar
        destino (str): ruta donde guardar el archivo
        reintentos (int): numero maximo de intentos (default 3)

    Salida:
        bool: True si descargo correctamente, False si fallo

    Ejemplo:
        _descargar_con_reintentos("https://github.com/.../file.zip", "/tmp/file.zip")
    """
    for intento in range(reintentos):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "scan_secret/2.1.0"})
            with urllib.request.urlopen(req, timeout=120) as resp:
                with open(destino, "wb") as f:
                    while True:
                        chunk = resp.read(65536)
                        if not chunk:
                            break
                        f.write(chunk)
            if os.path.getsize(destino) > 0:
                return True
        except Exception as e:
            _logger.warning("Intento %d/%d fallido: %s", intento + 1, reintentos, str(e))
            if os.path.exists(destino):
                os.remove(destino)
    return False


def _extraer_binario(archive_path, nombre):
    """Extrae el binario de un archivo .zip o .tar.gz y retorna su ruta.

    Entrada:
        archive_path (str): ruta al archivo comprimido
        nombre (str): nombre de la herramienta

    Salida:
        str | None: ruta al binario extraido, None si fallo

    Ejemplo:
        _extraer_binario("/tmp/gitleaks.zip", "gitleaks")
        -> "C:/.../tools/gitleaks/gitleaks.exe"
    """
    config = _HERRAMIENTAS_CONFIG[nombre]
    sistema = platform.system()
    bin_name = config["binary_name"].get(sistema, nombre)
    dest_dir = os.path.join(_DIR_TOOLS, nombre)
    os.makedirs(dest_dir, exist_ok=True)
    bin_path = os.path.join(dest_dir, bin_name)

    try:
        if archive_path.endswith(".zip"):
            with zipfile.ZipFile(archive_path, "r") as zf:
                for info in zf.infolist():
                    if os.path.basename(info.filename) == bin_name:
                        with zf.open(info) as src, open(bin_path, "wb") as dst:
                            dst.write(src.read())
                        break
                else:
                    for info in zf.infolist():
                        if not info.is_dir():
                            with zf.open(info) as src, open(bin_path, "wb") as dst:
                                dst.write(src.read())
                            break
        elif archive_path.endswith(".tar.gz") or archive_path.endswith(".tgz"):
            with tarfile.open(archive_path, "r:gz") as tf:
                for member in tf.getmembers():
                    if os.path.basename(member.name) == bin_name:
                        with tf.extractfile(member) as src:
                            with open(bin_path, "wb") as dst:
                                dst.write(src.read())
                        break
                else:
                    for member in tf.getmembers():
                        if member.isfile():
                            with tf.extractfile(member) as src:
                                with open(bin_path, "wb") as dst:
                                    dst.write(src.read())
                            break
        else:
            return None

        if os.path.isfile(bin_path):
            if sistema != "Windows":
                os.chmod(bin_path, 0o755)
            return bin_path
    except Exception as e:
        _logger.error("Error extrayendo %s: %s", nombre, str(e))
    return None


def descargar_herramienta(nombre):
    """Descarga una herramienta desde GitHub releases.

    Flujo: query GitHub API -> seleccionar asset por plataforma ->
    descargar -> extraer binario -> validar.

    Entrada:
        nombre (str): nombre de la herramienta ("gitleaks", "trufflehog")

    Salida:
        str | None: ruta al binario descargado/validado, None si fallo

    Ejemplo:
        descargar_herramienta("gitleaks")
        -> "C:/.../tools/gitleaks/gitleaks.exe"
    """
    config = _HERRAMIENTAS_CONFIG[nombre]
    repo = config["repo"]
    sistema = platform.system()

    _logger.info("Descargando %s desde GitHub (%s)...", nombre, repo)

    api_url = f"https://api.github.com/repos/{repo}/releases/latest"
    version = config["version_fallback"]
    download_url = None

    try:
        req = urllib.request.Request(api_url, headers={"User-Agent": "scan_secret/2.1.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        tag = data.get("tag_name", "")
        version = tag.lstrip("v") if tag else config["version_fallback"]
        assets = data.get("assets", [])
        download_url = _seleccionar_asset_github(assets, nombre, version)
    except Exception as e:
        _logger.warning("No se pudo consultar GitHub API para %s: %s", nombre, str(e))

    if not download_url:
        tag = "v" + version
        asset_pattern = config["asset_patterns"].get(sistema, "")
        asset_name = asset_pattern.format(version=version)
        download_url = f"https://github.com/{repo}/releases/download/{tag}/{asset_name}"

    bin_name = config["binary_name"].get(sistema, nombre)
    ext = ".zip" if download_url.endswith(".zip") else ".tar.gz"
    tmp_archive = os.path.join(_DIR_TOOLS, nombre + ext)

    os.makedirs(os.path.dirname(tmp_archive), exist_ok=True)

    _logger.info("Descargando %s v%s...", nombre, version)
    if not _descargar_con_reintentos(download_url, tmp_archive):
        _logger.error("No se pudo descargar %s desde %s", nombre, download_url)
        return None

    _logger.info("Extrayendo %s...", nombre)
    bin_path = _extraer_binario(tmp_archive, nombre)

    try:
        os.remove(tmp_archive)
    except OSError:
        pass

    if bin_path:
        version_flag = config["version_flag"]
        ver = _validar_binario(bin_path, version_flag)
        if ver:
            _logger.info("%s v%s instalado correctamente en %s", nombre, ver, bin_path)
        else:
            _logger.warning("%s descargado pero no responde a --version: %s", nombre, bin_path)
    else:
        _logger.error("No se pudo extraer el binario de %s", nombre)

    return bin_path


def validar_herramientas():
    """Valida que gitleaks y trufflehog esten disponibles y funcionando.

    Busca en orden: carpeta local tools/ -> PATH del sistema.
    Ejecuta --version para confirmar que cada binario funciona.

    Entrada: ninguna

    Salida:
        tuple[str | None, str | None]: (ruta_gitleaks, ruta_trufflehog)
            Ambos None si no se encontraron, o rutas a los binarios validados.

Ejemplo:
        gitleaks_bin, trufflehog_bin = validar_herramientas()
    """
    gitleaks_bin = None
    trufflehog_bin = None

    datos_config = _leer_config_herramientas()

    for nombre in ["gitleaks", "trufflehog"]:
        config = _HERRAMIENTAS_CONFIG[nombre]

        ruta_config = None
        if datos_config:
            ruta_config = datos_config["herramientas"].get(nombre, {}).get("ruta")

        if ruta_config and os.path.isfile(ruta_config):
            ver = _validar_binario(ruta_config, config["version_flag"])
            if ver:
                _logger.info("[OK] %s v%s encontrado en config: %s", nombre, ver, ruta_config)
                if nombre == "gitleaks":
                    gitleaks_bin = ruta_config
                else:
                    trufflehog_bin = ruta_config
                continue
            else:
                _logger.warning("%s registrado en config pero no responde: %s", nombre, ruta_config)

        path_local = _obtener_binario_local(nombre)
        if path_local:
            ver = _validar_binario(path_local, config["version_flag"])
            if ver:
                _logger.info("[OK] %s v%s encontrado en: %s", nombre, ver, path_local)
                if nombre == "gitleaks":
                    gitleaks_bin = path_local
                else:
                    trufflehog_bin = path_local
                continue
            else:
                _logger.warning("%s encontrado en local pero no responde: %s", nombre, path_local)

        path_path = _buscar_en_path(config["cmd"])
        if path_path:
            ver = _validar_binario(path_path, config["version_flag"])
            if ver:
                _logger.info("[OK] %s v%s encontrado en PATH: %s", nombre, ver, path_path)
                if nombre == "gitleaks":
                    gitleaks_bin = path_path
                else:
                    trufflehog_bin = path_path
                continue
            else:
                _logger.warning("%s en PATH pero no responde: %s", nombre, path_path)

        _logger.warning("%s no encontrado localmente ni en PATH", nombre)

    return gitleaks_bin, trufflehog_bin


def ensure_herramientas():
    """Valida herramientas y descarga las que falten.

    Flujo completo: validar -> descargar faltantes -> re-validar.
    Si despues de descargar alguna sigue faltando, aborta con error.

    Entrada: ninguna

    Salida:
        tuple[str, str]: (ruta_gitleaks, ruta_trufflehog) — ambas deben ser validas

    Excepcion:
        SystemExit: si alguna herramienta no esta disponible tras intentar descargar

    Ejemplo:
        gitleaks_bin, trufflehog_bin = ensure_herramientas()
"""
    gitleaks_bin, trufflehog_bin = validar_herramientas()

    if not gitleaks_bin:
        _logger.info("Gitleaks no encontrado. Intentando descargar automaticamente...")
        gitleaks_bin = descargar_herramienta("gitleaks")

    if not trufflehog_bin:
        _logger.info("Trufflehog no encontrado. Intentando descargar automaticamente...")
        trufflehog_bin = descargar_herramienta("trufflehog")

    faltantes = []
    if not gitleaks_bin:
        faltantes.append("gitleaks")
    if not trufflehog_bin:
        faltantes.append("trufflehog")

    if faltantes:
        msg = _t("err_tools_missing", ", ".join(faltantes))
        _logger.error(msg)
        sys.exit(1)

    versiones = {}
    for nombre, ruta in [("gitleaks", gitleaks_bin), ("trufflehog", trufflehog_bin)]:
        cfg = _HERRAMIENTAS_CONFIG[nombre]
        versiones[nombre] = _validar_binario(ruta, cfg["version_flag"])
    _guardar_config_herramientas(gitleaks_bin, trufflehog_bin, versiones)
    _logger.info("Config de herramientas actualizado (SO=%s)", platform.system())

    return gitleaks_bin, trufflehog_bin


# ---- Main ----
# Punto de entrada: parsea argumentos, ejecuta herramientas,
# consolida resultados y genera reporte unificado.


def main():
    """Punto de entrada principal.

    Parsea argumentos CLI, ejecuta Gitleaks + Trufflehog sobre el
    target, consolida hallazgos, decodifica JWTs y escribe reporte.

Entrada: argumentos CLI (via argparse)
        -f / --folder / --dir: directorio a escanear
        -a / --archivo / --file: archivo a escanear
        -o / --output / --outdir: directorio de salida
        -l / --lang: idioma (es/en)
        -i / --ignorar / --ignore: carpetas adicionales a ignorar (repetible)

    Salida:
        Escribe en disco:
          - gitleaks_raw.json (raw Gitleaks)
          - trufflehog_raw.json (raw Trufflehog)
          - informe_unificado.txt (reporte consolidado)

        Stdin/out:
          - Mensajes de progreso por consola
          - Codigo de salida 0 en exito, 1 en error

    Ejemplos:
        python scan_secret.py -f ./repo
python scan_secret.py -a ./token.txt -o ./out -l en
    """
    parser = argparse.ArgumentParser(description=_t("desc"))
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--folder", "--dir", dest="folder", help=_t("h_f"))
    group.add_argument("-a", "--archivo", "--file", dest="archivo", help=_t("h_a"))
    parser.add_argument("-o", "--output", "--outdir", dest="output", help=_t("h_o"))
    parser.add_argument("-l", "--lang", choices=["es", "en"], default="es", help=_t("h_l"))
    parser.add_argument("-i", "--ignorar", "--ignore", dest="ignorar", action="append",
                        default=[], help=_t("h_i"))

    args = parser.parse_args()

    global _IDIOMA
    _IDIOMA = args.lang

    # Resolver target (directorio o archivo)
    target = None
    es_archivo = False
    if args.folder:
        target = os.path.abspath(args.folder)
        es_archivo = False
    elif args.archivo:
        target = os.path.abspath(args.archivo)
        es_archivo = True

    if not os.path.exists(target):
        _logger.error(_t("err_not_found", target))
        sys.exit(1)
    if es_archivo and not os.path.isfile(target):
        _logger.error(_t("err_not_file", target))
        sys.exit(1)
    if not es_archivo and not os.path.isdir(target):
        _logger.error(_t("err_not_dir", target))
        sys.exit(1)

    # Directorio de salida (se conserva) y temporal (se limpia)
    # Si no se usa -o, el trio se trata como temporal y se elimina al salir
    conservar = args.output is not None
    out_dir = os.path.abspath(args.output) if conservar else DIR_SCRIPT
    if os.path.exists(out_dir) and not os.path.isdir(out_dir):
        _logger.error(_t("err_output_not_dir", out_dir))
        sys.exit(1)
    try:
        os.makedirs(out_dir, exist_ok=True)
    except Exception as e:
        _logger.error(_t("err_output_create", out_dir, str(e)))
        sys.exit(1)
    if not os.access(out_dir, os.W_OK):
        _logger.error(_t("err_output_perms", out_dir))
        sys.exit(1)

    # Directorio temporal aislado para archivos intermedios
    # (no usa %TEMP% porque antivirus lo purga a diario)
    tmp_dir = os.path.join(out_dir, "tmp_" + datetime.now().strftime("%Y%m%d"))
    os.makedirs(tmp_dir, exist_ok=True)

    gitleaks_raw = os.path.join(tmp_dir, "gitleaks_raw.json")
    trufflehog_raw = os.path.join(tmp_dir, "trufflehog_raw.json")

# El trio va al directorio final según -o
    dir_final = out_dir if conservar else tmp_dir
    finding_json = os.path.join(dir_final, "finding.json")
    reporte_md = os.path.join(dir_final, "reporte.md")
    reporte_log = os.path.join(dir_final, "reporte.log")

    for f in [gitleaks_raw, trufflehog_raw, finding_json, reporte_md, reporte_log]:
        if os.path.exists(f):
            os.remove(f)

    # Canal de evidencia: reporte.log queda activo para toda la operacion
    _configurar_log_archivo(reporte_log)

    # Exclusiones: bases + carpetas de residuo indicadas por el operador (-i)
    exclusiones = obtener_exclusiones_directorios()
    for extra in args.ignorar:
        extra_limpio = extra.strip().strip("/\\")
        if extra_limpio and extra_limpio not in exclusiones:
            exclusiones.append(extra_limpio)
    _logger.info(_t("exclusiones_log", ", ".join(exclusiones)))

    # Validar y descargar herramientas si faltan
    gitleaks_bin, trufflehog_bin = ensure_herramientas()

    # Ejecutar Gitleaks
    _logger.info(_t("running_gitleaks"))
    ejecutar_herramienta([gitleaks_bin, "detect", "--source", target, "-v",
                          "--report-format", "json", "--report-path", gitleaks_raw, "--no-git"])

    # Ejecutar Trufflehog
    _logger.info(_t("running_trufflehog"))
    th_out = ejecutar_herramienta([trufflehog_bin, "filesystem", target, "--only-verified=false", "--json"])
    if th_out.strip():
        with open(trufflehog_raw, "w", encoding="utf-8") as f:
            f.write(th_out)

    # Consolidar hallazgos
    _logger.info(_t("consolidating"))
    todos_hallazgos = []
    secretos_vistos = set()

    # Parsear salida de Gitleaks (JSON array)
    if os.path.exists(gitleaks_raw) and os.path.getsize(gitleaks_raw) > 0:
        with open(gitleaks_raw, encoding="utf-8") as f:
            try:
                gl_data = json.load(f)
                for item in gl_data:
                    fname = item.get("File", "")
                    if debe_excluir(fname, exclusiones) or os.path.basename(fname) in ARCHIVOS_TEMP_SALIDA:
                        continue
                    secret = item.get("Secret", "")
                    if len(secret) < 8 or secret in secretos_vistos:
                        continue
                    secretos_vistos.add(secret)
                    todos_hallazgos.append({
                        "Archivo": fname, "Linea": item.get("StartLine", 0),
                        "Herramienta": "Gitleaks", "Regla": item.get("RuleID", ""),
                        "Secreto": secret
                    })
            except json.JSONDecodeError:
                pass

    # Parsear salida de Trufflehog (JSON lines / NDJSON)
    if os.path.exists(trufflehog_raw) and os.path.getsize(trufflehog_raw) > 0:
        with open(trufflehog_raw, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                    fname = item.get("SourceMetadata", {}).get("Filesystem", {}).get("file", "")
                    if not fname:
                        fname = item.get("Source", "[No especificado]")
                    if debe_excluir(fname, exclusiones) or os.path.basename(fname) in ARCHIVOS_TEMP_SALIDA:
                        continue
                    secret = item.get("Raw", item.get("RawV2", ""))
                    if not secret or secret in secretos_vistos:
                        continue
                    secretos_vistos.add(secret)
                    lnum = item.get("SourceMetadata", {}).get("Filesystem", {}).get("line", 0)
                    todos_hallazgos.append({
                        "Archivo": fname, "Linea": lnum,
                        "Herramienta": "Trufflehog", "Regla": item.get("DetectorName", ""),
                        "Secreto": secret
                    })
                except json.JSONDecodeError:
                    continue

    # Agrupar por archivo
    agrupados = defaultdict(list)
    for h in todos_hallazgos:
        agrupados[h["Archivo"]].append(h)
    agrupados = dict(sorted(agrupados.items()))

    # ---- Generar finding.json ----
    fecha_iso = datetime.now().isoformat()
    hallazgos_json = []
    for h in todos_hallazgos:
        ref = _referencias_hallazgo(h["Regla"], h["Herramienta"])
        entry = {
            "Archivo": h["Archivo"],
            "Linea": h["Linea"],
            "Herramienta": h["Herramienta"],
            "Regla": h["Regla"],
            "Severidad": ref["severidad"],
            "CWE": ref["cwe"],
            "OWASP": ref["owasp"],
            "Descripcion": ref["desc"],
            "Remediacion": ref["remed"],
            "Secreto": h["Secreto"],
        }
        jwt_data = _jwt_estructurado(h["Secreto"])
        if jwt_data:
            entry["JWT"] = jwt_data
        hallazgos_json.append(entry)

    finding_data = {
        "metadata": {
            "target": target,
            "fecha": fecha_iso,
            "total_hallazgos": len(todos_hallazgos),
            "archivos_afectados": len(agrupados),
            "herramientas": ["Gitleaks", "Trufflehog"],
        },
        "hallazgos": hallazgos_json,
    }
    with open(finding_json, "w", encoding="utf-8") as f:
        json.dump(finding_data, f, indent=2, ensure_ascii=False)

    # ---- Generar reporte.md ----
    lineas_md = []
    lineas_md.append("# " + _t("title"))
    lineas_md.append("")
    lineas_md.append("**" + _t("path") + ":** " + target)
    lineas_md.append("**" + _t("date") + ":** " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    lineas_md.append("**" + _t("total") + ":** " + str(len(todos_hallazgos)))
    lineas_md.append("")
    lineas_md.append("---")
    lineas_md.append("")

    for archivo, hallazgos in agrupados.items():
        try:
            ruta_corta = os.path.relpath(archivo, target)
            if ruta_corta.startswith(".."):
                ruta_corta = archivo
        except ValueError:
            ruta_corta = archivo
        lineas_md.append("## " + _t("file_header") + " `" + ruta_corta + "`")
        lineas_md.append("")
        hallazgos.sort(key=lambda x: x["Linea"])
        for h in hallazgos:
            ref = _referencias_hallazgo(h["Regla"], h["Herramienta"])
            lineas_md.append("- **" + _t("line") + ":** " + str(h["Linea"]))
            lineas_md.append("  **" + _t("tool") + ":** " + h["Herramienta"])
            lineas_md.append("  **" + _t("rule") + ":** " + h["Regla"])
            lineas_md.append("  **" + _t("severity") + ":** " + ref["severidad"])
            lineas_md.append("  **CWE:** " + ref["cwe"] + "  **OWASP:** " + ref["owasp"])
            lineas_md.append("  **" + _t("remediation") + ":** " + ref["remed"])
            lineas_md.append("  **" + _t("secret") + ":** `" + h["Secreto"] + "`")
            jwt_info = decodificar_jwt(h["Secreto"])
            if jwt_info:
                lineas_md.append("  ```")
                lineas_md.append(jwt_info)
                lineas_md.append("  ```")
            lineas_md.append("")
        lineas_md.append("---")
        lineas_md.append("")

    count_gitleaks = sum(1 for h in todos_hallazgos if h["Herramienta"] == "Gitleaks")
    count_trufflehog = sum(1 for h in todos_hallazgos if h["Herramienta"] == "Trufflehog")
    lineas_md.append("## " + _t("summary_title"))
    lineas_md.append("")
    lineas_md.append("- " + _t("summary_files") + ": " + str(len(agrupados)))
    lineas_md.append("- " + _t("summary_gitleaks") + ": " + str(count_gitleaks))
    lineas_md.append("- " + _t("summary_trufflehog") + ": " + str(count_trufflehog))
    lineas_md.append("- " + _t("summary_total") + ": " + str(len(todos_hallazgos)))

    with open(reporte_md, "w", encoding="utf-8") as f:
        f.write("\n".join(lineas_md) + "\n")

# ---- Append al reporte.log (anexo de evidencia) ----
    # La cabecera de trazabilidad y el log operacional fueron escritos
    # durante la ejecucion (canal de archivo). Aqui se agrega el anexo
    # con el detalle de hallazgos (secretos enmascarados) sin sobrescribir.
    MASCARA = "****"
    lineas_log = []
    for archivo, hallazgos in agrupados.items():
        try:
            ruta_corta = os.path.relpath(archivo, target)
            if ruta_corta.startswith(".."):
                ruta_corta = archivo
        except ValueError:
            ruta_corta = archivo
        lineas_log.append("[" + _t("file_header").strip("[]") + "] " + ruta_corta)
        lineas_log.append("-" * 60)
        hallazgos.sort(key=lambda x: x["Linea"])
        for h in hallazgos:
            ref = _referencias_hallazgo(h["Regla"], h["Herramienta"])
            lineas_log.append("  " + _t("line") + ": " + str(h["Linea"]))
            lineas_log.append("  " + _t("tool") + ": " + h["Herramienta"])
            lineas_log.append("  " + _t("rule") + ": " + h["Regla"])
            lineas_log.append("  " + _t("severity") + ": " + ref["severidad"])
            lineas_log.append("  CWE: " + ref["cwe"] + " | OWASP: " + ref["owasp"])
            lineas_log.append("  " + _t("remediation") + ": " + ref["remed"])
            lineas_log.append("  " + _t("secret") + ": " + MASCARA)
            lineas_log.append("")

    lineas_log.append("")
    lineas_log.append("=" * 60)
    lineas_log.append(_t("summary_title"))
    lineas_log.append("=" * 60)
    lineas_log.append("  " + _t("summary_files") + ": " + str(len(agrupados)))
    lineas_log.append("  " + _t("summary_gitleaks") + ": " + str(count_gitleaks))
    lineas_log.append("  " + _t("summary_trufflehog") + ": " + str(count_trufflehog))
    lineas_log.append("  " + _t("summary_total") + ": " + str(len(todos_hallazgos)))
    lineas_log.append("=" * 60)

    with open(reporte_log, "a", encoding="utf-8") as f:
        f.write("\n".join(lineas_log) + "\n")

    # Limpiar archivos intermedios (no persiste data sensible local)
    for f_temp in [gitleaks_raw, trufflehog_raw]:
        try:
            if os.path.exists(f_temp):
                os.remove(f_temp)
        except OSError:
            pass

    _logger.info(_t("report_generated", out_dir))
    _logger.info(_t("finding_json_desc"))
    _logger.info(_t("reporte_md_desc"))
    _logger.info(_t("reporte_log_desc"))


if __name__ == "__main__":
    main()

