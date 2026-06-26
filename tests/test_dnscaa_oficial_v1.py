#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import logging
import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch
from io import StringIO
from urllib.error import HTTPError, URLError

SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, SCRIPT_DIR)

import dnscaa_oficial_v1 as mod


class TestParseCaa(unittest.TestCase):

    def test_formato_doh_estandar(self):
        result = mod.parse_caa('0 issue "letsencrypt.org"')
        self.assertEqual(result, {"flags": 0, "tag": "issue", "value": "letsencrypt.org"})

    def test_formato_rfc3597_hex(self):
        hex_data = r"\# 19 00 05 69 73 73 75 65 6c 65 74 73 65 6e 63 72 79 70 74 2e 6f 72 67"
        result = mod.parse_caa(hex_data)
        self.assertEqual(result["tag"], "issue")
        self.assertEqual(result["value"], "letsencrypt.org")
        self.assertEqual(result["flags"], 0)

    def test_formato_issuewild(self):
        result = mod.parse_caa('0 issuewild ";"')
        self.assertEqual(result, {"flags": 0, "tag": "issuewild", "value": ";"})

    def test_formato_raw_fallback(self):
        result = mod.parse_caa("datos_invalidos_sin_tres_partes")
        self.assertEqual(result, {"raw": "datos_invalidos_sin_tres_partes"})

    def test_formato_iodef(self):
        result = mod.parse_caa('0 iodef "mailto:security@example.com"')
        self.assertEqual(result["tag"], "iodef")
        self.assertEqual(result["value"], "mailto:security@example.com")


class TestGetDnsStatusName(unittest.TestCase):

    def test_noerror(self):
        self.assertEqual(mod.get_dns_status_name(0), "NOERROR")

    def test_nxdomain(self):
        self.assertEqual(mod.get_dns_status_name(3), "NXDOMAIN")

    def test_servfail(self):
        self.assertEqual(mod.get_dns_status_name(2), "SERVFAIL")

    def test_refused(self):
        self.assertEqual(mod.get_dns_status_name(5), "REFUSED")

    def test_formerr(self):
        self.assertEqual(mod.get_dns_status_name(1), "FORMERR")

    def test_notimp(self):
        self.assertEqual(mod.get_dns_status_name(4), "NOTIMP")

    def test_none(self):
        self.assertEqual(mod.get_dns_status_name(None), "UNKNOWN")

    def test_unknown_code(self):
        self.assertEqual(mod.get_dns_status_name(99), "STATUS_99")


class TestGetDigCommand(unittest.TestCase):

    def test_caa_command(self):
        result = mod.get_dig_command("example.com", "CAA")
        self.assertEqual(result, "dig @8.8.8.8 example.com CAA +multiline")

    def test_cname_command(self):
        result = mod.get_dig_command("sub.example.com", "CNAME")
        self.assertEqual(result, "dig @8.8.8.8 sub.example.com CNAME +multiline")


class TestComputeHierarchy(unittest.TestCase):

    def test_subdominio_profundo(self):
        levels = mod.compute_hierarchy("a.b.example.com", "example.com")
        self.assertEqual(levels, ["a.b.example.com", "b.example.com", "example.com"])

    def test_zone_apex_directo(self):
        levels = mod.compute_hierarchy("example.com", "example.com")
        self.assertEqual(levels, ["example.com"])

    def test_un_subdominio(self):
        levels = mod.compute_hierarchy("sub.example.com", "example.com")
        self.assertEqual(levels, ["sub.example.com", "example.com"])

    def test_host_no_pertenece_zona(self):
        with self.assertRaises(ValueError):
            mod.compute_hierarchy("other.com", "example.com")

    def test_trailing_dot(self):
        levels = mod.compute_hierarchy("sub.example.com.", "example.com.")
        self.assertEqual(levels, ["sub.example.com", "example.com"])


class TestDeriveZoneApex(unittest.TestCase):

    def test_dominio_simple(self):
        self.assertEqual(mod.derive_zone_apex("example.com"), "example.com")

    def test_subdominio(self):
        self.assertEqual(mod.derive_zone_apex("sub.example.com"), "example.com")

    def test_subdominio_profundo(self):
        self.assertEqual(mod.derive_zone_apex("a.b.example.com"), "example.com")

    def test_dominio_corto(self):
        with self.assertRaises(ValueError):
            mod.derive_zone_apex("x")

    def test_trailing_dot(self):
        self.assertEqual(mod.derive_zone_apex("sub.example.com."), "example.com")


class TestConsensusRecords(unittest.TestCase):

    def test_ambos_resolutores_coinciden(self):
        query = {
            "resolver_results": [
                {"http_status": 200, "dns_status": 0, "records": [{"flags": 0, "tag": "issue", "value": "letsencrypt.org"}]},
                {"http_status": 200, "dns_status": 0, "records": [{"flags": 0, "tag": "issue", "value": "letsencrypt.org"}]},
            ]
        }
        result = mod.consensus_records(query)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["tag"], "issue")

    def test_un_resolutor_falla(self):
        query = {
            "resolver_results": [
                {"http_status": 200, "dns_status": 0, "records": [{"flags": 0, "tag": "issue", "value": "ca.example.com"}]},
                {"http_status": 500, "dns_status": 2, "records": []},
            ]
        }
        result = mod.consensus_records(query)
        self.assertEqual(len(result), 1)

    def test_ambos_fallan(self):
        query = {
            "resolver_results": [
                {"http_status": None, "dns_status": None, "records": []},
                {"http_status": 500, "dns_status": 2, "records": []},
            ]
        }
        result = mod.consensus_records(query)
        self.assertEqual(result, [])

    def test_registros_diferentes_merge(self):
        rec_a = {"flags": 0, "tag": "issue", "value": "ca1.com"}
        rec_b = {"flags": 0, "tag": "issue", "value": "ca2.com"}
        query = {
            "resolver_results": [
                {"http_status": 200, "dns_status": 0, "records": [rec_a, rec_b]},
                {"http_status": 200, "dns_status": 0, "records": [rec_a]},
            ]
        }
        result = mod.consensus_records(query)
        self.assertEqual(len(result), 2)


class TestCreateOutputDir(unittest.TestCase):

    def test_crea_carpeta_con_nombre_y_fecha(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            original_raiz = mod.RAIZ_RESULTADOS
            mod.RAIZ_RESULTADOS = os.path.join(tmpdir, "Resultados_CAA")
            try:
                carpeta = mod.create_output_dir("ejemplo.com")
                self.assertTrue(os.path.isdir(carpeta))
                basename = os.path.basename(carpeta)
                self.assertTrue(basename.startswith("ejemplo.com_"))
                self.assertRegex(basename, r"ejemplo\.com_\d{8}_\d{6}")
            finally:
                mod.RAIZ_RESULTADOS = original_raiz

    def test_sanitiza_caracteres_especiales(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            original_raiz = mod.RAIZ_RESULTADOS
            mod.RAIZ_RESULTADOS = os.path.join(tmpdir, "Resultados_CAA")
            try:
                carpeta = mod.create_output_dir("sub.ejemplo*.com")
                self.assertTrue(os.path.isdir(carpeta))
                basename = os.path.basename(carpeta)
                self.assertNotIn("*", basename)
            finally:
                mod.RAIZ_RESULTADOS = original_raiz


class TestHttpJson(unittest.TestCase):

    def test_error_http(self):
        logger = logging.getLogger("test_http_json_error")
        logger.handlers.clear()
        logger.addHandler(logging.NullHandler())
        with patch("dnscaa_oficial_v1.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = HTTPError("http://x", 403, "Forbidden", {}, None)
            result = mod.http_json("http://x", {"name": "test"}, {}, logger)
            self.assertEqual(result["http_status"], 403)
            self.assertIsNone(result["document"])
            self.assertIn("Forbidden", result["error"])

    def test_error_conexion(self):
        logger = logging.getLogger("test_http_json_conn")
        logger.handlers.clear()
        logger.addHandler(logging.NullHandler())
        with patch("dnscaa_oficial_v1.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = URLError("timeout")
            result = mod.http_json("http://x", {"name": "test"}, {}, logger)
            self.assertIsNone(result["http_status"])
            self.assertIsNone(result["document"])

    def test_respuesta_exitosa(self):
        logger = logging.getLogger("test_http_json_ok")
        logger.handlers.clear()
        logger.addHandler(logging.NullHandler())
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps({"Status": 0, "Answer": []}).encode()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        with patch("dnscaa_oficial_v1.urlopen", return_value=mock_resp):
            result = mod.http_json("http://x", {"name": "test"}, {}, logger)
            self.assertEqual(result["http_status"], 200)
            self.assertEqual(result["document"]["Status"], 0)


class TlsCertificate(unittest.TestCase):

    def test_error_conexion(self):
        logger = logging.getLogger("test_tls_err")
        logger.handlers.clear()
        logger.addHandler(logging.NullHandler())
        with patch("dnscaa_oficial_v1.socket.create_connection", side_effect=OSError("refused")):
            result = mod.tls_certificate("nonexistent.example.com", logger)
            self.assertIsNotNone(result["error"])
            self.assertEqual(result["subject"], {})

    def test_certificado_valido(self):
        logger = logging.getLogger("test_tls_ok")
        logger.handlers.clear()
        logger.addHandler(logging.NullHandler())
        mock_tcp = MagicMock()
        mock_tls = MagicMock()
        mock_tls.getpeercert.return_value = {
            "subject": ((("commonName", "example.com"),),),
            "issuer": ((("organizationName", "DigiCert"),), (("commonName", "DigiCert SHA2"),)),
            "notBefore": "Jan 1 00:00:00 2024 GMT",
            "notAfter": "Jan 1 00:00:00 2025 GMT",
        }
        mock_tcp.__enter__ = MagicMock(return_value=mock_tcp)
        mock_tcp.__exit__ = MagicMock(return_value=False)
        mock_tls.__enter__ = MagicMock(return_value=mock_tls)
        mock_tls.__exit__ = MagicMock(return_value=False)

        with patch("dnscaa_oficial_v1.socket.create_connection", return_value=mock_tcp):
            with patch("dnscaa_oficial_v1.ssl.create_default_context") as mock_ctx_cls:
                mock_ctx = MagicMock()
                mock_ctx.wrap_socket.return_value = mock_tls
                mock_ctx_cls.return_value = mock_ctx
                result = mod.tls_certificate("example.com", logger)
                self.assertIsNone(result["error"])
                self.assertEqual(result["subject"]["commonName"], "example.com")
                self.assertEqual(result["issuer"]["organizationName"], "DigiCert")


class TestInspectorTarget(unittest.TestCase):

    def test_inspect_target_caa_ausente(self):
        logger = logging.getLogger("test_inspect_no_caa")
        logger.handlers.clear()
        logger.addHandler(logging.NullHandler())

        mock_cname_response = {
            "name": "sub.example.com",
            "type": "CNAME",
            "resolver_results": [
                {"resolver": "Google DNS", "url_used": "", "http_status": 200, "dns_status": 0, "records": [], "raw_dns_response": {"Status": 0, "Answer": []}, "request_headers": {}, "error": None},
                {"resolver": "Cloudflare DNS", "url_used": "", "http_status": 200, "dns_status": 0, "records": [], "raw_dns_response": {"Status": 0, "Answer": []}, "request_headers": {}, "error": None},
            ]
        }
        mock_caa_response = {
            "name": "example.com",
            "type": "CAA",
            "resolver_results": [
                {"resolver": "Google DNS", "url_used": "", "http_status": 200, "dns_status": 0, "records": [], "raw_dns_response": {"Status": 0, "Answer": []}, "request_headers": {}, "error": None},
                {"resolver": "Cloudflare DNS", "url_used": "", "http_status": 200, "dns_status": 0, "records": [], "raw_dns_response": {"Status": 0, "Answer": []}, "request_headers": {}, "error": None},
            ]
        }

        call_count = [0]
        def mock_query_dns(name, rtype, log):
            call_count[0] += 1
            if rtype == "CNAME":
                return mock_cname_response
            return mock_caa_response

        with patch("dnscaa_oficial_v1.query_dns", side_effect=mock_query_dns):
            with patch("dnscaa_oficial_v1.tls_certificate", return_value={"subject": {}, "issuer": {}, "not_before": None, "not_after": None, "error": "test skip"}):
                result = mod.inspect_target("sub.example.com", "example.com", logger)
                self.assertFalse(result["caa_policy_present"])
                self.assertIsNone(result["effective_caa_name"])

    def test_inspect_target_caa_presente(self):
        logger = logging.getLogger("test_inspect_caa")
        logger.handlers.clear()
        logger.addHandler(logging.NullHandler())

        caa_record = {"flags": 0, "tag": "issue", "value": "letsencrypt.org"}
        mock_caa_response = {
            "name": "example.com",
            "type": "CAA",
            "resolver_results": [
                {"resolver": "Google DNS", "url_used": "", "http_status": 200, "dns_status": 0, "records": [caa_record], "raw_dns_response": {"Status": 0, "Answer": [{"type": 257, "data": '0 issue "letsencrypt.org"'}]}, "request_headers": {}, "error": None},
                {"resolver": "Cloudflare DNS", "url_used": "", "http_status": 200, "dns_status": 0, "records": [caa_record], "raw_dns_response": {"Status": 0, "Answer": [{"type": 257, "data": '0 issue "letsencrypt.org"'}]}, "request_headers": {}, "error": None},
            ]
        }
        mock_cname_response = {
            "name": "example.com",
            "type": "CNAME",
            "resolver_results": [
                {"resolver": "Google DNS", "url_used": "", "http_status": 200, "dns_status": 0, "records": [], "raw_dns_response": {"Status": 0, "Answer": []}, "request_headers": {}, "error": None},
                {"resolver": "Cloudflare DNS", "url_used": "", "http_status": 200, "dns_status": 0, "records": [], "raw_dns_response": {"Status": 0, "Answer": []}, "request_headers": {}, "error": None},
            ]
        }

        def mock_query_dns(name, rtype, log):
            if rtype == "CNAME":
                return mock_cname_response
            return mock_caa_response

        with patch("dnscaa_oficial_v1.query_dns", side_effect=mock_query_dns):
            with patch("dnscaa_oficial_v1.tls_certificate", return_value={"subject": {"commonName": "example.com"}, "issuer": {"organizationName": "Let's Encrypt", "commonName": "R3"}, "not_before": "2024", "not_after": "2025", "error": None}):
                result = mod.inspect_target("example.com", "example.com", logger)
                self.assertTrue(result["caa_policy_present"])
                self.assertEqual(result["effective_caa_name"], "example.com")

    def test_inspect_derive_zone_apex_auto(self):
        logger = logging.getLogger("test_inspect_auto")
        logger.handlers.clear()
        logger.addHandler(logging.NullHandler())

        with patch("dnscaa_oficial_v1.query_dns") as mock_q:
            mock_q.return_value = {
                "name": "x",
                "type": "CAA",
                "resolver_results": [
                    {"resolver": "Google DNS", "url_used": "", "http_status": 200, "dns_status": 0, "records": [], "raw_dns_response": {"Status": 0, "Answer": []}, "request_headers": {}, "error": None},
                    {"resolver": "Cloudflare DNS", "url_used": "", "http_status": 200, "dns_status": 0, "records": [], "raw_dns_response": {"Status": 0, "Answer": []}, "request_headers": {}, "error": None},
                ]
            }
            with patch("dnscaa_oficial_v1.tls_certificate", return_value={"subject": {}, "issuer": {}, "not_before": None, "not_after": None, "error": "skip"}):
                result = mod.inspect_target("sub.example.com", None, logger)
                self.assertEqual(result["zone_apex"], "example.com")


class TestRunIntegracion(unittest.TestCase):

    def test_run_crea_archivos_salida(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            original_raiz = mod.RAIZ_RESULTADOS
            mod.RAIZ_RESULTADOS = tmpdir
            try:
                with patch("dnscaa_oficial_v1.inspect_target") as mock_inspect:
                    mock_inspect.return_value = {
                        "host": "example.com",
                        "zone_apex": "example.com",
                        "cname": [],
                        "cname_evidence": [],
                        "lookup_hierarchy": [],
                        "effective_caa_name": None,
                        "effective_caa_records": [],
                        "caa_policy_present": False,
                        "tls_certificate": {"subject": {}, "issuer": {}, "not_before": None, "not_after": None, "error": "skip"},
                    }
                    exit_code = mod.run("example.com", None, None)
                    self.assertEqual(exit_code, 0)

                    carpetas = os.listdir(tmpdir)
                    self.assertEqual(len(carpetas), 1)
                    carpeta = os.path.join(tmpdir, carpetas[0])
                    self.assertTrue(os.path.exists(os.path.join(carpeta, "evidencia_dns_caa.json")))
                    self.assertTrue(os.path.exists(os.path.join(carpeta, "PROCESO.log")))

                    with open(os.path.join(carpeta, "evidencia_dns_caa.json"), "r", encoding="utf-8") as f:
                        data = json.load(f)
                    self.assertIn("targets", data)
                    self.assertIn("zones", data)
                    self.assertEqual(data["version"], "2.0.0")
            finally:
                mod.RAIZ_RESULTADOS = original_raiz

    def test_run_output_dir_personalizado(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            custom_dir = os.path.join(tmpdir, "mi_salida")
            with patch("dnscaa_oficial_v1.inspect_target") as mock_inspect:
                mock_inspect.return_value = {
                    "host": "example.com",
                    "zone_apex": "example.com",
                    "cname": [],
                    "cname_evidence": [],
                    "lookup_hierarchy": [],
                    "effective_caa_name": None,
                    "effective_caa_records": [],
                    "caa_policy_present": False,
                    "tls_certificate": {"subject": {}, "issuer": {}, "not_before": None, "not_after": None, "error": "skip"},
                }
                exit_code = mod.run("example.com", None, custom_dir)
                self.assertEqual(exit_code, 0)
                self.assertTrue(os.path.exists(os.path.join(custom_dir, "evidencia_dns_caa.json")))
                self.assertTrue(os.path.exists(os.path.join(custom_dir, "PROCESO.log")))


class TestArgparseCLI(unittest.TestCase):

    def test_target_requerido(self):
        with self.assertRaises(SystemExit):
            mod.main()

    def test_target_valido(self):
        with patch("dnscaa_oficial_v1.run", return_value=0) as mock_run:
            with patch("sys.argv", ["dnscaa_oficial_v1.py", "-t", "example.com"]):
                exit_code = mod.main()
                mock_run.assert_called_once_with("example.com", None, None)

    def test_target_y_zone_apex(self):
        with patch("dnscaa_oficial_v1.run", return_value=0) as mock_run:
            with patch("sys.argv", ["dnscaa_oficial_v1.py", "-t", "sub.example.com", "-z", "example.com"]):
                mod.main()
                mock_run.assert_called_once_with("sub.example.com", "example.com", None)

    def test_target_y_output(self):
        with patch("dnscaa_oficial_v1.run", return_value=0) as mock_run:
            with patch("sys.argv", ["dnscaa_oficial_v1.py", "-t", "example.com", "-o", "C:/salida"]):
                mod.main()
                mock_run.assert_called_once_with("example.com", None, "C:/salida")


class TestQueryDnsConMock(unittest.TestCase):

    def test_query_dns_registra_url_y_headers(self):
        logger = logging.getLogger("test_query_url")
        logger.handlers.clear()
        logger.addHandler(logging.NullHandler())

        mock_doc = {"Status": 0, "Answer": [{"type": 257, "data": '0 issue "ca.example.com"'}]}
        mock_response = {"http_status": 200, "document": mock_doc, "error": None}

        with patch("dnscaa_oficial_v1.http_json", return_value=mock_response):
            result = mod.query_dns("example.com", "CAA", logger)
            self.assertEqual(result["name"], "example.com")
            self.assertEqual(result["type"], "CAA")
            for rr in result["resolver_results"]:
                self.assertIn("url_used", rr)
                self.assertIn("request_headers", rr)
                self.assertEqual(rr["records"], [{"flags": 0, "tag": "issue", "value": "ca.example.com"}])


if __name__ == "__main__":
    unittest.main()
