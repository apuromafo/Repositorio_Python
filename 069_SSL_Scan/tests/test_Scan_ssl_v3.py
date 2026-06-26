#!/usr/bin/env python3
"""Suite de pruebas para SCAN SSL v34.1 — Auditor SSL/TLS con PQC y CVSS"""
import sys
import os
import io
import unittest
from unittest.mock import patch, MagicMock, mock_open

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import Scan_ssl_v3 as sslscan


class TestRenderLogLine(unittest.TestCase):

    def test_version_line_green(self):
        r = sslscan.render_log_line("Version: 2.2.2 Windows")
        self.assertIn("Version:", r)
        self.assertIn(sslscan.Fore.GREEN, r)

    def test_titles_cyan(self):
        for t in sslscan.TITULOS_CYAN:
            r = sslscan.render_log_line(f"  {t}")
            self.assertIn(sslscan.Fore.CYAN, r)

    def test_insecure_protocol_enabled_red(self):
        for p in ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"]:
            r = sslscan.render_log_line(f"{p}     enabled")
            self.assertIn(sslscan.Fore.RED, r)

    def test_insecure_protocol_disabled_green(self):
        for p in ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"]:
            r = sslscan.render_log_line(f"{p}     disabled")
            self.assertIn(sslscan.Fore.GREEN, r)

    def test_secure_protocol_enabled_green(self):
        for p in ["TLSv1.2", "TLSv1.3"]:
            r = sslscan.render_log_line(f"{p}     enabled")
            self.assertIn(sslscan.Fore.GREEN, r)

    def test_secure_protocol_disabled_red(self):
        for p in ["TLSv1.2", "TLSv1.3"]:
            r = sslscan.render_log_line(f"{p}     disabled")
            self.assertIn(sslscan.Fore.RED, r)

    def test_heartbleed_not_vulnerable_green(self):
        r = sslscan.render_log_line("TLSv1.2 not vulnerable to heartbleed")
        self.assertIn(sslscan.Fore.GREEN, r)

    def test_heartbleed_vulnerable_red(self):
        r = sslscan.render_log_line("TLSv1.2 vulnerable to heartbleed")
        self.assertIn(sslscan.Fore.RED, r)

    def test_cipher_accepted_highlighted(self):
        r = sslscan.render_log_line("Accepted  TLSv1.2  256 bits  ECDHE-RSA-AES256-GCM-SHA384")
        self.assertIn(sslscan.Fore.GREEN, r)

    def test_preferred_highlighted(self):
        r = sslscan.render_log_line("Preferred TLSv1.2  256 bits  ECDHE-RSA-AES256-GCM-SHA384")
        self.assertIn(sslscan.Fore.GREEN, r)

    def test_empty_line_passthrough(self):
        self.assertEqual(sslscan.render_log_line(""), "")


class TestAuditoriaV34(unittest.TestCase):

    def setUp(self):
        self.good = """Version: 2.2.2
  SSL/TLS Protocols:
SSLv2     disabled
SSLv3     disabled
TLSv1.0   disabled
TLSv1.1   disabled
TLSv1.2   enabled
TLSv1.3   enabled
  TLS renegotiation:
Secure session renegotiation supported
  Heartbleed:
TLSv1.2 not vulnerable to heartbleed
  SSL Certificate:
Issuer:   Sectigo RSA Domain Validation Secure Server CA
Not valid after:  Jun 21 23:59:59 2026 GMT
X25519MLKEM512
"""

    def test_audit_shows_header(self):
        f = io.StringIO()
        with patch('sys.stdout', f):
            sslscan.ejecutar_auditoria_v34(self.good, "target.test")
        self.assertIn("INFORME TÉCNICO DE AUDITORÍA SSL", f.getvalue())

    def test_audit_shows_fips203(self):
        f = io.StringIO()
        with patch('sys.stdout', f):
            sslscan.ejecutar_auditoria_v34(self.good, "t")
        self.assertIn("FIPS 203", f.getvalue())

    def test_audit_shows_fips204(self):
        f = io.StringIO()
        with patch('sys.stdout', f):
            sslscan.ejecutar_auditoria_v34(self.good, "t")
        self.assertIn("FIPS 204", f.getvalue())

    def test_audit_heartbleed_vulnerable(self):
        v = """Heartbleed:\nTLSv1.2 vulnerable to heartbleed\nIssuer: CA\n"""
        f = io.StringIO()
        with patch('sys.stdout', f):
            sslscan.ejecutar_auditoria_v34(v, "v")
        self.assertIn("VULNERABLE", f.getvalue())

    def test_audit_heartbleed_not_vulnerable(self):
        v = """Heartbleed:\nnot vulnerable to heartbleed\nIssuer: CA\n"""
        f = io.StringIO()
        with patch('sys.stdout', f):
            sslscan.ejecutar_auditoria_v34(v, "v")
        self.assertIn("No vulnerable", f.getvalue())

    def test_audit_insecure_renegotiation(self):
        v = """TLS renegotiation:\nInsecure client-initiated renegotiation\nIssuer: CA\n"""
        f = io.StringIO()
        with patch('sys.stdout', f):
            sslscan.ejecutar_auditoria_v34(v, "v")
        self.assertIn("Riesgo", f.getvalue())

    def test_audit_no_tls13(self):
        """TLSv1.3 disabled debe marcar Legado"""
        v = """SSL/TLS Protocols:\nTLSv1.2   enabled\nTLSv1.3   disabled\nIssuer: CA\n"""
        f = io.StringIO()
        with patch('sys.stdout', f):
            sslscan.ejecutar_auditoria_v34(v, "v")
        o = f.getvalue()
        self.assertIn("Legado", o)

    def test_audit_pqc_kex_vanguardia(self):
        v = """Server Key Exchange Group(s):\nX25519MLKEM768\nIssuer: CA\n"""
        f = io.StringIO()
        with patch('sys.stdout', f):
            sslscan.ejecutar_auditoria_v34(v, "v")
        self.assertIn("Vanguardia", f.getvalue())

    def test_audit_pqc_sig_vanguardia(self):
        v = """SSL Certificate:\nSignature Algorithm: ML-DSA-65\nIssuer: CA\n"""
        f = io.StringIO()
        with patch('sys.stdout', f):
            sslscan.ejecutar_auditoria_v34(v, "v")
        self.assertIn("Vanguardia", f.getvalue())

    def test_audit_cvss_summary_shown(self):
        f = io.StringIO()
        with patch('sys.stdout', f):
            sslscan.ejecutar_auditoria_v34(self.good, "t")
        o = f.getvalue()
        self.assertIn("CVSS 4.0", o)
        self.assertIn("CVSS 3.1", o)
        self.assertIn("Score de Riesgo", o)

    def test_audit_certificate_validity(self):
        f = io.StringIO()
        with patch('sys.stdout', f):
            sslscan.ejecutar_auditoria_v34(self.good, "t")
        self.assertIn("Vigencia del Certificado", f.getvalue())

    def test_audit_returns_tuple(self):
        v = """Issuer: CA\n"""
        f = io.StringIO()
        with patch('sys.stdout', f):
            r = sslscan.ejecutar_auditoria_v34(v, "v")
        self.assertIsInstance(r, tuple)
        self.assertEqual(len(r), 3)

    def test_audit_returns_findings_list(self):
        v = """Issuer: CA\n"""
        f = io.StringIO()
        with patch('sys.stdout', f):
            h, _, _ = sslscan.ejecutar_auditoria_v34(v, "v")
        self.assertIsInstance(h, list)


class TestProvisionarBinario(unittest.TestCase):

    @patch('Scan_ssl_v3.os.path.exists', return_value=True)
    @patch('Scan_ssl_v3.os.makedirs')
    @patch('Scan_ssl_v3.urllib.request.urlopen')
    @patch('Scan_ssl_v3.zipfile.ZipFile')
    @patch('Scan_ssl_v3.shutil.move')
    @patch('Scan_ssl_v3.os.remove')
    @patch('Scan_ssl_v3.os.walk')
    def test_already_exists(self, w, rm, mv, z, u, mk, ex):
        self.assertTrue(sslscan.provisionar_binario())
        u.assert_not_called()

    @patch('Scan_ssl_v3.os.path.exists', side_effect=[False, False])
    @patch('Scan_ssl_v3.os.makedirs')
    @patch('Scan_ssl_v3.urllib.request.urlopen')
    @patch('Scan_ssl_v3.zipfile.ZipFile')
    @patch('Scan_ssl_v3.shutil.move')
    @patch('Scan_ssl_v3.os.remove')
    @patch('Scan_ssl_v3.os.walk', return_value=[("t", ["s"], ["sslscan.exe"])])
    def test_download_ok(self, w, rm, mv, z, u, mk, ex):
        u.return_value.__enter__.return_value.read.return_value = b"x"
        z.return_value.__enter__.return_value.namelist.return_value = ["sslscan.exe"]
        self.assertTrue(sslscan.provisionar_binario())

    @patch('Scan_ssl_v3.os.path.exists', return_value=False)
    @patch('Scan_ssl_v3.os.makedirs')
    @patch('Scan_ssl_v3.urllib.request.urlopen', side_effect=Exception("fail"))
    def test_download_fails_gracefully(self, u, mk, ex):
        self.assertFalse(sslscan.provisionar_binario())


class TestGenerarCurls(unittest.TestCase):

    @patch('builtins.print')
    def test_generar_curls_no_folder(self, mock_print):
        r = sslscan.generar_curls("example.com")
        self.assertIn("comandos", r)
        self.assertEqual(len(r["comandos"]), 8)
        self.assertEqual(r["meta"]["target"], "example.com")

    @patch('builtins.print')
    @patch('Scan_ssl_v3.json.dump')
    @patch('builtins.open', new_callable=mock_open)
    def test_generar_curls_with_folder(self, mf, jd, mp):
        r = sslscan.generar_curls("example.com", folder="/tmp")
        self.assertIn("comandos", r)


class TestExportarFindings(unittest.TestCase):

    @patch('builtins.print')
    @patch('Scan_ssl_v3.json.dump')
    @patch('builtins.open', new_callable=mock_open)
    def test_exportar_findings(self, mf, jd, mp):
        h = [("CRITICAL", "SSLv2", {"score40": 9.8, "vector40": "...", "score31": 9.8, "vector31": "..."})]
        sslscan.exportar_findings_json(h, 9.8, "ALTO", "test.target", "/tmp")
        jd.assert_called_once()


class TestConstants(unittest.TestCase):

    def test_titulos_cyan_complete(self):
        e = ["SSL/TLS Protocols:", "TLS Fallback SCSV:", "TLS renegotiation:",
             "TLS Compression:", "Heartbleed:", "Supported Server Cipher(s):",
             "Server Key Exchange Group(s):", "SSL Certificate:", "Issuer:", "Altnames:"]
        self.assertEqual(sslscan.TITULOS_CYAN, e)

    def test_version_defined(self):
        self.assertTrue(hasattr(sslscan, 'VERSION'))
        self.assertTrue(sslscan.VERSION.startswith("v"))

    def test_cvss_map_keys(self):
        for k in ["SSLv2 enabled", "SSLv3 enabled", "TLSv1.0 enabled",
                   "TLSv1.1 enabled", "TLSv1.3 disabled", "heartbleed vulnerable",
                   "insecure renegotiation", "no_pqc_kex", "no_pqc_sig"]:
            self.assertIn(k, sslscan.CVSS_MAP)
            self.assertIn("score40", sslscan.CVSS_MAP[k])
            self.assertIn("score31", sslscan.CVSS_MAP[k])


class TestMainFunction(unittest.TestCase):

    def setUp(self):
        self.orig_argv = sys.argv

    def tearDown(self):
        sys.argv = self.orig_argv

    def test_version_flag(self):
        sys.argv = ['Scan_ssl_v3.py', '-V']
        with self.assertRaises(SystemExit):
            sslscan.main()

    def test_version_long_flag(self):
        sys.argv = ['Scan_ssl_v3.py', '--version']
        with self.assertRaises(SystemExit):
            sslscan.main()

    def test_no_args_shows_banner(self):
        sys.argv = ['Scan_ssl_v3.py']
        f = io.StringIO()
        with patch('sys.stdout', f):
            sslscan.main()
        self.assertIn("SCAN SSL", f.getvalue())

    @patch('Scan_ssl_v3.provisionar_binario', return_value=True)
    @patch('Scan_ssl_v3.subprocess.run')
    @patch('Scan_ssl_v3.os.makedirs')
    @patch('builtins.open', new_callable=mock_open)
    @patch('Scan_ssl_v3.os.listdir', return_value=[])
    def test_main_with_target(self, mlist, mf, mm, mr, mp):
        sys.argv = ['Scan_ssl_v3.py', '-t', 'example.com']
        mr.return_value = MagicMock(
            stdout="Version: 2.2.2\nIssuer:   Test CA\nNot valid after:  Jun 21 23:59:59 2026 GMT\n")
        f = io.StringIO()
        with patch('sys.stdout', f):
            sslscan.main()
        self.assertIn("COMPLETADO", f.getvalue())

    @patch('Scan_ssl_v3.os.path.exists', return_value=True)
    @patch('builtins.open', new_callable=mock_open,
           read_data="Version: 2.2.2\nIssuer:   Test CA\nNot valid after:  Jun 21 23:59:59 2026 GMT\n")
    def test_main_with_file(self, mf, me):
        sys.argv = ['Scan_ssl_v3.py', '-f', '/some/path']
        f = io.StringIO()
        with patch('sys.stdout', f):
            sslscan.main()
        self.assertIn("INFORME TÉCNICO DE AUDITORÍA SSL", f.getvalue())

    @patch('Scan_ssl_v3.os.path.exists', return_value=False)
    def test_main_with_bad_file(self, me):
        sys.argv = ['Scan_ssl_v3.py', '-f', '/nonexistent']
        f = io.StringIO()
        with patch('sys.stdout', f):
            sslscan.main()
        self.assertIn("No se encontró evidencia", f.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
