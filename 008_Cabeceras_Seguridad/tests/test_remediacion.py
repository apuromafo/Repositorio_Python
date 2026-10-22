# ------------------------------------------------------------
# DISCLAIMER: Este script es parte del repositorio de herramientas de pruebas de penetración.
# Su uso está sujeto a los términos de la licencia MIT y al aviso legal presente en el README.
# ------------------------------------------------------------

# Tests unitarios del plan de remediación (v1.3.0):
#   - Cabeceras_Seguridad.detectar_temas_remediacion: qué temas aplican.
#   - Cabeceras_Seguridad.plan_remediacion: impresión sin excepción y contenido clave.

import unittest
import os
import sys
import io
import contextlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import Cabeceras_Seguridad as tool  # noqa: E402


HDR_COOPEUCH = {
    "server": "CloudFront",
    "content-security-policy": (
        "default-src 'self' 'unsafe-inline'; base-uri 'self'; object-src 'none'; "
        "font-src * data: 'self' 'unsafe-inline'; img-src * data: 'self'; "
        "script-src 'self' 'unsafe-eval' 'unsafe-inline'; frame-src * 'self'; "
        "media-src * data: 'self'; "
        "script-src-elem 'self' code.iconify.design api.iconify.design 'unsafe-inline' 'unsafe-eval'; "
        "connect-src 'self'; worker-src blob:"
    ),
    "strict-transport-security": "max-age=31536000",
    "via": "1.1 xxxx.cloudfront.net (CloudFront)",
}

HDR_ROBUSTO = {
    "content-security-policy": (
        "default-src 'self'; script-src 'self' 'nonce-AbCdEf01' 'strict-dynamic'; "
        "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; "
        "form-action 'self'; upgrade-insecure-requests"
    ),
    "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
}


class TestDetectarTemasRemediacion(unittest.TestCase):
    def test_csp_con_flags_se_detecta(self):
        temas = tool.detectar_temas_remediacion(HDR_COOPEUCH)
        self.assertIn("csp_endurecer", temas)
        det = temas["csp_endurecer"]
        self.assertIn(("script-src", "flags inseguros 'unsafe-inline'/'unsafe-eval'"), det)
        self.assertIn(("font-src", "wildcard global '*'"), det)
        self.assertIn(("font-src", "fuente 'data:'"), det)

    def test_hsts_corto_se_detecta(self):
        temas = tool.detectar_temas_remediacion(HDR_COOPEUCH)
        self.assertIn("hsts_estrechar", temas)
        problemas = temas["hsts_estrechar"]
        self.assertTrue(any("includeSubDomains" in p for p in problemas))
        self.assertTrue(any("preload" in p for p in problemas))

    def test_stack_expuesto_se_detecta(self):
        temas = tool.detectar_temas_remediacion(HDR_COOPEUCH)
        self.assertIn("stack_ocultar", temas)
        self.assertTrue(any("Server:" in e for e in temas["stack_ocultar"]))

    def test_csp_robusto_no_genera_temas(self):
        temas = tool.detectar_temas_remediacion(HDR_ROBUSTO)
        self.assertEqual(temas, {})

    def test_hsts_ausente_se_detecta(self):
        temas = tool.detectar_temas_remediacion({"content-type": "text/html"})
        self.assertIn("hsts_estrechar", temas)
        self.assertTrue(any("ausente" in p for p in temas["hsts_estrechar"]))

    def test_x_powered_by_php_dispara_temas_cms(self):
        temas = tool.detectar_temas_remediacion({"x-powered-by": "PHP/7.4.1"})
        self.assertIn("stack_ocultar", temas)
        self.assertIn("cms_metadatos", temas)

    def test_max_age_corto_se_detecta(self):
        temas = tool.detectar_temas_remediacion(
            {"strict-transport-security": "max-age=600; includeSubDomains; preload"})
        self.assertIn("hsts_estrechar", temas)
        self.assertTrue(any("max-age=600" in p for p in temas["hsts_estrechar"]))


class TestPlanRemediacion(unittest.TestCase):
    def _capturar(self, fn, *args):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            resultado = fn(*args)
        return resultado, buf.getvalue()

    def test_plan_se_imprime_sin_excepcion(self):
        temas, salida = self._capturar(tool.plan_remediacion, HDR_COOPEUCH)
        self.assertIn("csp_endurecer", temas)
        self.assertIn("Plan de remediación", salida)
        self.assertIn("[Ficha 1]", salida)
        self.assertIn("[Ficha 2]", salida)
        self.assertIn("[PASO 1]", salida)
        self.assertIn("Report-Only", salida)
        self.assertIn("SOC 2", salida)
        self.assertIn("PCI DSS", salida)
        self.assertIn("nonce", salida)
        self.assertIn("[OK]", salida)
        self.assertIn("hstspreload.org", salida)
        self.assertIn("server_tokens off;", salida)
        self.assertIn("Cloudflare", salida)
        self.assertIn("Akamai", salida)
        self.assertIn("onClientResponse", salida)

    def test_sin_temas_no_imprime_plan(self):
        _, salida = self._capturar(tool.plan_remediacion, HDR_ROBUSTO)
        self.assertEqual(salida, "")


if __name__ == "__main__":
    unittest.main()
