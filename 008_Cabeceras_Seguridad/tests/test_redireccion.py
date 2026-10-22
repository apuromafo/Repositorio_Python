# ------------------------------------------------------------
# DISCLAIMER: Este script es parte del repositorio de herramientas de pruebas de penetración.
# Su uso está sujeto a los términos de la licencia MIT y al aviso legal presente en el README.
# ------------------------------------------------------------

# Tests unitarios de los elementos rescatados del script ancestral (v1.4.3):
#   - verificar_redireccion_http_https: chequeo HTTP->HTTPS (fix: prueba http://).
#   - Server-Timing en la lista de divulgación (suggest_headers_to_remove).
#   - print_tiempo con offset GMT-3.
# Los tests son 100% offline (sin red).

import unittest
import io
import os
import re
import contextlib
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import Cabeceras_Seguridad as tool


def _limpiar(texto):
    return re.sub(r"\x1b\[[0-9;]*m", "", texto)


class TestVerificarRedireccionHttpHttps(unittest.TestCase):
    def test_url_no_https_no_es_verificable(self):
        r = tool.verificar_redireccion_http_https("http://demo.testfire.net")
        self.assertFalse(r["verificado"])
        self.assertFalse(r["redirige"] is True)
        self.assertIn("https://", r["detalle"])

    def test_url_vacia(self):
        r = tool.verificar_redireccion_http_https("")
        self.assertFalse(r["verificado"])

    def test_claves_del_resultado(self):
        r = tool.verificar_redireccion_http_https("http://ejemplo.com")
        self.assertEqual(sorted(r.keys()), ["detalle", "redirige", "verificado"])

    def test_error_de_conexion_da_detalle_sin_crash(self):
        # Mock sin red: requests.get lanza ConnectionError -> detalle informativo, sin excepción.
        original = tool.requests.get

        def raise_err(*a, **k):
            raise tool.requests.exceptions.ConnectionError("conexión rechazada")

        tool.requests.get = raise_err
        try:
            r = tool.verificar_redireccion_http_https("https://192.0.2.1")
        finally:
            tool.requests.get = original
        self.assertFalse(r["verificado"])
        self.assertFalse(r["redirige"])
        self.assertIn("No se pudo conectar por HTTP", r["detalle"])
        self.assertIn("ConnectionError", r["detalle"])


class TestServerTimingEnDisclosers(unittest.TestCase):
    def test_server_timing_detectado_con_nota(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            tool.suggest_headers_to_remove({"Server-Timing": "cdn-cache; desc=MISS"})
        salida = _limpiar(buf.getvalue())
        self.assertIn("Server-Timing", salida)
        self.assertIn("middleware", salida)  # nota específica del diccionario de notas

    def test_lista_normal_no_afectada(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            tool.suggest_headers_to_remove({"Content-Security-Policy": "default-src 'self'"})
        salida = _limpiar(buf.getvalue())
        self.assertIn("No se detectaron", salida)


class TestPrintTiempoGmt3(unittest.TestCase):
    def test_incluye_offset_gmt3(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            tool.print_tiempo()
        salida = _limpiar(buf.getvalue())
        self.assertIn("GMT-3", salida)
        # Formato "(HH:MM GMT-3)" rescatado
        self.assertTrue(re.search(r"\(\d{2}:\d{2} GMT-3\)", salida))


if __name__ == "__main__":
    unittest.main()
