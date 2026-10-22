# ------------------------------------------------------------
# DISCLAIMER: Este script es parte del repositorio de herramientas de pruebas de penetración.
# Su uso está sujeto a los términos de la licencia MIT y al aviso legal presente en el README.
# ------------------------------------------------------------

# Tests unitarios del motor de análisis profundo de CSP (v1.1.0).
# Casos basados en la semántica de CSP Evaluator (Google, CSP v3):
#   - Cabeceras_Seguridad.parsear_csp: tokenizado de directivas.
#   - Cabeceras_Seguridad.csp_efectiva: herencia fallback (CSP3).
#   - Cabeceras_Seguridad.evaluar_tokens_csp: hallazgos por fuente/directiva.
#   - Cabeceras_Seguridad.analizar_csp_profundo: agregado, dedupe y faltantes.
# El análisis profundoademás cubre directivas faltantes (form-action, base-uri,
# frame-ancestors, upgrade-insecure-requests, report-uri/report-to).

import unittest
import os
import re
import sys
import io
import contextlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import Cabeceras_Seguridad as tool  # noqa: E402


CSP_COOPEUCH = (
    "default-src 'self' 'unsafe-inline'; base-uri 'self'; object-src 'none'; "
    "font-src * data: 'self' 'unsafe-inline'; img-src * data: 'self'; "
    "script-src 'self' 'unsafe-eval' 'unsafe-inline'; frame-src * 'self'; "
    "media-src * data: 'self'; "
    "script-src-elem 'self' code.iconify.design api.iconify.design 'unsafe-inline' 'unsafe-eval'; "
    "connect-src 'self'; worker-src blob:"
)

CSP_STRICT_NONCE = (
    "default-src 'self'; script-src 'self' 'nonce-AbCdEf01' 'strict-dynamic'; "
    "style-src 'self'; img-src 'self' data:; frame-ancestors 'none'; "
    "form-action 'self'; base-uri 'none'; object-src 'none'"
)


def _sev(hallazgos):
    return {(h["directiva"], h["fuente"], h["severidad"]) for h in hallazgos}


class TestParsearCsp(unittest.TestCase):
    def test_directivas_y_orden(self):
        directivas, orden = tool.parsear_csp(CSP_COOPEUCH)
        self.assertEqual(orden[0], "default-src")
        self.assertIn("script-src-elem", directivas)
        self.assertEqual(directivas["script-src-elem"], ["'self'", "code.iconify.design", "api.iconify.design", "'unsafe-inline'", "'unsafe-eval'"])
        self.assertEqual(directivas["worker-src"], ["blob:"])

    def test_directiva_repetida_combina(self):
        directivas, orden = tool.parsear_csp("script-src 'self'; script-src data:")
        self.assertEqual(orden.count("script-src"), 1)
        self.assertEqual(directivas["script-src"], ["'self'", "data:"])

    def test_vacia(self):
        directivas, orden = tool.parsear_csp("   ")
        self.assertEqual(directivas, {})
        self.assertEqual(orden, [])


class TestCspEfectiva(unittest.TestCase):
    def test_declarada_gana(self):
        directivas, _ = tool.parsear_csp("default-src 'none'; script-src 'self'")
        nombre, toks = tool.csp_efectiva(directivas, "script-src", ("default-src",))
        self.assertEqual(nombre, "script-src")
        self.assertEqual(toks, ["'self'"])

    def test_hereda_default_src(self):
        directivas, _ = tool.parsear_csp("default-src 'self' 'unsafe-inline'")
        nombre, toks = tool.csp_efectiva(directivas, "style-src", ("default-src",))
        self.assertEqual(nombre, "style-src (heredada de default-src)")
        self.assertEqual(toks, ["'self'", "'unsafe-inline'"])

    def test_sin_politica(self):
        directivas, _ = tool.parsear_csp("frame-src *")
        nombre, toks = tool.csp_efectiva(directivas, "script-src", ("default-src",))
        self.assertIsNone(toks)
        self.assertIn("sin política", nombre)


class TestEvaluarTokens(unittest.TestCase):
    def test_unsafe_inline_script_alta(self):
        h = tool.evaluar_tokens_csp("script-src", ["'self'", "'unsafe-inline'"], "script")
        severidades = {(x["directiva"], x["fuente"], x["severidad"]) for x in h}
        self.assertIn(("script-src", "'unsafe-inline'", "alta"), severidades)

    def test_unsafe_eval_alta(self):
        h = tool.evaluar_tokens_csp("script-src", ["'unsafe-eval'"], "script")
        self.assertTrue(any(x["severidad"] == "alta" and x["fuente"] == "'unsafe-eval'" for x in h))

    def test_self_script_posible_alta(self):
        h = tool.evaluar_tokens_csp("script-src", ["'self'"], "script")
        self.assertTrue(any(x["severidad"] == "posible_alta" for x in h))
        self.assertIn("JSONP", next(x for x in h if x["severidad"] == "posible_alta")["riesgo"])

    def test_host_externo_info(self):
        h = tool.evaluar_tokens_csp("script-src-elem", ["code.iconify.design"], "script")
        self.assertTrue(any(x["severidad"] == "info" for x in h))
        self.assertFalse(any(x["severidad"] == "alta" for x in h))

    def test_nonce_con_unsafe_inline_es_info(self):
        h = tool.evaluar_tokens_csp("script-src", ["'nonce-AbCdEf01'", "'unsafe-inline'"], "script")
        hallazgos_inline = [x for x in h if x["fuente"] == "'unsafe-inline'"]
        self.assertEqual(len(hallazgos_inline), 1)
        self.assertEqual(hallazgos_inline[0]["severidad"], "info")

    def test_strict_dynamic_con_unsafe_inline_es_info(self):
        h = tool.evaluar_tokens_csp("script-src", ["'strict-dynamic'", "'unsafe-inline'"], "script")
        hallazgos_inline = [x for x in h if x["fuente"] == "'unsafe-inline'"]
        self.assertEqual(hallazgos_inline[0]["severidad"], "info")

    def test_data_en_script_alta(self):
        h = tool.evaluar_tokens_csp("script-src", ["data:"], "script")
        self.assertTrue(any(x["severidad"] == "alta" for x in h))

    def test_data_en_otras_es_baja_no_alta(self):
        # Regresión: font-src data: no debe alarmar como script (falso positivo del motor viejo)
        h = tool.evaluar_tokens_csp("font-src", ["data:"], "otras")
        self.assertTrue(h)
        self.assertEqual({x["severidad"] for x in h}, {"baja"})

    def test_unsafe_inline_style_media(self):
        h = tool.evaluar_tokens_csp("style-src", ["'unsafe-inline'"], "style")
        self.assertTrue(any(x["severidad"] == "media" for x in h))

    def test_none_sin_hallazgo(self):
        h = tool.evaluar_tokens_csp("object-src", ["'none'"], "otras")
        self.assertEqual(h, [])


class TestAnalizarCspProfundo(unittest.TestCase):
    def test_csp_coopeuch_severidades(self):
        # El sitio real devuelve X-Frame-Options: SAMEORIGIN (se protege embebido)
        hallazgos = tool.analizar_csp_profundo(CSP_COOPEUCH, xfo_value="SAMEORIGIN")
        s = _sev(hallazgos)
        # El motor debe replicar los findings de CSP Evaluator (Google v3):
        self.assertIn(("script-src", "'unsafe-inline'", "alta"), s)
        self.assertIn(("script-src", "'unsafe-eval'", "alta"), s)
        self.assertIn(("script-src-elem", "'unsafe-inline'", "alta"), s)
        self.assertIn(("script-src-elem", "'unsafe-eval'", "alta"), s)
        self.assertIn(("script-src", "'self'", "posible_alta"), s)
        self.assertIn(("script-src-elem", "'self'", "posible_alta"), s)
        self.assertIn(("script-src-elem", "code.iconify.design", "info"), s)
        self.assertIn(("script-src-elem", "api.iconify.design", "info"), s)
        # Familias residuales con sus PROPIOS tokens:
        self.assertIn(("media-src", "*", "baja"), s)
        self.assertIn(("font-src", "*", "baja"), s)
        # Faltantes recomendables:
        self.assertIn(("form-action", "(directiva ausente)", "media"), s)
        # frame-ancestors existe como baja si XFO la cubre:
        self.assertIn(("frame-ancestors", "(directiva ausente)", "baja"), s)
        # Con object-src 'none' declarada no hay hallazgo de plugins:
        self.assertNotIn(("object-src", "(sin 'none' o sin política)", "media"), s)

    def test_csp_strict_nonce_sin_falsas_altas(self):
        hallazgos = tool.analizar_csp_profundo(CSP_STRICT_NONCE, xfo_value="DENY")
        s = _sev(hallazgos)
        # Políticas robustas: no debe haber hallazgos de 'unsafe-inline'/'unsafe-eval'
        altas = [k for k in s if k[2] in ("alta", "media")]
        self.assertEqual(altas, [])
        # Directivas duras declaradas (frame-ancestors / form-action / base-uri) no generan faltante:
        self.assertNotIn(("form-action", "(directiva ausente)", "media"), s)
        # Sin frame-ancestors... aquí SÍ está declarada y es 'none':
        self.assertTrue(all(k[0] != "frame-ancestors" for k in s))

    def test_frame_ancestors_respeto_xfo(self):
        # Sin XFO restrictiva y sin frame-ancestors => Media (clickjacking)
        hallazgos = tool.analizar_csp_profundo("script-src 'self'")
        s = _sev(hallazgos)
        self.assertIn(("frame-ancestors", "(directiva ausente)", "media"), s)

    def test_cierre_con_resumen_y_separador(self):
        # v1.4.1: la sección cierra con barra de separación + línea [Resumen],
        # delimitándola visualmente del resto del reporte (caché, plan, etc.).
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            tool.analizar_csp_profundo(CSP_COOPEUCH)
        salida = re.sub(r"\x1b\[[0-9;]*m", "", buf.getvalue())
        self.assertIn("[Resumen] Análisis profundo CSP:", salida)
        # La última línea visible de la sección es una barra del ancho de la apertura.
        self.assertTrue(salida.rstrip().endswith("=" * 70))

    def test_vacia_devuelve_lista_vacia(self):
        self.assertEqual(tool.analizar_csp_profundo(""), [])
        self.assertEqual(tool.analizar_csp_profundo(None), [])


if __name__ == "__main__":
    unittest.main()
