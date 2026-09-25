#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""test_redaccion: tests unitarios del visor/CLI de redaccion de evidencias.

Cubre: compilacion, hash SHA-256, normalizacion de regiones, aplicacion de
barra/blur/pixelado, exportacion (copia + manifest + reporte) y CLI. Sin red.
Los temporales se crean SIEMPRE dentro del repo (tests/tmp_redaccion), nunca
en %TEMP%.
"""

import contextlib
import io
import json
import os
import py_compile
import shutil
import sys
import unittest

DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tmp_redaccion")

sys.path.insert(0, DIR)

try:
    from PIL import Image, ImageDraw
    HAVE_PIL = True
except Exception:  # pragma: no cover
    HAVE_PIL = False

import redaccion as rd  # noqa: E402
import redactar  # noqa: E402


def _imagen_prueba(path, ancho=100, alto=80, color=(200, 30, 30)):
    img = Image.new("RGB", (ancho, alto), color)
    ImageDraw.Draw(img).rectangle([10, 10, 40, 40], fill=(10, 200, 10))
    img.save(path, "PNG")
    return path


class TestCompilacion(unittest.TestCase):
    def test_compila_todo(self):
        for nombre in ("redaccion.py", "redactar.py", "visor_redaccion.py"):
            with self.subTest(archivo=nombre):
                py_compile.compile(os.path.join(DIR, nombre), doraise=True)


@unittest.skipUnless(HAVE_PIL, "Pillow no disponible")
class TestRedaccion(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.makedirs(TMP, exist_ok=True)
        cls.entrada = _imagen_prueba(os.path.join(TMP, "evidencia.png"))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(TMP, ignore_errors=True)

    def test_hash_sha256(self):
        h1 = rd.hash_sha256(self.entrada)
        h2 = rd.hash_sha256(self.entrada)
        self.assertEqual(h1, h2)
        self.assertEqual(len(h1), 64)

    def test_normalizar_region_absoluta(self):
        box = rd.normalizar_region([10, 5, 50, 60], 100, 80)
        self.assertEqual(box, (10, 5, 50, 60))

    def test_normalizar_region_normalizada(self):
        box = rd.normalizar_region([0.1, 0.1, 0.5, 0.5], 100, 80)
        self.assertEqual(box, (10, 8, 50, 40))

    def test_normalizar_region_dict(self):
        box = rd.normalizar_region({"x": 5, "y": 5, "w": 20, "h": 30}, 100, 80)
        self.assertEqual(box, (5, 5, 25, 35))

    def test_normalizar_region_clamp(self):
        box = rd.normalizar_region([-5, -5, 500, 500], 100, 80)
        self.assertEqual(box, (0, 0, 100, 80))

    def test_barra_pone_negro(self):
        img = Image.open(self.entrada)
        copia = rd.aplicar_redaccion(img, [{"region": [10, 10, 40, 40], "modo": "barra"}])
        self.assertEqual(copia.getpixel((25, 25)), (0, 0, 0))
        # fuera de la region no cambia
        self.assertNotEqual(img.getpixel((25, 25)), (0, 0, 0))
        # el original no se toco
        self.assertEqual(img.getpixel((25, 25)), (10, 200, 10))

    def test_blur_cambia_region(self):
        img = Image.open(self.entrada)
        # region que cruza el cuadrado verde y el fondo rojo (mezcla de colores)
        copia = rd.aplicar_redaccion(img, [{"region": [20, 20, 60, 60], "modo": "blur"}])
        self.assertNotEqual(copia.getpixel((25, 25)), (10, 200, 10))

    def test_pixelado_cambia_region(self):
        img = Image.open(self.entrada)
        copia = rd.aplicar_redaccion(img, [{"region": [20, 20, 60, 60], "modo": "pixelado", "intensidad": 8}])
        self.assertNotEqual(copia.getpixel((25, 25)), (10, 200, 10))

    def test_metodo_invalido(self):
        img = Image.open(self.entrada)
        with self.assertRaises(ValueError):
            rd.aplicar_redaccion(img, [{"region": [0, 0, 10, 10], "modo": "xyz"}])

    def test_byn_puro_binario(self):
        # 2 niveles = binario puro: solo 0 o 255
        img = Image.open(self.entrada)
        out = rd.aplicar_byn(img, niveles=2)
        pix = set()
        w, h = out.size
        for x in range(w):
            for y in range(h):
                pix.add(out.getpixel((x, y)))
        self.assertTrue(pix <= {(0, 0, 0), (255, 255, 255)}, pix)
        # una imagen de un solo color queda en un unico nivel
        self.assertLessEqual(len(pix), 2)

    def test_byn_niveles_acotados(self):
        img = Image.open(self.entrada)
        for n in (4, 8, 16, 32):
            out = rd.aplicar_byn(img, niveles=n)
            self.assertEqual(out.mode, "RGB")
        with self.assertRaises(ValueError):
            rd.aplicar_byn(img, niveles=3)

    def test_byn_en_redaccion_y_manifest(self):
        out = os.path.join(TMP, "salida_byn")
        regiones = [{"region": [10, 10, 40, 40], "modo": "barra", "motivo": "z"}]
        res = rd.redactar_archivo(self.entrada, regiones, out_dir=out,
                                  filtro_byn=2, comando="test byn")
        with open(res["manifest"], encoding="utf-8") as fh:
            m = json.load(fh)
        self.assertEqual(m["filtro_byn"]["niveles"], 2)
        # la salida es binaria
        from PIL import Image as _I
        sal = _I.open(res["salida"]).convert("RGB")
        pix = set()
        for x in range(sal.width):
            for y in range(sal.height):
                pix.add(sal.getpixel((x, y)))
        self.assertTrue(pix <= {(0, 0, 0), (255, 255, 255)}, pix)

    def test_barra_color_personalizado(self):
        img = Image.open(self.entrada)
        copia = rd.aplicar_redaccion(
            img, [{"region": [10, 10, 40, 40], "modo": "barra", "color": "#ff0000"}])
        self.assertEqual(copia.getpixel((25, 25)), (255, 0, 0))
        # el original sigue intacto
        self.assertEqual(img.getpixel((25, 25)), (10, 200, 10))

    def test_barra_borde_y_relleno(self):
        img = Image.open(self.entrada)
        copia = rd.aplicar_redaccion(img, [{
            "region": [10, 10, 40, 40], "modo": "barra",
            "color": "#00ff00", "color_borde": "#0000ff", "grosor_borde": 4}])
        # contorno azul cerca del borde de la caja
        self.assertEqual(copia.getpixel((11, 25)), (0, 0, 255))
        # relleno verde en el centro
        self.assertEqual(copia.getpixel((25, 25)), (0, 255, 0))
        # original intacto
        self.assertEqual(img.getpixel((25, 25)), (10, 200, 10))

    def test_barra_sin_borde(self):
        img = Image.open(self.entrada)
        copia = rd.aplicar_redaccion(img, [{
            "region": [10, 10, 40, 40], "modo": "barra", "color": "#ff0000",
            "color_borde": "sin borde"}])
        self.assertEqual(copia.getpixel((11, 25)), (255, 0, 0))  # no hay contorno
        self.assertEqual(copia.getpixel((25, 25)), (255, 0, 0))

    def test_marca_de_agua_cambia_imagen(self):
        img = Image.open(self.entrada)
        out = rd.marca_de_agua(img, texto="CONF", alpha=40)
        self.assertEqual(out.size, img.size)
        self.assertEqual(out.mode, "RGB")
        # respecto de la imagen solida original, la marca modifica pixeles
        self.assertNotEqual(list(out.getdata()), list(img.getdata()))

    def test_marca_de_agua_multilinea(self):
        img = Image.open(self.entrada)
        mono = rd.marca_de_agua(img, texto="copia autorizada a", alpha=40, tamanio=20)
        multi = rd.marca_de_agua(img, texto="copia autorizada a|correo@algo.com",
                                 alpha=40, tamanio=20)
        self.assertNotEqual(list(mono.getdata()), list(multi.getdata()))

    def test_marca_de_agua_tamanio(self):
        img = Image.open(self.entrada)
        a = rd.marca_de_agua(img, texto="CONF", alpha=40, tamanio=20)
        b = rd.marca_de_agua(img, texto="CONF", alpha=40, tamanio=80)
        self.assertNotEqual(list(a.getdata()), list(b.getdata()))

    def test_marca_de_agua_color(self):
        img = Image.open(self.entrada)
        a = rd.marca_de_agua(img, texto="CONF", alpha=120, tamanio=30, color="#ffffff")
        b = rd.marca_de_agua(img, texto="CONF", alpha=120, tamanio=30, color="#ff0000")
        self.assertNotEqual(list(a.getdata()), list(b.getdata()))

    def test_marca_de_agua_negrita(self):
        img = Image.open(self.entrada)
        a = rd.marca_de_agua(img, texto="CONF", alpha=90, tamanio=40, negrita=False)
        b = rd.marca_de_agua(img, texto="CONF", alpha=90, tamanio=40, negrita=True)
        self.assertNotEqual(list(a.getdata()), list(b.getdata()))

    def test_marca_de_agua_cantidad(self):
        img = Image.open(self.entrada)
        a = rd.marca_de_agua(img, texto="CONF", alpha=90, tamanio=40, cantidad=1)
        b = rd.marca_de_agua(img, texto="CONF", alpha=90, tamanio=40, cantidad=5)
        self.assertNotEqual(list(a.getdata()), list(b.getdata()))

    def test_pdf_con_marca_de_agua(self):
        out = os.path.join(TMP, "salida_pdf")
        regiones = [{"region": [10, 10, 40, 40], "modo": "barra", "motivo": "z"}]
        res = rd.redactar_archivo(self.entrada, regiones, out_dir=out,
                                  pdf=True, marca_agua="TEST-CONF",
                                  marca_tamanio=48, marca_alpha=80,
                                  marca_color="#ff0000", marca_negrita=True,
                                  marca_cantidad=5, comando="test pdf")
        self.assertTrue(os.path.isfile(res["salida"]))
        self.assertTrue(res["salida_pdf"] and os.path.isfile(res["salida_pdf"]))
        with open(res["salida_pdf"], "rb") as fh:
            self.assertEqual(fh.read(4), b"%PDF")
        with open(res["manifest"], encoding="utf-8") as fh:
            m = json.load(fh)
        self.assertEqual(m["marca_agua"]["texto"], "TEST-CONF")
        self.assertEqual(m["marca_agua"]["tamanio"], 48)
        self.assertEqual(m["marca_agua"]["alpha"], 80)
        self.assertEqual(m["marca_agua"]["color"], "#ff0000")
        self.assertTrue(m["marca_agua"]["negrita"])
        self.assertEqual(m["marca_agua"]["cantidad"], 5)
        self.assertFalse(m["pdf_protegido"])
        self.assertTrue(m["salida_pdf"].endswith(".pdf"))
        # sin --pdf no se genera el PDF
        res2 = rd.redactar_archivo(self.entrada, regiones,
                                   out_dir=os.path.join(TMP, "salida_sin_pdf"),
                                   comando="test")
        self.assertIsNone(res2.get("salida_pdf"))

    @unittest.skipUnless(rd.HAVE_PYPDF, "pypdf no disponible")
    def test_pdf_con_contrasena(self):
        out = os.path.join(TMP, "salida_clave")
        regiones = [{"region": [10, 10, 40, 40], "modo": "barra", "motivo": "z"}]
        res = rd.redactar_archivo(self.entrada, regiones, out_dir=out,
                                  pdf=True, marca_agua="CONF",
                                  pdf_password="clave123", comando="test clave")
        self.assertTrue(res["salida_pdf"] and os.path.isfile(res["salida_pdf"]))
        from pypdf import PdfReader
        r = PdfReader(res["salida_pdf"])
        self.assertTrue(r.is_encrypted)
        r.decrypt("clave123")
        self.assertEqual(len(r.pages), 1)
        with open(res["manifest"], encoding="utf-8") as fh:
            m = json.load(fh)
        self.assertTrue(m["pdf_protegido"])
        # la contrasena NUNCA queda en claro en el manifest
        self.assertNotIn("clave123", json.dumps(m))

    def test_redactar_archivo_genera_copia_manifest_y_hashes(self):
        out = os.path.join(TMP, "salida1")
        regiones = [
            {"region": [10, 10, 40, 40], "modo": "barra", "motivo": "zona 1"},
            {"region": [0.5, 0.5, 0.9, 0.9], "modo": "blur", "motivo": "zona 2"},
        ]
        res = rd.redactar_archivo(self.entrada, regiones, out_dir=out, comando="test")
        self.assertTrue(os.path.isfile(res["salida"]))
        self.assertTrue(os.path.isfile(res["manifest"]))
        self.assertTrue(os.path.isfile(os.path.join(out, "reporte.log")))
        # el original intacto
        self.assertEqual(res["hash_original"], rd.hash_sha256(self.entrada))
        self.assertNotEqual(res["hash_original"], res["hash_salida"])
        with open(res["manifest"], encoding="utf-8") as fh:
            m = json.load(fh)
        self.assertEqual(m["n_regiones"], 2)
        self.assertEqual(m["entrada"], "evidencia.png")
        self.assertTrue(m["herramienta"].endswith("/redaccion"))

    def test_redactar_archivo_sin_regiones(self):
        with self.assertRaises(ValueError):
            rd.redactar_archivo(self.entrada, [], out_dir=os.path.join(TMP, "nada"))

    def test_cli_ayuda(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            with self.assertRaises(SystemExit):
                redactar.main(["--help"])

    def test_cli_batch(self):
        reglas = os.path.join(TMP, "reglas.json")
        with open(reglas, "w", encoding="utf-8") as fh:
            json.dump([{"region": [10, 10, 40, 40], "modo": "barra", "motivo": "test"}], fh)
        out = os.path.join(TMP, "cli_out")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = redactar.main(["-i", self.entrada, "-r", reglas, "-o", out])
        self.assertEqual(rc, 0)
        self.assertTrue(os.path.isfile(os.path.join(out, "evidencia_redactada.png")))

    def test_cli_region_mal(self):
        reglas = os.path.join(TMP, "mal.json")
        with open(reglas, "w", encoding="utf-8") as fh:
            json.dump([{"modo": "barra"}], fh)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = redactar.main(["-i", self.entrada, "-r", reglas, "-o", os.path.join(TMP, "bad")])
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()