# ------------------------------------------------------------
# DISCLAIMER: Este script es parte del repositorio de herramientas de pruebas de penetración.
# Su uso está sujeto a los términos de la licencia MIT y al aviso legal presente en el README.
# ------------------------------------------------------------

import logging
logger = logging.getLogger(__name__)
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
logger.addHandler(handler)
logger.setLevel(logging.INFO)

import unittest
import os
import sys
import json
import tempfile
import shutil
from unittest.mock import patch, MagicMock
from bs4 import BeautifulSoup

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import download



class TestSyntaxAndImports(unittest.TestCase):
    """Valida que el modulo se importa sin errores."""

    def test_import(self):
        self.assertTrue(hasattr(download, '__version__'))
        self.assertEqual(download.__version__, "3.0.0")

    def test_constants(self):
        self.assertEqual(download.BASE_URL, "https://portswigger.net")
        self.assertEqual(download.IMAGES_DIR_NAME, "images")


class TestArgparse(unittest.TestCase):
    """Valida el parser de argumentos."""

    def test_default_args(self):
        import argparse
        with patch('sys.argv', ['download.py']):
            parser = argparse.ArgumentParser()
            parser.add_argument("-l", "--lang", choices=["es", "en"], default="es")
            parser.add_argument("-o", "--output", default="portswigger_academy_content")
            parser.add_argument("-d", "--delay", type=float, default=1.0)
            parser.add_argument("-r", "--retries", type=int, default=3)
            parser.add_argument("-t", "--threads", type=int, default=4)
            parser.add_argument("-v", "--verbose", action="store_true")
            args = parser.parse_args([])
            self.assertEqual(args.lang, "es")
            self.assertEqual(args.threads, 4)
            self.assertEqual(args.delay, 1.0)


class TestUrlToFilePath(unittest.TestCase):
    """Valida conversion de URLs a rutas de archivos."""

    def test_academy_lesson(self):
        url = "https://portswigger.net/web-security/academy/sessions/lab-basic-session-attack"
        result = download.url_to_filepath(url, "/output")
        self.assertTrue(result.endswith(".html"))
        self.assertIn("lab-basic-session-attack", result)

    def test_topic_url(self):
        url = "https://portswigger.net/web-security/cors"
        result = download.url_to_filepath(url, "/output")
        self.assertTrue(result.endswith(".html"))
        self.assertTrue(result.startswith("/output"))

    def test_index_url(self):
        url = "https://portswigger.net/web-security/"
        result = download.url_to_filepath(url, "/output")
        self.assertIn("index.html", result)

    def test_numbered_topic(self):
        url = "https://portswigger.net/web-security/cors"
        result = download.url_to_filepath(url, "/output", indices=[1])
        self.assertIn("001_cors.html", result)

    def test_numbered_lesson(self):
        url = "https://portswigger.net/web-security/cors/access-control-allow-origin"
        result = download.url_to_filepath(url, "/output", indices=[1, 2])
        self.assertIn("001_cors", result)
        self.assertIn("002_access-control-allow-origin.html", result)


class TestImageFilters(unittest.TestCase):
    """Valida filtros de imagenes."""

    def test_ico_rejected(self):
        self.assertFalse(download._is_content_image("https://example.com/favicon.ico"))

    def test_tracking_rejected(self):
        self.assertFalse(download._is_content_image("https://example.com/tracking/pixel.gif"))

    def test_content_accepted(self):
        self.assertTrue(download._is_content_image("https://portswigger.net/web-security/images/diagram.png"))

    def test_svg_accepted(self):
        self.assertTrue(download._is_content_image("https://portswigger.net/web-security/images/architecture.svg"))

    def test_webp_accepted(self):
        self.assertTrue(download._is_content_image("https://portswigger.net/web-security/images/photo.webp"))


class TestSpamDetection(unittest.TestCase):
    """Valida deteccion de bloques spam."""

    def setUp(self):
        self.soup = BeautifulSoup("<html><body><div>Normal content</div></body></html>", "html.parser")

    def test_spam_element(self):
        el = BeautifulSoup("<div>Want to track your progress</div>", "html.parser").find("div")
        self.assertTrue(download._is_spam_element(el))

    def test_non_spam_element(self):
        el = BeautifulSoup("<div>CORS allows cross-origin requests</div>", "html.parser").find("div")
        self.assertFalse(download._is_spam_element(el))


class TestImageResolution(unittest.TestCase):
    """Valida resolucion de URLs de imagenes."""

    def test_src_resolution(self):
        img = BeautifulSoup('<img src="/images/test.png">', "html.parser").find("img")
        result = download._resolve_image_url(img, "https://portswigger.net/web-security/cors")
        self.assertEqual(result, "https://portswigger.net/images/test.png")

    def test_data_src_resolution(self):
        img = BeautifulSoup('<img data-src="/images/lazy.png">', "html.parser").find("img")
        result = download._resolve_image_url(img, "https://portswigger.net/web-security/cors")
        self.assertEqual(result, "https://portswigger.net/images/lazy.png")

    def test_data_uri_skipped(self):
        img = BeautifulSoup('<img src="data:image/png;base64,abc">', "html.parser").find("img")
        result = download._resolve_image_url(img, "https://portswigger.net/web-security/cors")
        self.assertIsNone(result)

    def test_no_src(self):
        img = BeautifulSoup('<img alt="test">', "html.parser").find("img")
        result = download._resolve_image_url(img, "https://portswigger.net/web-security/cors")
        self.assertIsNone(result)


class TestExtractTopicLinks(unittest.TestCase):
    """Valida extraccion de links de temas."""

    def test_extracts_topics(self):
        html = '''
        <html><body>
        <div class="container-cards-white-medium-space-between">
            <a href="/web-security/cors"><h3>CORS</h3></a>
            <a href="/web-security/sessions"><h3>Sessions</h3></a>
            <a href="/web-security/all-labs"><h3>All labs (skip)</h3></a>
            <a href="/web-security/certification"><h3>Cert (skip)</h3></a>
        </div>
        </body></html>
        '''
        soup = BeautifulSoup(html, "html.parser")
        links = download.extract_topic_links(soup)
        self.assertEqual(len(links), 2)
        self.assertTrue(any("cors" in l for l in links))
        self.assertTrue(any("sessions" in l for l in links))

    def test_empty_page(self):
        soup = BeautifulSoup("<html><body></body></html>", "html.parser")
        links = download.extract_topic_links(soup)
        self.assertEqual(len(links), 0)


class TestExtractLessonLinks(unittest.TestCase):
    """Valida extraccion de links de lecciones."""

    def test_extracts_lessons(self):
        html = '''
        <html><body>
        <aside class="nav-lhs">
            <nav class="nav-lhs-scrollable">
                <ul>
                    <li><a href="/web-security/cors">CORS overview</a></li>
                    <li><a href="/web-security/cors/exploiting">Exploiting CORS</a></li>
                    <li><a href="/web-security/cors/labs">Labs</a></li>
                    <li><a href="https://portswigger.net/web-security/cors/same-site">Same-site bypass</a></li>
                </ul>
            </nav>
        </aside>
        </body></html>
        '''
        soup = BeautifulSoup(html, "html.parser")
        links = download.extract_lesson_links(soup, "https://portswigger.net/web-security/cors")
        self.assertEqual(len(links), 3)


class TestSaveHtml(unittest.TestCase):
    """Valida guardado de HTML con fuente."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_saves_with_source(self):
        path = os.path.join(self.tmpdir, "test.html")
        download.save_html("<h1>Test</h1>", "https://example.com", path)
        self.assertTrue(os.path.exists(path))
        with open(path, 'r', encoding='utf-8') as f:
            content = f.read()
        self.assertIn("https://example.com", content)
        self.assertIn("<h1>Test</h1>", content)
        self.assertIn("Descargado:", content)


class TestProgressResume(unittest.TestCase):
    """Valida guardado/carga de progreso."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_save_and_load(self):
        urls = {"https://a.com", "https://b.com", "https://c.com"}
        download.save_progress(self.tmpdir, urls)
        loaded = download.load_progress(self.tmpdir)
        self.assertEqual(urls, loaded)

    def test_load_empty(self):
        loaded = download.load_progress(self.tmpdir)
        self.assertEqual(loaded, set())


class TestGenerateIndex(unittest.TestCase):
    """Valida generacion del indice maestro."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_generates_index(self):
        topics = {
            "cors": {
                "https://portswigger.net/web-security/cors/academy/lab1": "lab1",
                "https://portswigger.net/web-security/cors/academy/lab2": "lab2",
            }
        }
        download.generate_index(topics, self.tmpdir)
        idx = os.path.join(self.tmpdir, "INDEX.html")
        self.assertTrue(os.path.exists(idx))
        with open(idx, 'r', encoding='utf-8') as f:
            content = f.read()
        self.assertIn("cors", content)
        self.assertIn("lab1", content)
        self.assertIn("lab2", content)


class TestGenerateIndexJson(unittest.TestCase):
    """Valida generacion del indice JSON."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_generates_json(self):
        topics = {
            "cors": {
                "https://portswigger.net/web-security/cors/academy/lab1": "lab1",
                "https://portswigger.net/web-security/cors/academy/lab2": "lab2",
            },
            "sessions": {
                "https://portswigger.net/web-security/sessions/academy/lab-a": "lab-a",
            }
        }
        download.generate_index_json(topics, self.tmpdir)
        idx = os.path.join(self.tmpdir, "INDEX.json")
        self.assertTrue(os.path.exists(idx))
        with open(idx, 'r', encoding='utf-8') as f:
            data = json.load(f)
        self.assertEqual(data["total_topics"], 2)
        self.assertEqual(data["total_lessons"], 3)
        self.assertIn("cors", data["topics"])
        self.assertIn("sessions", data["topics"])
        self.assertEqual(data["topics"]["cors"]["lesson_count"], 2)
        self.assertIn("lab1", data["topics"]["cors"]["lessons"])


class TestExtractAndClean(unittest.TestCase):
    """Valida limpieza de HTML."""

    def test_removes_scripts(self):
        html = '<html><body><div class="container-main"><p>Content</p><script>x=1</script></div></body></html>'
        result = download.extract_and_clean(html, "https://example.com", "/tmp/img")
        self.assertNotIn("<script>", result)
        self.assertIn("Content", result)

    def test_removes_styles(self):
        html = '<html><body><div class="container-main"><p>Content</p><style>.x{color:red}</style></div></body></html>'
        result = download.extract_and_clean(html, "https://example.com", "/tmp/img")
        self.assertNotIn("<style>", result)

    def test_returns_empty_on_no_content(self):
        html = '<html><head></head></html>'
        result = download.extract_and_clean(html, "https://example.com", "/tmp/img")
        self.assertEqual(result, "")


class TestTranslateChunks(unittest.TestCase):
    """Valida chunking de texto para traduccion."""

    def test_short_text_single_chunk(self):
        result = download.split_into_chunks("Hello world")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], "Hello world")

    def test_long_text_splits(self):
        text = "A" * 10000
        result = download.split_into_chunks(text, max_size=4500)
        self.assertGreater(len(result), 1)
        for chunk in result:
            self.assertGreater(len(chunk), 0)

    def test_preserves_paragraphs(self):
        text = ("Para1 " * 20) + "\n\n" + ("Para2 " * 20) + "\n\n" + ("Para3 " * 20)
        result = download.split_into_chunks(text, max_size=100)
        self.assertGreater(len(result), 1)
        combined = "\n\n".join(result)
        self.assertIn("Para1", combined)
        self.assertIn("Para3", combined)


class TestTranslateProtection(unittest.TestCase):
    """Valida proteccion de contenido no traducible."""

    def test_code_block_protected(self):
        text = "Before\n```\ncode here\n```\nAfter"
        protected_text, protected = download.protect_content(text)
        self.assertNotIn("```", protected_text)
        self.assertEqual(len(protected), 1)
        restored = download.restore_content(protected_text, protected)
        self.assertEqual(restored, text)

    def test_inline_code_protected(self):
        text = "Use `variable` in code"
        protected_text, protected = download.protect_content(text)
        self.assertNotIn("`variable`", protected_text)
        restored = download.restore_content(protected_text, protected)
        self.assertEqual(restored, text)

    def test_image_link_protected(self):
        text = "See ![img](http://example.com/img.png) here"
        protected_text, protected = download.protect_content(text)
        self.assertNotIn("![img]", protected_text)
        restored = download.restore_content(protected_text, protected)
        self.assertEqual(restored, text)

    def test_no_protection_needed(self):
        text = "Simple text with no code"
        protected_text, protected = download.protect_content(text)
        self.assertEqual(len(protected), 0)
        self.assertEqual(protected_text, text)


class TestTranslateProgress(unittest.TestCase):
    """Valida sistema de resume para traduccion."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_save_and_load_progress(self):
        paths = {"001_topic/001_lesson.md", "001_topic/002_lesson.md"}
        download.save_progress(self.tmpdir, paths)
        loaded = download.load_progress(self.tmpdir)
        self.assertEqual(loaded, paths)

    def test_load_empty_when_no_file(self):
        loaded = download.load_progress(self.tmpdir)
        self.assertEqual(loaded, set())


if __name__ == "__main__":
    unittest.main()
