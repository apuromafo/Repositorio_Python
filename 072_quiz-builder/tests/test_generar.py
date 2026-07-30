import os, sys, json, tempfile, unittest, shutil
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from generar import main as generar_main

class TestGenerarDirect(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.mkdtemp()
        self.orig_dir = os.getcwd()
        # We'll test the preguntas.js generation by inspecting the template

    def tearDown(self):
        shutil.rmtree(self.temp, ignore_errors=True)
        os.chdir(self.orig_dir)

    def test_template_preguntas_exists(self):
        path = os.path.join(os.path.dirname(__file__), '..', 'template', 'preguntas.js')
        self.assertTrue(os.path.exists(path))

    def test_template_state_exists(self):
        path = os.path.join(os.path.dirname(__file__), '..', 'template', 'js', 'state.js')
        self.assertTrue(os.path.exists(path))

    def test_template_js_files(self):
        js_dir = os.path.join(os.path.dirname(__file__), '..', 'template', 'js')
        required = ['app.js', 'exam.js', 'storage.js', 'timer.js', 'state.js',
                     'filters.js', 'shortcuts.js', 'solution.js', 'navigation.js',
                     'renderer.js', 'stats.js', 'review.js', 'mistakesHistory.js',
                     'analytics.js', 'adaptive.js', 'visualization.js', 'profile.js',
                     'pdf-export.js', 'lang-es.js', 'lang-en.js', 'settings.js']
        for f in required:
            with self.subTest(f=f):
                self.assertTrue(os.path.exists(os.path.join(js_dir, f)), f'Missing {f}')

    def test_template_css_files(self):
        css_dir = os.path.join(os.path.dirname(__file__), '..', 'template', 'css')
        required = ['exam.css', 'pdf-export.css', 'themes.css']
        for f in required:
            with self.subTest(f=f):
                self.assertTrue(os.path.exists(os.path.join(css_dir, f)), f'Missing {f}')

    def test_template_html_files(self):
        tpl = os.path.join(os.path.dirname(__file__), '..', 'template')
        self.assertTrue(os.path.exists(os.path.join(tpl, 'index.html')))
        self.assertTrue(os.path.exists(os.path.join(tpl, 'editor.html')))

    def test_preguntas_template_has_placeholders(self):
        path = os.path.join(os.path.dirname(__file__), '..', 'template', 'preguntas.js')
        with open(path, encoding='utf-8') as f:
            content = f.read()
        self.assertIn('{ID_EXAMEN}', content)
        self.assertIn('{NOMBRE_EXAMEN}', content)
        self.assertIn('{TEMAS}', content)
        self.assertIn('const questionBank = [', content)

    def test_state_has_required_fields(self):
        path = os.path.join(os.path.dirname(__file__), '..', 'template', 'js', 'state.js')
        with open(path, encoding='utf-8') as f:
            content = f.read()
        self.assertIn('examTopics', content)
        self.assertIn('topicNames', content)
        self.assertIn('timeRemaining', content)
        self.assertIn('currentUser', content)

class TestExamenesJson(unittest.TestCase):
    def test_examenes_json_valid(self):
        path = os.path.join(os.path.dirname(__file__), '..', 'examenes.json')
        if os.path.exists(path):
            with open(path, encoding='utf-8') as f:
                data = json.load(f)
            self.assertIsInstance(data, list)

if __name__ == '__main__':
    unittest.main()
