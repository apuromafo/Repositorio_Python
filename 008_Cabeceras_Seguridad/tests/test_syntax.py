# ------------------------------------------------------------
# DISCLAIMER: Este script es parte del repositorio de herramientas de pruebas de penetración.
# Su uso está sujeto a los términos de la licencia MIT y al aviso legal presente en el README.
# ------------------------------------------------------------

import unittest
import py_compile
import os
import logging

logger = logging.getLogger(__name__)
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
logger.addHandler(handler)
logger.setLevel(logging.INFO)

class TestSyntax(unittest.TestCase):
    def setUp(self):
        self.dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    def test_all_py_files_compile(self):
        errors = []
        for f in os.listdir(self.dir):
            if not f.endswith('.py'):
                continue
            path = os.path.join(self.dir, f)
            # Skip files inside old/ subdirectories
            rel_path = os.path.relpath(path, self.dir)
            if rel_path.startswith('old') or rel_path.startswith('OLD'):
                continue
            try:
                py_compile.compile(path, doraise=True)
            except py_compile.PyCompileError as e:
                errors.append(f"{f}: {e}")
        self.assertEqual([], errors)

if __name__ == '__main__':
    unittest.main()
