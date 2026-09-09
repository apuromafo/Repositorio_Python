# ------------------------------------------------------------
# DISCLAIMER: Este script es parte del repositorio de herramientas de pruebas de penetración.
# Su uso está sujeto a los términos de la licencia MIT y al aviso legal presente en el README.
# ------------------------------------------------------------

import unittest
import unittest.mock
import sys
import os
import platform

import logging
logger = logging.getLogger(__name__)
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
logger.addHandler(handler)
logger.setLevel(logging.INFO)

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__))))

from scan_secret import (
    debe_excluir,
    obtener_exclusiones_directorios,
    _obtener_binario_local,
    _validar_binario,
    _buscar_en_path,
    _seleccionar_asset_github,
    _HERRAMIENTAS_CONFIG,
    _DIR_TOOLS,
    _leer_config_herramientas,
    _guardar_config_herramientas,
)


class TestScanSecret(unittest.TestCase):
    def test_obtener_exclusiones(self):
        exclusiones = obtener_exclusiones_directorios()
        self.assertIn(".git", exclusiones)
        self.assertIn("node_modules", exclusiones)
        self.assertIn(".scannerwork", exclusiones)

    def test_exclusion_residuos_sonarqube(self):
        self.assertIn(".sonarqube", obtener_exclusiones_directorios())
        self.assertIn(".sonar", obtener_exclusiones_directorios())

    def test_debe_excluir_sonarqube(self):
        self.assertTrue(debe_excluir("/proyecto/.sonarqube/report.json", [".sonarqube"]))

    def test_debe_excluir_residuo_pytest(self):
        self.assertTrue(debe_excluir("/proyecto/tests/.pytest_cache/v/cache/nodeids", [".pytest_cache"]))

    def test_debe_excluir_git(self):
        self.assertTrue(debe_excluir("/proyecto/.git/config", [".git"]))

    def test_debe_excluir_node_modules(self):
        self.assertTrue(debe_excluir("/proyecto/node_modules/foo/bar.js", [".git", "node_modules"]))

    def test_debe_excluir_scannerwork(self):
        self.assertTrue(debe_excluir("/proyecto/.scannerwork/report.json", [".git", ".scannerwork"]))

    def test_no_excluir_normal(self):
        self.assertFalse(debe_excluir("/proyecto/src/main.py", [".git", "node_modules"]))

    def test_debe_excluir_ruta_vacia(self):
        self.assertFalse(debe_excluir("", [".git"]))

    def test_debe_excluir_ruta_none(self):
        self.assertFalse(debe_excluir(None, [".git"]))


class TestHerramientasConfig(unittest.TestCase):
    def test_config_gitleaks_existe(self):
        self.assertIn("gitleaks", _HERRAMIENTAS_CONFIG)
        cfg = _HERRAMIENTAS_CONFIG["gitleaks"]
        self.assertIn("repo", cfg)
        self.assertIn("cmd", cfg)
        self.assertIn("version_fallback", cfg)
        self.assertIn("asset_patterns", cfg)
        self.assertIn("binary_name", cfg)

    def test_config_trufflehog_existe(self):
        self.assertIn("trufflehog", _HERRAMIENTAS_CONFIG)
        cfg = _HERRAMIENTAS_CONFIG["trufflehog"]
        self.assertIn("repo", cfg)
        self.assertIn("cmd", cfg)
        self.assertIn("version_fallback", cfg)

    def test_asset_patterns_todas_plataformas(self):
        for nombre, cfg in _HERRAMIENTAS_CONFIG.items():
            for plataforma in ["Windows", "Linux", "Darwin"]:
                self.assertIn(plataforma, cfg["asset_patterns"],
                              f"{nombre} no tiene asset para {plataforma}")
                self.assertIn(plataforma, cfg["binary_name"],
                              f"{nombre} no tiene binary_name para {plataforma}")

    def test_asset_patterns_darwin_coinciden_assets_reales(self):
        for nombre, cfg in _HERRAMIENTAS_CONFIG.items():
            patron = cfg["asset_patterns"]["Darwin"]
            self.assertNotIn("universal", patron.lower(),
                             f"{nombre}: darwin_universal no existe en GitHub")
            extencion_valida = patron.endswith(".tar.gz")
            self.assertTrue(extencion_valida, f"{nombre}: Darwin debe ser .tar.gz")

    def test_dir_tools_es_subdirectorio_del_script(self):
        import scan_secret as ss
        import os as _os
        self.assertEqual(_DIR_TOOLS, _os.path.join(ss.DIR_SCRIPT, "tools"))
        self.assertTrue(_os.path.isdir(ss.DIR_SCRIPT))


class TestObtenerBinarioLocal(unittest.TestCase):
    def test_retorna_none_si_no_existe(self):
        result = _obtener_binario_local("gitleaks")
        if result is not None:
            self.assertTrue(os.path.isfile(result))
        else:
            self.assertIsNone(result)

    def test_herramienta_inexistente_retorna_none(self):
        result = _obtener_binario_local("herramienta_que_no_existe_12345")
        self.assertIsNone(result)


class TestValidarBinario(unittest.TestCase):
    def test_binario_invalido_retorna_none(self):
        result = _validar_binario("no_existe_abc123", "--version")
        self.assertIsNone(result)

    def test_binario_none_retorna_none(self):
        result = _validar_binario(None, "--version")
        self.assertIsNone(result)


class TestBuscarEnPath(unittest.TestCase):
    def test_herramienta_inexistente_retorna_none(self):
        result = _buscar_en_path("herramienta_que_no_existe_12345")
        self.assertIsNone(result)

    def test_retorna_none_si_vacio(self):
        result = _buscar_en_path("")
        self.assertIsNone(result)


class TestSeleccionarAssetGithub(unittest.TestCase):
    def test_selecciona_asset_windows(self):
        assets = [
            {"name": "gitleaks_8.21.2_linux_x64.tar.gz", "browser_download_url": "https://linux"},
            {"name": "gitleaks_8.21.2_windows_x64.zip", "browser_download_url": "https://windows"},
            {"name": "gitleaks_8.21.2_darwin_universal.tar.gz", "browser_download_url": "https://darwin"},
        ]
        result = _seleccionar_asset_github(assets, "gitleaks", "8.21.2")
        if platform.system() == "Windows":
            self.assertIn("windows", result)
        elif platform.system() == "Linux":
            self.assertIn("linux", result)
        elif platform.system() == "Darwin":
            self.assertIn("darwin", result)

    def test_retorna_none_si_no_coincide(self):
        assets = [{"name": "otro_archivo.tar.gz", "browser_download_url": "https://x"}]
        result = _seleccionar_asset_github(assets, "gitleaks", "99.99.99")
        self.assertIsNone(result)

    def test_lista_vacia_retorna_none(self):
        result = _seleccionar_asset_github([], "gitleaks", "8.21.2")
        self.assertIsNone(result)

    def test_fallback_por_plataforma(self):
        assets = [
            {"name": "gitleaks_8.21.2_linux_amd64.tar.gz", "browser_download_url": "https://linux"},
            {"name": "gitleaks_8.21.2_windows_amd64.zip", "browser_download_url": "https://windows"},
        ]
        result = _seleccionar_asset_github(assets, "gitleaks", "8.21.2")
        self.assertIsNotNone(result)


class TestConfigHerramientas(unittest.TestCase):
    def setUp(self):
        self._dir_test_config = os.path.join(os.path.dirname(os.path.dirname(__file__)), "_test_config")
        self._patch_dir = unittest.mock.patch("scan_secret._DIR_CONFIG", self._dir_test_config)
        self._patch_dir.start()
        self._patch_config = unittest.mock.patch("scan_secret.ARCHIVO_CONFIG", os.path.join(self._dir_test_config, "herramientas.json"))
        self._patch_config.start()
        self.addCleanup(self._patch_dir.stop)
        self.addCleanup(self._patch_config.stop)

    def test_leer_sin_archivo_retorna_none(self):
        self.assertIsNone(_leer_config_herramientas())

    def test_guardar_y_leer_devuelven_estructura(self):
        versiones = {"gitleaks": "8.24.2", "trufflehog": "3.95.9"}
        _guardar_config_herramientas("C:/bin/gitleaks.exe", "C:/bin/trufflehog.exe", versiones)
        data = _leer_config_herramientas()
        self.assertIsNotNone(data)
        self.assertEqual(data["sistema_operativo"], platform.system())
        self.assertEqual(data["herramientas"]["gitleaks"]["ruta"], "C:/bin/gitleaks.exe")
        self.assertEqual(data["herramientas"]["gitleaks"]["version"], "8.24.2")
        self.assertEqual(data["herramientas"]["trufflehog"]["version"], "3.95.9")

    def test_guardar_con_binarios_none(self):
        _guardar_config_herramientas(None, None, {"gitleaks": "8.24.2", "trufflehog": "3.95.9"})
        data = _leer_config_herramientas()
        self.assertIsNotNone(data)
        self.assertIsNone(data["herramientas"]["gitleaks"]["ruta"])
        self.assertIsNone(data["herramientas"]["trufflehog"]["ruta"])

    def test_leer_so_distinto_retorna_none(self):
        versiones = {"gitleaks": "8.24.2", "trufflehog": "3.95.9"}
        _guardar_config_herramientas("C:/bin/gitleaks.exe", "C:/bin/trufflehog.exe", versiones)
        with unittest.mock.patch("scan_secret.platform.system", return_value="Linux"):
            self.assertIsNone(_leer_config_herramientas())

    def tearDown(self):
        if os.path.isdir(self._dir_test_config):
            import shutil
            shutil.rmtree(self._dir_test_config, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
