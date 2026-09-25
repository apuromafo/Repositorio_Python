from __future__ import annotations

import csv
import io
import json
import subprocess
import sys
import tempfile
import unittest
from datetime import date
from pathlib import Path

import catalogo_ciberseguridad as catalogo


RAIZ = Path(__file__).resolve().parent
SCRIPT = RAIZ / "catalogo_ciberseguridad.py"


class CatalogoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.entradas = catalogo.cargar_catalogo()

    def test_el_catalogo_es_valido(self) -> None:
        self.assertEqual([], catalogo.validar_catalogo(self.entradas))

    def test_incluye_normativa_operativa_para_red_y_blue_team(self) -> None:
        self.assertGreaterEqual(len(self.entradas), 90)
        roles = {rol for entrada in self.entradas for rol in entrada.roles}
        self.assertTrue({"red-team", "blue-team", "purple-team"}.issubset(roles))

    def test_cubre_chile_latam_y_banca(self) -> None:
        Chile = [e for e in self.entradas if e.jurisdiccion == "Chile"]
        latam = [e for e in self.entradas if e.region == "América Latina"]
        banca = [e for e in self.entradas if e.sector == "Banca y seguros"]

        self.assertGreaterEqual(len(Chile), 10)
        self.assertGreaterEqual(len(latam), 20)
        self.assertGreaterEqual(len(banca), 12)
        self.assertGreaterEqual(
            len({e.jurisdiccion for e in latam if e.jurisdiccion != "Internacional"}),
            8,
        )

    def test_corte_de_actualizacion_explicito(self) -> None:
        self.assertEqual(date(2026, 9, 25), catalogo.REVISION_FECHA)
        for entrada in self.entradas:
            for campo in (entrada.publicada, entrada.promulgada, entrada.actualizada):
                if campo:
                    self.assertLessEqual(campo, date(2026, 9, 25))
            if entrada.estado == "Próxima a entrar en vigor":
                self.assertIsNotNone(entrada.vigente_desde)
                self.assertGreater(entrada.vigente_desde, date(2026, 9, 25))

    def test_transicion_de_proteccion_de_datos_en_chile(self) -> None:
        nueva = self._por_id("CL-PRV-001")
        anterior = self._por_id("CL-PRV-002")

        self.assertEqual("Ley 21.719", nueva.acronimo)
        self.assertEqual(date(2026, 12, 1), nueva.vigente_desde)
        self.assertEqual("Próxima a entrar en vigor", nueva.estado)
        self.assertEqual(date(2026, 11, 30), anterior.vigente_hasta)
        self.assertEqual("Vigente con transición declarada", anterior.estado)

    def test_corrige_norma_chilena_derogada(self) -> None:
        vigente = self._por_id("CL-REG-002")
        derogada = self._por_id("CL-REG-001")

        self.assertEqual("Ley 21.459", vigente.acronimo)
        self.assertEqual("Ley 19.223", derogada.acronimo)
        self.assertEqual("Derogada", derogada.estado)
        self.assertTrue(derogada.actualizada)

    def test_incluye_versiones_actuales_de_referencia_red_blue(self) -> None:
        esperadas = {
            "CSF 2.0",
            "NIST SP 800-53 Rev. 5.2.0",
            "NIST SP 800-61 Rev. 3",
            "MITRE ATT&CK",
            "OWASP ASVS 5.0.0",
            "CIS Controls v8.1",
            "PCI DSS v4.0.1",
        }
        acronimos = {entrada.acronimo for entrada in self.entradas}
        self.assertTrue(esperadas.issubset(acronimos), esperadas - acronimos)

    def test_buscar_ignora_mayusculas_y_acentos(self) -> None:
        resultados = catalogo.buscar_entradas(self.entradas, "gestión de RIESGOS")
        self.assertTrue(resultados)
        self.assertIn("Chile", {e.jurisdiccion for e in resultados})

    def test_filtros_por_rol_sector_y_pais(self) -> None:
        resultados = catalogo.filtrar_entradas(
            self.entradas,
            pais="Chile",
            sector="Banca y seguros",
            rol="blue-team",
        )
        self.assertTrue(resultados)
        for entrada in resultados:
            self.assertEqual("Chile", entrada.jurisdiccion)
            self.assertEqual("Banca y seguros", entrada.sector)
            self.assertIn("blue-team", entrada.roles)

    def test_validacion_detecta_errores(self) -> None:
        invalida = self.entradas[0]
        copia = invalida.__class__(**{**invalida.__dict__, "id": "ID DUPLICADO"})
        entrada_buena = invalida.__class__(**invalida.__dict__)
        errores = catalogo.validar_catalogo([entrada_buena, copia, entrada_buena])
        self.assertTrue(any("id" in error.lower() for error in errores))
        self.assertTrue(any("fecha" in error.lower() for error in catalogo.validar_datos_fecha("31-02-2026")))

    def test_exportacion_json_incluye_metadatos(self) -> None:
        salida = io.StringIO()
        catalogo.exportar_json(self.entradas[:2], salida)
        documento = json.loads(salida.getvalue())
        self.assertEqual("2026-09-25", documento["metadatos"]["fecha_revision"])
        self.assertEqual(2, len(documento["entradas"]))

    def test_exportacion_csv_usa_utf8_para_excel(self) -> None:
        salida = io.StringIO()
        catalogo.exportar_csv(self.entradas[:2], salida)
        filas = list(csv.DictReader(io.StringIO(salida.getvalue())))
        self.assertEqual(2, len(filas))
        self.assertEqual(self.entradas[0].id, filas[0]["id"])
        self.assertIn("roles", filas[0])

    def test_cli_buscar_falla_cuando_no_encuentra(self) -> None:
        proceso = subprocess.run(
            [sys.executable, str(SCRIPT), "buscar", "texto-imposible-xyz"],
            cwd=RAIZ,
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False,
        )
        self.assertEqual(2, proceso.returncode)
        self.assertIn("No se encontraron", proceso.stdout + proceso.stderr)

    def test_cli_exporta_sin_dependencias(self) -> None:
        with tempfile.TemporaryDirectory() as temporal:
            salida = Path(temporal) / "catalogo.json"
            proceso = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "exportar",
                    "--formato",
                    "json",
                    "--salida",
                    str(salida),
                ],
                cwd=RAIZ,
                capture_output=True,
                text=True,
                encoding="utf-8",
                check=False,
            )
            self.assertEqual(0, proceso.returncode, proceso.stdout + proceso.stderr)
            documento = json.loads(salida.read_text(encoding="utf-8"))
            self.assertEqual(catalogo.REVISION_FECHA.isoformat(), documento["metadatos"]["fecha_revision"])

    def _por_id(self, identificador: str) -> catalogo.Entrada:
        return next(entrada for entrada in self.entradas if entrada.id == identificador)


if __name__ == "__main__":
    unittest.main()
