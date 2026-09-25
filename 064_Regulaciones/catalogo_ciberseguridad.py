#!/usr/bin/env python3
"""Catálogo interactivo de ciberseguridad con corte al 25 de septiembre de 2026.

La herramienta no requiere dependencias externas. Los datos se cargan desde
``datos_catalogo.json`` y todas las afirmaciones normative deben contrastarse
con la fuente oficial antes de tomar decisiones legales o de cumplimiento.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import re
import shutil
import sys
import unicodedata
from collections import Counter
from dataclasses import dataclass, fields
from datetime import date
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, TextIO, Tuple
from urllib.parse import urlparse


REVISION_FECHA = date(2026, 9, 25)
ARCHIVO_DATOS = Path(__file__).with_name("datos_catalogo.json")
VERSION = "3.0.0"

CATEGORIAS = {
    "Ley y regulación",
    "Estándar",
    "Marco",
    "Metodología",
    "Guía",
    "Evaluación",
    "Base de conocimiento",
}
OBLIGACIONES = {
    "Obligatoria",
    "Obligatoria por sector",
    "Condicional",
    "Contractual",
    "Voluntaria",
    "Referencia técnica",
    "Derogada",
    "Retirada",
}
ESTADOS = {
    "Vigente",
    "Vigente con transición declarada",
    "Próxima a entrar en vigor",
    "Derogada",
    "Retirada",
}
ESTADOS_NO_VIGENTES = {"Derogada", "Retirada"}
ROLES = {
    "red-team",
    "blue-team",
    "purple-team",
    "dfir",
    "threat-intel",
    "appsec",
    "cloud",
    "identity",
    "governance",
    "architecture",
    "detection-engineering",
    "incident-response",
    "vulnerability-management",
    "data-protection",
}
ALIASES_ROLES = {
    "red": "red-team",
    "redteam": "red-team",
    "rojo": "red-team",
    "blue": "blue-team",
    "blueteam": "blue-team",
    "azul": "blue-team",
    "purple": "purple-team",
    "purpleteam": "purple-team",
    "forense": "dfir",
    "inteligencia": "threat-intel",
    "grc": "governance",
}
ALIASES_PAISES = {
    "chile": "chile",
    "colombia": "colombia",
    "brasil": "brasil",
    "brazil": "brasil",
    "argentina": "argentina",
    "mexico": "mexico",
    "méxico": "mexico",
    "peru": "perú",
    "perú": "perú",
    "ecuador": "ecuador",
    "uruguay": "uruguay",
    "paraguay": "paraguay",
    "bolivia": "bolivia",
    "costa rica": "costa rica",
    "panama": "panamá",
    "panamá": "panamá",
    "republica dominicana": "república dominicana",
    "república dominicana": "república dominicana",
    "el salvador": "el salvador",
    "guatemala": "guatemala",
    "honduras": "honduras",
    "nicaragua": "nicaragua",
    "estados unidos": "estados unidos",
    "eeuu": "estados unidos",
    "ee.uu.": "estados unidos",
    "canada": "canadá",
    "canadá": "canadá",
    "australia": "australia",
    "reino unido": "reino unido",
    "ue": "unión europea",
    "union europea": "unión europea",
    "unión europea": "unión europea",
    "internacional": "internacional",
    "global": "internacional",
}
ORDEN_REGION = {
    "Chile": 0,
    "América Latina": 1,
    "Europa": 2,
    "Norteamérica": 3,
    "Oceanía": 4,
    "Global": 5,
}
CATEGORIA_COLOR = {
    "Ley y regulación": "35",
    "Estándar": "36",
    "Marco": "34",
    "Metodología": "33",
    "Guía": "32",
    "Evaluación": "33",
    "Base de conocimiento": "36",
}
MAPA_EQUIPOS = {
    "Red Team": (
        "PTES",
        "OSSTMM 3",
        "MITRE ATT&CK",
        "NIST SP 800-115",
        "OWASP WSTG",
        "TIBER-EU",
    ),
    "Blue Team": (
        "MITRE ATT&CK",
        "MITRE D3FEND",
        "CSF 2.0",
        "NIST SP 800-53 Rev. 5.2.0",
        "NIST SP 800-61 Rev. 3",
        "CIS Controls v8.1",
    ),
    "Purple Team": (
        "MITRE ATT&CK",
        "MITRE D3FEND",
        "CSF 2.0",
        "CIS Controls v8.1",
        "OWASP ASVS 5.0.0",
    ),
    "DFIR": (
        "NIST SP 800-61 Rev. 3",
        "NIST SP 800-86",
        "FIRST CSIRT Services Framework v2.0",
        "MITRE ATT&CK",
    ),
}

DISCLAIMER = (
    "Corte documental: 25-09-2026. Este catálogo es una guía técnica y no "
    "asesoramiento legal. Verifique la vigencia, el alcance territorial, las "
    "excepciones y el texto oficial aplicable a cada organización."
)


class CatalogError(ValueError):
    """Error de estructura o contenido del catálogo."""


@dataclass(frozen=True)
class Entrada:
    id: str
    acronimo: str
    nombre: str
    jurisdiccion: str
    region: str
    categoria: str
    instrumento: str
    sector: str
    obligatoriedad: str
    estado: str
    autoridad: str
    resumen: str
    alcance: str
    url: str
    roles: Tuple[str, ...] = ()
    tags: Tuple[str, ...] = ()
    version: str = ""
    publicada: Optional[date] = None
    promulgada: Optional[date] = None
    vigente_desde: Optional[date] = None
    vigente_hasta: Optional[date] = None
    actualizada: Optional[date] = None
    uso_red_team: str = ""
    uso_blue_team: str = ""
    uso_purple_team: str = ""
    advertencia: str = ""

    @classmethod
    def desde_datos(cls, datos: Mapping[str, Any]) -> "Entrada":
        campos = {campo.name for campo in fields(cls)}
        desconocidos = sorted(set(datos) - campos)
        if desconocidos:
            raise CatalogError(
                "Campos desconocidos en {0}: {1}".format(
                    datos.get("id", "<sin id>"), ", ".join(desconocidos)
                )
            )

        requeridos = {
            "id",
            "acronimo",
            "nombre",
            "jurisdiccion",
            "region",
            "categoria",
            "instrumento",
            "sector",
            "obligatoriedad",
            "estado",
            "autoridad",
            "resumen",
            "alcance",
            "url",
        }
        faltantes = sorted(requeridos - set(datos))
        if faltantes:
            raise CatalogError(
                "Faltan campos en {0}: {1}".format(
                    datos.get("id", "<sin id>"), ", ".join(faltantes)
                )
            )

        valores: Dict[str, Any] = dict(datos)
        for nombre in ("roles", "tags"):
            valores[nombre] = tuple(valores.get(nombre) or ())
        for nombre in (
            "publicada",
            "promulgada",
            "vigente_desde",
            "vigente_hasta",
            "actualizada",
        ):
            valores[nombre] = _parsear_fecha(
                valores.get(nombre), nombre, str(datos.get("id", "<sin id>"))
            )
        return cls(**valores)

    def a_dict(self) -> Dict[str, Any]:
        resultado: Dict[str, Any] = {}
        for campo in fields(self):
            valor = getattr(self, campo.name)
            if isinstance(valor, date):
                valor = valor.isoformat()
            elif isinstance(valor, tuple):
                valor = list(valor)
            resultado[campo.name] = valor
        return resultado


def _parsear_fecha(
    valor: Any, campo: str, identificador: str
) -> Optional[date]:
    if valor in (None, ""):
        return None
    if isinstance(valor, date):
        return valor
    try:
        return date.fromisoformat(str(valor))
    except ValueError as exc:
        raise CatalogError(
            "Fecha inválida en {0}.{1}: {2!r}; se espera AAAA-MM-DD".format(
                identificador, campo, valor
            )
        ) from exc


def validar_datos_fecha(valor: Any) -> List[str]:
    """Devuelve errores para una fecha; nunca lanza ``ValueError``."""
    try:
        _parsear_fecha(valor, "fecha", "validación")
    except CatalogError as exc:
        return [str(exc)]
    return []


def _url_valida(url: str) -> bool:
    try:
        partes = urlparse(url)
    except ValueError:
        return False
    return partes.scheme in {"http", "https"} and bool(partes.netloc)


def validar_catalogo(entradas: Sequence[Entrada]) -> List[str]:
    """Valida enumeraciones, identificadores, fechas, URLs y duplicados."""
    errores: List[str] = []
    identificadores: set[str] = set()

    for indice, entrada in enumerate(entradas, start=1):
        prefijo = entrada.id or "entrada #{0}".format(indice)
        if not re.fullmatch(r"[A-Z0-9]+(?:-[A-Z0-9]+)+", entrada.id):
            errores.append("{0}: id inválido".format(prefijo))
        if entrada.id in identificadores:
            errores.append("{0}: id duplicado".format(prefijo))
        identificadores.add(entrada.id)

        for campo in (
            "acronimo",
            "nombre",
            "jurisdiccion",
            "instrumento",
            "sector",
            "autoridad",
            "resumen",
            "alcance",
            "url",
        ):
            if not getattr(entrada, campo).strip():
                errores.append("{0}: {1} no puede estar vacío".format(prefijo, campo))
        if entrada.categoria not in CATEGORIAS:
            errores.append("{0}: categoría desconocida {1!r}".format(prefijo, entrada.categoria))
        if entrada.obligatoriedad not in OBLIGACIONES:
            errores.append(
                "{0}: obligatoriedad desconocida {1!r}".format(
                    prefijo, entrada.obligatoriedad
                )
            )
        if entrada.estado not in ESTADOS:
            errores.append("{0}: estado desconocido {1!r}".format(prefijo, entrada.estado))
        if not _url_valida(entrada.url):
            errores.append("{0}: URL oficial inválida".format(prefijo))
        roles_desconocidos = sorted(set(entrada.roles) - ROLES)
        if roles_desconocidos:
            errores.append(
                "{0}: roles desconocidos {1}".format(
                    prefijo, ", ".join(roles_desconocidos)
                )
            )
        if not entrada.roles:
            errores.append("{0}: debe declarar al menos un rol".format(prefijo))
        if (
            entrada.vigente_desde
            and entrada.vigente_hasta
            and entrada.vigente_hasta < entrada.vigente_desde
        ):
            errores.append("{0}: el período de vigencia es inválido".format(prefijo))
        if entrada.estado == "Próxima a entrar en vigor":
            if entrada.vigente_desde is None:
                errores.append(
                    "{0}: una entrada futura debe indicar 'vigente_desde'".format(prefijo)
                )
            elif REVISION_FECHA >= entrada.vigente_desde:
                errores.append(
                    "{0}: estado futuro incompatible con la fecha de corte".format(
                        prefijo
                    )
                )
        if entrada.estado in ESTADOS_NO_VIGENTES and entrada.obligatoriedad not in {
            "Derogada",
            "Retirada",
        }:
            errores.append(
                "{0}: una entrada no vigente debe marcarse como derogada o retirada".format(
                    prefijo
                )
            )

    return errores


def cargar_catalogo(ruta: Optional[Path] = None) -> List[Entrada]:
    """Carga, convierte y valida el catálogo desde un archivo JSON."""
    ruta = Path(ruta) if ruta is not None else ARCHIVO_DATOS
    try:
        documento = json.loads(ruta.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise CatalogError("No existe el archivo de datos: {0}".format(ruta)) from exc
    except json.JSONDecodeError as exc:
        raise CatalogError(
            "JSON inválido en {0}, línea {1}, columna {2}: {3}".format(
                ruta, exc.lineno, exc.colno, exc.msg
            )
        ) from exc
    except OSError as exc:
        raise CatalogError("No se pudo leer {0}: {1}".format(ruta, exc)) from exc

    if not isinstance(documento, dict) or not isinstance(documento.get("entradas"), list):
        raise CatalogError("El documento debe contener una lista 'entradas'")
    entradas: List[Entrada] = []
    for indice, dato in enumerate(documento["entradas"], start=1):
        if not isinstance(dato, dict):
            raise CatalogError("La entrada #{0} no es un objeto".format(indice))
        entradas.append(Entrada.desde_datos(dato))
    errores = validar_catalogo(entradas)
    if errores:
        raise CatalogError(
            "El catálogo contiene {0} error(es):\n- {1}".format(
                len(errores), "\n- ".join(errores)
            )
        )
    return entradas


def _normalizar(texto: str) -> str:
    descompuesto = unicodedata.normalize("NFKD", texto.casefold())
    sin_acentos = "".join(c for c in descompuesto if not unicodedata.combining(c))
    return " ".join(re.findall(r"[a-z0-9]+", sin_acentos))


def _texto_busqueda(entrada: Entrada) -> str:
    campos = (
        entrada.id,
        entrada.acronimo,
        entrada.nombre,
        entrada.jurisdiccion,
        entrada.region,
        entrada.categoria,
        entrada.instrumento,
        entrada.sector,
        entrada.estado,
        entrada.obligatoriedad,
        entrada.autoridad,
        entrada.resumen,
        entrada.alcance,
        entrada.uso_red_team,
        entrada.uso_blue_team,
        entrada.uso_purple_team,
        entrada.advertencia,
        " ".join(entrada.roles),
        " ".join(entrada.tags),
    )
    return _normalizar(" ".join(campos))


def buscar_entradas(entradas: Sequence[Entrada], consulta: str) -> List[Entrada]:
    """Busca todos los términos en el contenido indexado de cada entrada."""
    terminos = _normalizar(consulta).split()
    if not terminos:
        return list(entradas)
    return [
        entrada
        for entrada in entradas
        if all(termino in _texto_busqueda(entrada) for termino in terminos)
    ]


def _compacto(texto: str) -> str:
    """Normaliza y elimina espacios para comparar roles y países."""
    return _normalizar(texto).replace(" ", "")


_ALIASES_ROLES_COMPACTOS = {
    _compacto(clave): _compacto(valor) for clave, valor in ALIASES_ROLES.items()
}
_ALIASES_PAISES_COMPACTOS = {
    _compacto(clave): _compacto(valor) for clave, valor in ALIASES_PAISES.items()
}


def _normalizar_rol(rol: Optional[str]) -> Optional[str]:
    if rol is None:
        return None
    clave = _compacto(rol)
    return _ALIASES_ROLES_COMPACTOS.get(clave, clave)


def _normalizar_pais(pais: Optional[str]) -> Optional[str]:
    if pais is None:
        return None
    clave = _compacto(pais)
    return _ALIASES_PAISES_COMPACTOS.get(clave, clave)


def _control_coincide(valor: str, filtro: Optional[str]) -> bool:
    """Coincidencia exacta o por prefijo para filtros de texto."""
    if not filtro:
        return True
    valor_normalizado = _normalizar(valor)
    filtro_normalizado = _normalizar(filtro)
    return valor_normalizado == filtro_normalizado or valor_normalizado.startswith(
        filtro_normalizado
    )


def filtrar_entradas(
    entradas: Sequence[Entrada],
    consulta: str = "",
    pais: Optional[str] = None,
    region: Optional[str] = None,
    categoria: Optional[str] = None,
    sector: Optional[str] = None,
    rol: Optional[str] = None,
    estado: Optional[str] = None,
    obligatoriedad: Optional[str] = None,
    incluir_historicos: bool = False,
) -> List[Entrada]:
    """Aplica búsqueda y filtros combinables; excluye históricos por defecto."""
    resultados = buscar_entradas(entradas, consulta)
    pais_normalizado = _normalizar_pais(pais)
    rol_normalizado = _normalizar_rol(rol)

    filtradas: List[Entrada] = []
    for entrada in resultados:
        if not incluir_historicos and estado is None and entrada.estado in ESTADOS_NO_VIGENTES:
            continue
        if pais_normalizado and _compacto(entrada.jurisdiccion) != pais_normalizado:
            continue
        if not _control_coincide(entrada.region, region):
            continue
        if not _control_coincide(entrada.categoria, categoria):
            continue
        if not _control_coincide(entrada.sector, sector):
            continue
        if rol_normalizado and rol_normalizado not in {
            _compacto(rol) for rol in entrada.roles
        }:
            continue
        if not _control_coincide(entrada.estado, estado):
            continue
        if not _control_coincide(entrada.obligatoriedad, obligatoriedad):
            continue
        filtradas.append(entrada)

    return sorted(
        filtradas,
        key=lambda e: (
            ORDEN_REGION.get(e.region, 99),
            e.jurisdiccion,
            e.nombre.casefold(),
        ),
    )


def encontrar_entradas(entradas: Sequence[Entrada], referencia: str) -> List[Entrada]:
    """Resuelve un ID o acrónimo exacto y, si no existe, por coincidencia parcial."""
    clave = _normalizar(referencia)
    exactas = [
        entrada
        for entrada in entradas
        if _normalizar(entrada.id) == clave or _normalizar(entrada.acronimo) == clave
    ]
    if exactas:
        return exactas
    return [
        entrada
        for entrada in entradas
        if clave and clave in _normalizar(" ".join((entrada.id, entrada.acronimo)))
    ]


def obtener_datos_regulaciones_final() -> List[Dict[str, Any]]:
    """Compatibilidad con la API del catálogo anterior.

    Devuelve una lista de diccionarios; el texto no se imprime al importar.
    """
    return [entrada.a_dict() for entrada in cargar_catalogo()]


def _activar_color_windows() -> None:
    if os.name != "nt" or not hasattr(sys.stdout, "buffer"):
        return
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        modo = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(sys.stdout.buffer.fileno(), ctypes.byref(modo)):
            return
        kernel32.SetConsoleMode(
            sys.stdout.buffer.fileno(), modo.value | 0x0004  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
        )
    except (AttributeError, OSError):
        return


def _quiere_color(opcion: str, stream: TextIO) -> bool:
    if os.environ.get("NO_COLOR") is not None:
        return False
    if opcion == "never":
        return False
    if opcion == "always":
        return True
    if not hasattr(stream, "isatty") or not stream.isatty():
        return False
    _activar_color_windows()
    return os.environ.get("TERM") != "dumb"


def _pintar(texto: str, codigo: str, habilitado: bool) -> str:
    return "\033[{0}m{1}\033[0m".format(codigo, texto) if habilitado else texto


def _ancho(stream: TextIO) -> int:
    return max(72, min(shutil.get_terminal_size((100, 24)).columns, 118))


def _envolver(texto: str, ancho: int, sangria: str = "") -> str:
    if not texto:
        return ""
    lineas: List[str] = []
    for parrafo in texto.splitlines() or [""]:
        from textwrap import fill

        lineas.append(
            fill(
                parrafo,
                width=ancho,
                initial_indent=sangria,
                subsequent_indent=sangria,
                break_long_words=False,
                break_on_hyphens=False,
            )
        )
    return "\n".join(lineas)


def _fecha(valor: Optional[date]) -> str:
    return valor.isoformat() if valor else "No consignada"


def _imprimir_preambulo(salida: TextIO) -> None:
    print("Catálogo de ciberseguridad — Red, Blue y Purple Team", file=salida)
    print(DISCLAIMER, file=salida)
    print("=" * min(_ancho(salida), 100), file=salida)


def imprimir_tabla(
    entradas: Optional[Sequence[Entrada]] = None,
    salida: Optional[TextIO] = None,
    detalle: bool = False,
    color: str = "auto",
) -> None:
    """Imprime una lista sin escapes Markdown literales.

    También conserva el nombre histórico ``imprimir_tabla`` de la versión 2.1.
    """
    salida = salida or sys.stdout
    entradas = list(entradas) if entradas is not None else cargar_catalogo()
    if not entradas:
        print("No se encontraron entradas.", file=salida)
        return
    usar_color = _quiere_color(color, salida)
    ancho = _ancho(salida)
    _imprimir_preambulo(salida)
    print("", file=salida)
    for entrada in entradas:
        categoria = _pintar(entrada.categoria, CATEGORIA_COLOR.get(entrada.categoria, "0"), usar_color)
        print(
            "[{0}] {1} — {2}".format(entrada.id, entrada.acronimo, entrada.nombre),
            file=salida,
        )
        print(
            "    {0} | {1} | {2} | {3} | Publicación: {4}".format(
                entrada.jurisdiccion,
                entrada.sector,
                categoria,
                entrada.estado,
                _fecha(entrada.publicada),
            ),
            file=salida,
        )
        if detalle:
            print(_envolver(entrada.resumen, ancho, "    "), file=salida)
            if entrada.uso_red_team:
                print(_envolver("Red Team: " + entrada.uso_red_team, ancho, "    "), file=salida)
            if entrada.uso_blue_team:
                print(_envolver("Blue Team: " + entrada.uso_blue_team, ancho, "    "), file=salida)
            if entrada.uso_purple_team:
                print(_envolver("Purple Team: " + entrada.uso_purple_team, ancho, "    "), file=salida)
        print("", file=salida)
    print("Mostradas {0} entrada(s).".format(len(entradas)), file=salida)


def imprimir_entrada(entrada: Entrada, salida: Optional[TextIO] = None, color: str = "auto") -> None:
    salida = salida or sys.stdout
    usar_color = _quiere_color(color, salida)
    ancho = _ancho(salida)
    _imprimir_preambulo(salida)
    print("", file=salida)
    print("{0} — {1}".format(entrada.acronimo, entrada.nombre), file=salida)
    print("ID: {0}".format(entrada.id), file=salida)
    print("Clasificación: {0} / {1}".format(entrada.categoria, entrada.instrumento), file=salida)
    print("Autoridad: {0}".format(entrada.autoridad), file=salida)
    print(
        "Jurisdicción / sector: {0} / {1}".format(entrada.jurisdiccion, entrada.sector),
        file=salida,
    )
    print("Región: {0}".format(entrada.region), file=salida)
    print("Obligatoriedad: {0}".format(entrada.obligatoriedad), file=salida)
    print("Estado al corte: {0}".format(entrada.estado), file=salida)
    if entrada.version:
        print("Versión: {0}".format(entrada.version), file=salida)
    print("Promulgada: {0}".format(_fecha(entrada.promulgada)), file=salida)
    print("Publicada: {0}".format(_fecha(entrada.publicada)), file=salida)
    print("Vigente desde: {0}".format(_fecha(entrada.vigente_desde)), file=salida)
    print("Vigente hasta: {0}".format(_fecha(entrada.vigente_hasta)), file=salida)
    print("Última actualización consignada: {0}".format(_fecha(entrada.actualizada)), file=salida)
    print("Roles: {0}".format(", ".join(entrada.roles)), file=salida)
    print("", file=salida)
    print("Resumen", file=salida)
    print(_envolver(entrada.resumen, ancho, "  "), file=salida)
    print("", file=salida)
    print("Alcance y aplicación", file=salida)
    print(_envolver(entrada.alcance, ancho, "  "), file=salida)
    for etiqueta, contenido in (
        ("Uso Red Team", entrada.uso_red_team),
        ("Uso Blue Team", entrada.uso_blue_team),
        ("Uso Purple Team", entrada.uso_purple_team),
    ):
        if contenido:
            print("", file=salida)
            print(etiqueta, file=salida)
            print(_envolver(contenido, ancho, "  "), file=salida)
    if entrada.advertencia:
        print("", file=salida)
        print(_pintar("Advertencia", "33", usar_color), file=salida)
        print(_envolver(entrada.advertencia, ancho, "  "), file=salida)
    if entrada.tags:
        print("", file=salida)
        print("Etiquetas: {0}".format(", ".join(entrada.tags)), file=salida)
    print("", file=salida)
    print("Fuente oficial: {0}".format(entrada.url), file=salida)


def imprimir_resumen(
    entradas: Sequence[Entrada], salida: Optional[TextIO] = None, color: str = "auto"
) -> None:
    salida = salida or sys.stdout
    usar_color = _quiere_color(color, salida)
    activos = [entrada for entrada in entradas if entrada.estado not in ESTADOS_NO_VIGENTES]
    futuros = [entrada for entrada in entradas if entrada.estado == "Próxima a entrar en vigor"]
    bancos = [entrada for entrada in activos if entrada.sector == "Banca y seguros"]
    chile = [entrada for entrada in activos if entrada.jurisdiccion == "Chile"]
    latam = [entrada for entrada in activos if entrada.region == "América Latina"]

    _imprimir_preambulo(salida)
    print("", file=salida)
    print("Total: {0} | Vigentes o futuros: {1} | Históricos: {2}".format(
        len(entradas), len(activos), len(entradas) - len(activos)
    ), file=salida)
    print("Chile: {0} | América Latina: {1} | Banca y seguros: {2}".format(
        len(chile), len(latam), len(bancos)
    ), file=salida)
    print("Próximas a entrar en vigor: {0}".format(len(futuros)), file=salida)
    print("", file=salida)

    for titulo, atributo in (
        ("Por región", "region"),
        ("Por categoría", "categoria"),
        ("Por estado", "estado"),
    ):
        print(titulo, file=salida)
        conteo = Counter(getattr(entrada, atributo) for entrada in activos)
        for valor, cantidad in conteo.most_common():
            print("  {0:<28} {1:>3}".format(valor, cantidad), file=salida)
        print("", file=salida)

    print("Operativa rápida", file=salida)
    print("  Red Team:  python catalogo_ciberseguridad.py banca --rol red-team", file=salida)
    print("  Blue Team: python catalogo_ciberseguridad.py banca --rol blue-team", file=salida)
    print("  Búsqueda:  python catalogo_ciberseguridad.py buscar incidentes --region 'América Latina'", file=salida)
    print("  Detalle:   python catalogo_ciberseguridad.py ver CL-PRV-001", file=salida)
    print(_pintar("\nAviso: " + DISCLAIMER, "33", usar_color), file=salida)


def imprimir_paises(
    entradas: Sequence[Entrada], salida: Optional[TextIO] = None
) -> None:
    salida = salida or sys.stdout
    visibles = [entrada for entrada in entradas if entrada.estado not in ESTADOS_NO_VIGENTES]
    conteo = Counter(entrada.jurisdiccion for entrada in visibles)
    print("Jurisdicciones y número de entradas vigentes:", file=salida)
    for jurisdiccion, cantidad in sorted(conteo.items()):
        print("  {0:<28} {1:>3}".format(jurisdiccion, cantidad), file=salida)


def imprimir_roles(
    entradas: Sequence[Entrada], salida: Optional[TextIO] = None
) -> None:
    salida = salida or sys.stdout
    visibles = [entrada for entrada in entradas if entrada.estado not in ESTADOS_NO_VIGENTES]
    conteo = Counter(rol for entrada in visibles for rol in set(entrada.roles))
    print("Cobertura por rol (una entrada puede aparecer en varios):", file=salida)
    for rol, cantidad in conteo.most_common():
        print("  {0:<28} {1:>3}".format(rol, cantidad), file=salida)


def imprimir_mapa_equipos(
    entradas: Sequence[Entrada], salida: Optional[TextIO] = None, color: str = "auto"
) -> None:
    salida = salida or sys.stdout
    usar_color = _quiere_color(color, salida)
    print("Mapa de referencia para equipos ofensivos, defensivos y híbridos", file=salida)
    print("=" * 72, file=salida)
    for equipo, acronimos in MAPA_EQUIPOS.items():
        print("", file=salida)
        print(_pintar(equipo, "36", usar_color), file=salida)
        for acronimo in acronimos:
            coincidencias = encontrar_entradas(entradas, acronimo)
            if not coincidencias:
                print("  [?] {0} (referencia no cargada)".format(acronimo), file=salida)
                continue
            for entrada in coincidencias:
                print("  [{0}] {1} — {2}".format(entrada.id, entrada.acronimo, entrada.nombre), file=salida)
    print("", file=salida)
    print("Orden práctico: autorización y alcance → línea base → ejecución → detección → respuesta → aprendizaje.", file=salida)


CSV_COLUMNAS = (
    "id",
    "acronimo",
    "nombre",
    "jurisdiccion",
    "region",
    "categoria",
    "instrumento",
    "sector",
    "obligatoriedad",
    "estado",
    "autoridad",
    "version",
    "publicada",
    "promulgada",
    "vigente_desde",
    "vigente_hasta",
    "actualizada",
    "resumen",
    "alcance",
    "roles",
    "tags",
    "uso_red_team",
    "uso_blue_team",
    "uso_purple_team",
    "advertencia",
    "url",
)


def _valor_csv(valor: Any) -> str:
    if isinstance(valor, (list, tuple)):
        texto = "; ".join(str(item) for item in valor)
    elif valor is None:
        texto = ""
    else:
        texto = str(valor)
    if texto[:1] in {"=", "+", "-", "@", "\t", "\r"}:
        return "'" + texto
    return texto


def exportar_json(
    entradas: Sequence[Entrada], salida: TextIO, ruta_origen: Optional[Path] = None
) -> None:
    documento = {
        "metadatos": {
            "titulo": "Catálogo de ciberseguridad — Red, Blue y Purple Team",
            "version": VERSION,
            "fecha_revision": REVISION_FECHA.isoformat(),
            "total_entradas": len(entradas),
            "fuente_datos": str(ruta_origen) if ruta_origen else str(ARCHIVO_DATOS),
            "advertencia": DISCLAIMER,
        },
        "entradas": [entrada.a_dict() for entrada in entradas],
    }
    json.dump(documento, salida, ensure_ascii=False, indent=2)
    salida.write("\n")


def exportar_csv(entradas: Sequence[Entrada], salida: TextIO) -> None:
    escritor = csv.DictWriter(salida, fieldnames=CSV_COLUMNAS, lineterminator="\n")
    escritor.writeheader()
    for entrada in entradas:
        datos = entrada.a_dict()
        fila = {columna: _valor_csv(datos.get(columna)) for columna in CSV_COLUMNAS}
        escritor.writerow(fila)


def _render_exportacion(entradas: Sequence[Entrada], formato: str) -> str:
    salida = io.StringIO(newline="")
    if formato == "json":
        exportar_json(entradas, salida)
    else:
        exportar_csv(entradas, salida)
    return salida.getvalue()


def _filtros_desde_argumentos(args: argparse.Namespace) -> Dict[str, Any]:
    return {
        "consulta": " ".join(getattr(args, "consulta", []) or []),
        "pais": getattr(args, "pais", None),
        "region": getattr(args, "region", None),
        "categoria": getattr(args, "categoria", None),
        "sector": getattr(args, "sector", None),
        "rol": getattr(args, "rol", None),
        "estado": getattr(args, "estado", None),
        "obligatoriedad": getattr(args, "obligatoriedad", None),
        "incluir_historicos": getattr(args, "incluir_historicos", False),
    }


def _agregar_filtros(parser: argparse.ArgumentParser) -> None:
    grupo = parser.add_argument_group("filtros")
    grupo.add_argument("--pais", "--país", help="Chile, Colombia, Brasil, México, etc.")
    grupo.add_argument("--region", help="América Latina, Europa, Norteamérica, Oceanía o Global")
    grupo.add_argument("--categoria", help="Ley y regulación, Estándar, Marco, etc.")
    grupo.add_argument("--sector", help="Banca y seguros, Privacidad, Pagos, etc.")
    grupo.add_argument(
        "--rol",
        help="red-team, blue-team, purple-team, dfir, appsec, cloud, etc.",
    )
    grupo.add_argument("--estado", help="Vigente, Próxima, Derogada o Retirada")
    grupo.add_argument("--obligatoriedad", help="Obligatoria, Contractual, Referencia técnica, etc.")
    grupo.add_argument(
        "--incluir-historicos",
        action="store_true",
        help="Incluye leyes derogadas y normas retiradas",
    )
    grupo.add_argument(
        "--color",
        choices=("auto", "always", "never"),
        default="auto",
        help="Controla el color ANSI (auto por defecto)",
    )


def construir_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="catalogo_ciberseguridad.py",
        description=(
            "Consulta normativa, estándares y marcos de ciberseguridad con corte "
            "al 25-09-2026. Sin dependencias externas."
        ),
        epilog="Ejecute 'python catalogo_ciberseguridad.py --help' para ver los comandos.",
    )
    parser.add_argument("--version", action="version", version="%(prog)s " + VERSION)
    subparsers = parser.add_subparsers(dest="comando", metavar="COMANDO")

    listar = subparsers.add_parser(
        "listar", aliases=["list"], help="Lista entradas, opcionalmente filtradas"
    )
    listar.add_argument("consulta", nargs="*", help="Palabras para búsqueda")
    _agregar_filtros(listar)
    listar.add_argument("--detalle", action="store_true", help="Muestra usos Red/Blue/Purple")
    listar.set_defaults(_salida="listar")

    buscar = subparsers.add_parser(
        "buscar", aliases=["search"], help="Busca por texto en todo el catálogo"
    )
    buscar.add_argument("consulta", nargs="+", help="Palabras para búsqueda")
    _agregar_filtros(buscar)
    buscar.add_argument("--detalle", action="store_true", help="Muestra usos Red/Blue/Purple")
    buscar.set_defaults(_salida="buscar")

    banca = subparsers.add_parser(
        "banca", aliases=["bancos"], help="Muestra referencias de banca y seguros"
    )
    banca.add_argument("consulta", nargs="*", help="Palabras adicionales")
    _agregar_filtros(banca)
    banca.add_argument("--detalle", action="store_true", help="Muestra usos Red/Blue/Purple")
    banca.set_defaults(_salida="listar", sector="Banca y seguros")

    ver = subparsers.add_parser(
        "ver", aliases=["show"], help="Muestra el detalle de un ID o acrónimo"
    )
    ver.add_argument("referencia", help="ID o acrónimo, por ejemplo CL-PRV-001 o LGPD")
    ver.add_argument("--color", choices=("auto", "always", "never"), default="auto")
    ver.set_defaults(_salida="ver")

    resumen = subparsers.add_parser("resumen", help="Muestra conteos y cobertura")
    resumen.add_argument("--color", choices=("auto", "always", "never"), default="auto")
    resumen.set_defaults(_salida="resumen")

    paises = subparsers.add_parser("paises", aliases=["countries"], help="Lista jurisdicciones")
    paises.set_defaults(_salida="paises")

    roles = subparsers.add_parser("roles", help="Muestra cobertura por rol")
    roles.set_defaults(_salida="roles")

    mapa = subparsers.add_parser("mapa", help="Muestra una ruta de referencias por equipo")
    mapa.add_argument("--color", choices=("auto", "always", "never"), default="auto")
    mapa.set_defaults(_salida="mapa")

    exportar = subparsers.add_parser(
        "exportar", aliases=["export"], help="Exporta resultados filtrados a JSON o CSV"
    )
    exportar.add_argument("consulta", nargs="*", help="Palabras para búsqueda")
    _agregar_filtros(exportar)
    exportar.add_argument("--formato", choices=("json", "csv"), default="json")
    exportar.add_argument("--salida", "-o", help="Archivo de salida o '-' para stdout")
    exportar.add_argument("--forzar", action="store_true", help="Sobrescribe un archivo existente")
    exportar.set_defaults(_salida="exportar")

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = construir_parser()
    args = parser.parse_args(argv)
    try:
        entradas = cargar_catalogo()
    except CatalogError as exc:
        print("Error de catálogo: {0}".format(exc), file=sys.stderr)
        return 1

    comando = args.comando
    if comando is None:
        imprimir_resumen(entradas, color="auto")
        return 0

    salida_comando = getattr(args, "_salida", comando)
    if salida_comando in {"listar", "buscar"}:
        filtros = _filtros_desde_argumentos(args)
        resultados = filtrar_entradas(entradas, **filtros)
        if not resultados:
            print("No se encontraron entradas para los filtros indicados.", file=sys.stderr)
            return 2
        imprimir_tabla(
            resultados,
            detalle=getattr(args, "detalle", False),
            color=getattr(args, "color", "auto"),
        )
        return 0

    if salida_comando == "ver":
        coincidencias = encontrar_entradas(entradas, args.referencia)
        if not coincidencias:
            print("No se encontró la referencia: {0}".format(args.referencia), file=sys.stderr)
            return 2
        if len(coincidencias) > 1:
            print("La referencia es ambigua; use el ID completo:", file=sys.stderr)
            for entrada in coincidencias:
                print("  {0} — {1}".format(entrada.id, entrada.acronimo), file=sys.stderr)
            return 2
        imprimir_entrada(coincidencias[0], color=args.color)
        return 0

    if salida_comando == "resumen":
        imprimir_resumen(entradas, color=args.color)
        return 0
    if salida_comando == "paises":
        imprimir_paises(entradas)
        return 0
    if salida_comando == "roles":
        imprimir_roles(entradas)
        return 0
    if salida_comando == "mapa":
        imprimir_mapa_equipos(entradas, color=args.color)
        return 0
    if salida_comando == "exportar":
        filtros = _filtros_desde_argumentos(args)
        resultados = filtrar_entradas(entradas, **filtros)
        if not resultados:
            print("No se encontraron entradas para exportar.", file=sys.stderr)
            return 2
        contenido = _render_exportacion(resultados, args.formato)
        if not args.salida or args.salida == "-":
            sys.stdout.write(contenido)
            return 0
        destino = Path(args.salida).expanduser()
        if destino.exists() and not args.forzar:
            print(
                "El archivo ya existe; use --forzar para sobrescribirlo: {0}".format(destino),
                file=sys.stderr,
            )
            return 1
        destino.parent.mkdir(parents=True, exist_ok=True)
        codificacion = "utf-8-sig" if args.formato == "csv" else "utf-8"
        destino.write_text(contenido, encoding=codificacion)
        print(
            "Se exportaron {0} entradas a {1}".format(len(resultados), destino),
            file=sys.stderr,
        )
        return 0

    parser.error("Comando no implementado: {0}".format(comando))
    return 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nOperación cancelada.", file=sys.stderr)
        raise SystemExit(130)
