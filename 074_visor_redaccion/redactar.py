#!/usr/bin/env python
# -*- coding: utf-8 -*-
# ------------------------------------------------------------
# DISCLAIMER: Este script es parte del repositorio de herramientas de pruebas de
# penetracion. Su uso esta sujeto a los terminos de la licencia MIT y al aviso
# legal presente en el README.
# ------------------------------------------------------------
# AVISO LEGAL: Uso solo con autorizacion / LEGAL NOTICE: Authorized use only.

"""redactar v1.0: CLI de redaccion/censura de evidencias (batch, 100% local).

Aplica redaccion por regiones a UNA imagen (examen, captura, documento) y deja:

  - <nombre>_redactada.png  (copia; el original nunca se toca)
  - <nombre>_manifest.json  (que/modo/motivo por region + hash, trazabilidad)
  - reporte.log             (cabecera de herramienta)

Las regiones se definen en un JSON (reglas). Ejemplo:

    [
      {"region": [100, 50, 320, 180], "modo": "blur",  "motivo": "rostro paciente"},
      {"region": [10, 10, 60, 40],    "modo": "barra", "motivo": "nombre en cabecera",
       "color": "#000000", "color_borde": "#ff0000", "grosor_borde": 2},
      {"region": [0.1, 0.4, 0.6, 0.5], "modo": "pixelado", "motivo": "zona sensible",
       "intensidad": 12}
    ]

Coordenadas absolutas en pixeles, o 0..1 si son flotantes (normalizadas).
modo: barra | blur | pixelado. intensidad opcional: blur -> radio, pixelado -> cell.
barra: color = relleno, color_borde = contorno (opcional), grosor_borde = ancho px.

Ejecutar:
    python redactar.py -i evidencia.png -r reglas.json -o salida/
    python redactar.py -i evidencia.png -r reglas.json -o salida/ --pdf --marca-agua "CONFIDENCIAL - no divulgar"
    python redactar.py -i evidencia.png -r reglas.json -o salida/ --pdf ^
      --marca-agua "copia autorizada a|correo@algo.com" --marca-tam 34 --marca-alpha 45 ^
      --marca-color "#ffffff" --marca-negrita --marca-cantidad 4
    python redactar.py -i evidencia.png -r reglas.json -o salida/ -l en

La marca de agua es MULTILINEA: separa las lineas con "|" o con \n.

Privacidad: local (Pillow), sin red, sin GPU. La salida siempre es una copia
redactada con su hash; el original queda intacto. Nada se publica.
"""

__version__ = "1.4.0"

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import redaccion as rd  # noqa: E402


def _cargar_reglas(path):
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, dict) and "regiones" in data:
        data = data["regiones"]
    if not isinstance(data, list) or not data:
        raise ValueError("El JSON de regiones debe ser una lista no vacia "
                         "o un dict con clave 'regiones'")
    for i, r in enumerate(data):
        if "region" not in r:
            raise ValueError("Region #%d no tiene clave 'region'" % (i + 1))
        r.setdefault("modo", "barra")
        r.setdefault("motivo", "")
    return data


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="redactar",
        description="Redaccion/censura de evidencias por regiones (100% local, Pillow).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("-i", "--in", dest="entrada", required=True,
                        help="Imagen de evidencia a redactar (no se modifica)")
    parser.add_argument("-r", "--regions", "--reglas", dest="reglas", required=True,
                        help="JSON con las regiones a redactar")
    parser.add_argument("-o", "--out", dest="salida", required=True,
                        help="Directorio de salida (copia redactada + manifest + reporte)")
    parser.add_argument("-p", "--prefijo", default=None,
                        help="Prefijo de los archivos de salida (default: nombre de entrada)")
    parser.add_argument("--byn", dest="byn", type=int, default=None, choices=rd.NIVELES_BYN,
                        help="Convertir la salida a B/N puro con N niveles de gris (2=binario puro, 4..256)")
    parser.add_argument("--pdf", action="store_true",
                        help="Ademas genera <nombre>_redactada.pdf con la imagen YA "
                             "redactada + MARCA DE AGUA repetida (evidencia que no se "
                             "puede quitar de la copia publicada)")
    parser.add_argument("--marca-agua", dest="marca_agua", default="CONFIDENCIAL",
                        help="Texto de la marca de agua del PDF (default: CONFIDENCIAL). "
                             "MULTILINEA: separa las lineas con '|' o con \\n")
    parser.add_argument("--marca-tam", dest="marca_tam", type=int, default=34,
                        help="Tamano (grosor) de la fuente de la marca en px (default: 34)")
    parser.add_argument("--marca-alpha", dest="marca_alpha", type=int, default=45,
                        help="Opacidad de la marca 0-255 (default: 45)")
    parser.add_argument("--marca-color", dest="marca_color", default="#ffffff",
                        help="Color de la marca (hex/nombre/RGB, default: #ffffff)")
    parser.add_argument("--marca-negrita", dest="marca_negrita", action="store_true",
                        help="Texto de la marca en NEGRITA (grosor de trazo mayor)")
    parser.add_argument("--marca-cantidad", dest="marca_cantidad", type=int, default=3,
                        help="Densidad de repeticion de la marca 1-5 (default: 3; 5 = muy tupida)")
    parser.add_argument("--pdf-clave", dest="pdf_clave", default=None,
                        help="Contrasena OPCIONAL para CIFRAR el PDF (pypdf). "
                             "Nunca se guarda en claro: solo pdf_protegido=True en el manifest")
    parser.add_argument("-l", "--lang", choices=("es", "en"), default="es",
                        help="Idioma de salida en consola (es/en)")
    args = parser.parse_args(argv)

    if not rd.HAVE_PIL:
        print("[redactar] ERROR: Pillow no disponible. pip install -r requirements.txt")
        return 2

    try:
        reglas = _cargar_reglas(args.reglas)
        res = rd.redactar_archivo(
            args.entrada, reglas,
            out_dir=args.salida, prefijo=args.prefijo,
            filtro_byn=args.byn, pdf=args.pdf, marca_agua=args.marca_agua,
            marca_tamanio=args.marca_tam, marca_alpha=args.marca_alpha,
            marca_color=args.marca_color, marca_negrita=args.marca_negrita,
            marca_cantidad=args.marca_cantidad, pdf_password=args.pdf_clave,
            comando="python redactar.py -i %s -r %s -o %s"
                    % (os.path.basename(args.entrada), args.reglas, args.salida),
        )
    except Exception as exc:
        print("[redactar] ERROR: %s" % exc)
        return 1

    if args.lang == "en":
        print("OK: %d region(s) redacted -> %s" % (res["n_regiones"], res["salida"]))
        print("manifest: %s" % res["manifest"])
        print("SHA-256 original: %s" % res["hash_original"])
        print("SHA-256 output:   %s" % res["hash_salida"])
        if res.get("salida_pdf"):
            print("PDF (with watermark): %s" % res["salida_pdf"])
    else:
        print("OK: %d region(es) redactadas -> %s" % (res["n_regiones"], res["salida"]))
        print("manifest: %s" % res["manifest"])
        print("SHA-256 original: %s" % res["hash_original"])
        print("SHA-256 salida:   %s" % res["hash_salida"])
        if res.get("salida_pdf"):
            print("PDF (con marca de agua): %s" % res["salida_pdf"])
    return 0


if __name__ == "__main__":
    sys.exit(main())