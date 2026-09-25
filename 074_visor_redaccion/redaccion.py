#!/usr/bin/env python
# -*- coding: utf-8 -*-
# ------------------------------------------------------------
# DISCLAIMER: Este script es parte del repositorio de herramientas de pruebas de
# penetracion. Su uso esta sujeto a los terminos de la licencia MIT y al aviso
# legal presente en el README.
# ------------------------------------------------------------
# AVISO LEGAL: Uso solo con autorizacion / LEGAL NOTICE: Authorized use only.

"""redaccion v1.4: nucleo de redaccion/censura de evidencias (100% local, Pillow).

Modo "mostrar pero censurar" para auditorias (SII, salud, pensiones, etc.): se
marcan regiones de la evidencia (rostro, cuerpo, DNI, numero de historia,
nombre, fecha...) y esto genera:

  - copia redactada (barra / blur / pixelado; barra con relleno + borde)  -> NUNCA toca el original
  - manifest.json (que region, que metodo, motivo, hash)  -> trazabilidad
  - reporte.log con cabecera de herramienta
  - hash SHA-256 del original y de la copia  -> cadena de custodia
  - opcional PDF con MARCA DE AGUA sobre la imagen redactada (evidencia que
    no se puede quitar de la copia publicada)

Privacidad: 100% local (Pillow), sin red, sin GPU, sin tokens. El original
queda intacto; la salida es SIEMPRE una copia redactada. Nada se publica: los
casos de auditoria son cerrados y locales.

Uso como libreria:
    import redaccion as rd
    res = rd.redactar_archivo("evidencia.png", regiones, out_dir="salida/",
                              pdf=True, marca_agua="copia autorizada a|correo@algo.com",
                              marca_tamanio=34, marca_alpha=45, marca_color="#ffffff")
    print(res["hash_original"], res["hash_salida"], res.get("salida_pdf"))
"""

__version__ = "1.4.0"

import datetime
import hashlib
import json
import math
import os

try:
    from PIL import Image, ImageDraw, ImageFilter, ImageFont, ImageOps
    HAVE_PIL = True
except Exception:  # pragma: no cover
    HAVE_PIL = False

try:
    from pypdf import PdfReader, PdfWriter
    HAVE_PYPDF = True
except Exception:  # pragma: no cover
    HAVE_PYPDF = False

MODOS = ("barra", "blur", "pixelado")
HERRAMIENTA = "074_visor_redaccion/redaccion"
AUTOR = "Apuromafo"


def hash_sha256(path):
    """Hash SHA-256 de un archivo (cadena de custodia)."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def cargar_imagen(path):
    """Carga la imagen y la convierte a RGB (soporta EXIF de orientacion)."""
    if not HAVE_PIL:  # pragma: no cover
        raise RuntimeError("Pillow no esta disponible: pip install -r requirements.txt")
    img = Image.open(path)
    img = ImageOps.exif_transpose(img)
    if img.mode != "RGB":
        img = img.convert("RGB")
    return img


def _clamp_region(box, ancho, alto):
    x1, y1, x2, y2 = box
    x1 = max(0, min(int(round(x1)), ancho))
    y1 = max(0, min(int(round(y1)), alto))
    x2 = max(0, min(int(round(x2)), ancho))
    y2 = max(0, min(int(round(y2)), alto))
    if x2 < x1:
        x1, x2 = x2, x1
    if y2 < y1:
        y1, y2 = y2, y1
    if x2 - x1 < 1:
        x2 = min(x1 + 1, ancho)
    if y2 - y1 < 1:
        y2 = min(y1 + 1, alto)
    return (x1, y1, x2, y2)


def normalizar_region(region, ancho, alto):
    """Pasa la region a pixeles absolutos (x1,y1,x2,y2).

    Acepta listas/tuplas de 4 elementos o dict con claves x1,y1,x2,y2 / x,y,w,h.
    Si los 4 valores son flotantes en (0,1], se interpretan como coordenadas
    normalizadas (x por ancho, y por alto); en cualquier otro caso se usan tal
    cual como pixeles.
    """
    if isinstance(region, dict):
        if "region" in region:
            region = region["region"]
        elif all(k in region for k in ("x", "y", "w", "h")):
            region = [region["x"], region["y"],
                      region["x"] + region["w"], region["y"] + region["h"]]
        elif all(k in region for k in ("x1", "y1", "x2", "y2")):
            region = [region["x1"], region["y1"], region["x2"], region["y2"]]
        else:
            raise ValueError("Region dict invalida: %r" % (region,))
    if len(region) != 4:
        raise ValueError("Region debe tener 4 valores: %r" % (region,))
    vals = list(region)
    if all(isinstance(v, float) and 0.0 < v <= 1.0 for v in vals):
        # coordenadas normalizadas: indices pares son x, impares son y
        vals = [vals[0] * ancho, vals[1] * alto, vals[2] * ancho, vals[3] * alto]
    return _clamp_region(vals, ancho, alto)


def _parse_color(color):
    """Convierte un color a tupla RGB. Acepta nombre, hex '#rrggbb' o triplete."""
    if color is None:
        return (0, 0, 0)
    if isinstance(color, str):
        color = color.strip()
        if color.startswith("#"):
            color = color.lstrip("#")
            if len(color) == 6:
                return tuple(int(color[i:i + 2], 16) for i in (0, 2, 4))
            if len(color) == 3:
                return tuple(int(c * 2, 16) for c in color)
            raise ValueError("Color hex invalido: %r" % color)
        tabla = {
            "black": (0, 0, 0), "negro": (0, 0, 0),
            "white": (255, 255, 255), "blanco": (255, 255, 255),
            "gray": (128, 128, 128), "grey": (128, 128, 128), "gris": (128, 128, 128),
            "red": (255, 0, 0), "rojo": (255, 0, 0),
            "blue": (0, 0, 255), "azul": (0, 0, 255),
            "green": (0, 255, 0), "verde": (0, 255, 0),
            "yellow": (255, 255, 0), "amarillo": (255, 255, 0),
        }
        if color.lower() in tabla:
            return tabla[color.lower()]
        raise ValueError("Color invalido: %r" % color)
    if isinstance(color, (list, tuple)) and len(color) >= 3:
        return tuple(max(0, min(255, int(v))) for v in color[:3])
    raise ValueError("Color invalido: %r" % color)


NIVELES_BYN = (2, 4, 8, 16, 32, 64, 128, 256)


def aplicar_byn(imagen, niveles=256):
    """Convierte la imagen a BLANCO Y NEGRO PURO (gris).

    niveles: cantidad de niveles de gris (2=binario puro, 4/8/16/32/64/128/256).
    Habilitado por el usuario para ver/exportar evidencias a color SIN tonos de
    piel: el resultado es gris (o binario si niveles=2). Devuelve una copia RGB.
    """
    if niveles not in NIVELES_BYN:
        raise ValueError("niveles debe ser uno de %s (2=binario puro)" % (NIVELES_BYN,))
    gris = imagen.convert("L")
    if niveles == 256:
        return gris.convert("RGB")
    bits = int(round(math.log2(niveles)))
    return ImageOps.posterize(gris, bits).convert("RGB")


def _aplicar_una(imagen, box, metodo, intensidad, color=None, color_borde=None, grosor_borde=2):
    """Aplica barra/blur/pixelado sobre (x1,y1,x2,y2) de la imagen (en su lugar).

    color: relleno de la barra. color_borde: contorno opcional de la barra
    ("sin borde"/None = sin contorno). grosor_borde: ancho del contorno en px.
    """
    x1, y1, x2, y2 = box
    if metodo == "barra":
        dr = ImageDraw.Draw(imagen)
        borde = None
        if color_borde and str(color_borde).strip().lower() not in ("sin borde", "ninguno", "none", ""):
            borde = _parse_color(color_borde)
        if borde is not None:
            dr.rectangle(box, fill=_parse_color(color), outline=borde,
                         width=max(1, int(grosor_borde)))
        else:
            dr.rectangle(box, fill=_parse_color(color))
    elif metodo == "blur":
        region = imagen.crop(box).filter(ImageFilter.GaussianBlur(radius=intensidad))
        imagen.paste(region, box)
    elif metodo == "pixelado":
        region = imagen.crop(box)
        cell = max(1, int(intensidad))
        w = max(1, (x2 - x1) // cell)
        h = max(1, (y2 - y1) // cell)
        region = region.resize((w, h), Image.LANCZOS).resize((x2 - x1, y2 - y1), Image.NEAREST)
        imagen.paste(region, box)
    else:
        raise ValueError("Metodo invalido: %r (usar %s)" % (metodo, "/".join(MODOS)))
    return imagen


def aplicar_redaccion(imagen, regiones, filtro_byn=None):
    """Devuelve una COPIA de la imagen con las regiones redactadas.

    regiones: lista de dicts {region, modo, motivo, tipo, intensidad, color,
    color_borde, grosor_borde}. color = relleno de la barra; color_borde y
    grosor_borde personalizan el contorno (opcional).
    El `imagen` original no se modifica.
    filtro_byn: opcional, niveles de gris (2..256) para convertir primero la
    imagen a B/N puro (evidencias a color sin tonos de piel).
    """
    if not HAVE_PIL:
        raise RuntimeError("Pillow no esta disponible")
    copia = imagen.copy()
    if filtro_byn:
        copia = aplicar_byn(copia, niveles=filtro_byn)
    ancho, alto = copia.size
    for n, reg in enumerate(regiones, start=1):
        modo = reg.get("modo", "barra").strip().lower() or "barra"
        intensidad = int(reg.get("intensidad", reg.get("radio", 8)))
        color = reg.get("color")
        color_borde = reg.get("color_borde")
        grosor_borde = reg.get("grosor_borde", 2)
        box = normalizar_region(reg.get("region"), ancho, alto)
        _aplicar_una(copia, box, modo, intensidad, color=color,
                     color_borde=color_borde, grosor_borde=grosor_borde)
    return copia


def marca_de_agua(imagen, texto="CONFIDENCIAL", alpha=45, tamanio=34, color="#ffffff",
                  negrita=False, cantidad=3):
    """Devuelve una COPIA RGB con la marca de agua repetida (mosaico diagonal).

    Se usa al exportar PDF: la evidencia sale YA con marca de agua sobre la
    imagen redactada, para que no se pueda quitar de la copia publicada.
    100% local (Pillow), sin red. El mosaico rotado cubre toda la imagen.

    texto: puede ser MULTILINEA — separa las lineas con "|" o con \n.
    Ej: "copia autorizada a|correo@algo.com" dibuja dos lineas.
    alpha: opacidad del texto (0-255). tamanio: tamano de fuente en px.
    color: color del texto (nombre/hex/RGB).
    negrita: True dibuja el texto en NEGRITA (grosor de trazo).
    cantidad: densidad de la repeticion 1-5 (1 = espaciado amplio, 5 = muy
    tupido, mas veces repetido).
    """
    if not HAVE_PIL:
        raise RuntimeError("Pillow no esta disponible")
    lineas = [l.strip() for l in str(texto or "CONFIDENCIAL").replace("|", "\n").split("\n") if l.strip()]
    if not lineas:
        lineas = ["CONFIDENCIAL"]
    w, h = imagen.size
    try:
        if negrita:
            fuente = ImageFont.truetype("arialbd.ttf", max(8, int(tamanio)))
        else:
            fuente = ImageFont.truetype("arial.ttf", max(8, int(tamanio)))
    except Exception:  # pragma: no cover
        try:
            fuente = ImageFont.truetype("arial.ttf", max(8, int(tamanio)))
        except Exception:  # pragma: no cover
            fuente = ImageFont.load_default()
    try:
        rgb = _parse_color(color)
    except Exception:  # pragma: no cover
        rgb = (255, 255, 255)
    alfa = max(0, min(255, int(alpha)))
    # medir el bloque multilinea: ancho maximo y alto total
    med = ImageDraw.Draw(Image.new("RGB", (1, 1)))
    altos = []
    anchos = []
    for li in lineas:
        bb = med.textbbox((0, 0), li, font=fuente)
        anchos.append(bb[2] - bb[0])
        altos.append(bb[3] - bb[1])
    ancho_t = max(120, max(anchos) + 28)
    alto_t = max(60, sum(altos) + 24 + (len(lineas) - 1) * 6)
    mosaico = Image.new("RGBA", (ancho_t, alto_t), (0, 0, 0, 0))
    dm = ImageDraw.Draw(mosaico)
    y = 12
    for li in lineas:
        dm.text((14, y), li, font=fuente, fill=(rgb[0], rgb[1], rgb[2], alfa))
        bb = med.textbbox((0, 0), li, font=fuente)
        y += (bb[3] - bb[1]) + 6
    mosaico = mosaico.rotate(22, expand=True, resample=Image.BICUBIC)
    # teselado del mosaico sobre toda la imagen
    capa = Image.new("RGBA", imagen.size, (0, 0, 0, 0))
    cant = max(1, min(5, int(cantidad or 3)))
    # densidad: mas cantidad = mas repeticiones (menos espacio entre mosaicos)
    sx = max(0.35, 1.1 - (cant - 1) * 0.1625)   # 1.1 -> 0.45 de 1 a 5
    sy = max(0.35, 1.0 - (cant - 1) * 0.1375)   # 1.0 -> 0.45 de 1 a 5
    paso_x = max(1, int(mosaico.width * sx))
    paso_y = max(1, int(mosaico.height * sy))
    fila, y = 0, -mosaico.height
    while y < h:
        x = (0 if fila % 2 == 0 else -mosaico.width // 2)
        while x < w + mosaico.width:
            capa.paste(mosaico, (int(x), int(y)), mosaico)
            x += paso_x
        fila += 1
        y += paso_y
    return Image.alpha_composite(imagen.convert("RGBA"), capa).convert("RGB")


def _metadata_base(entrada, regiones, comando, filtro_byn=None):
    now = datetime.datetime.now().isoformat(timespec="seconds")
    meta = {
        "herramienta": HERRAMIENTA,
        "version": __version__,
        "fecha": now,
        "autor": AUTOR,
        "comando": comando or "",
        "entrada": os.path.basename(entrada),
        "region_docs": "Coordenadas en pixeles de la imagen de entrada. Modos: "
                       "barra|blur|pixelado. Color: relleno (color) y opcional "
                       "borde (color_borde + grosor_borde).",
    }
    if filtro_byn:
        meta["filtro_byn"] = {
            "niveles": filtro_byn,
            "nota": "Imagen convertida a blanco y negro puro (gris) antes de la redaccion.",
        }
    return meta


def proteger_pdf(ruta, clave):
    """Cifra un PDF existente con contrasena (lo reescribe protegido).

    Requiere pypdf (opcional, requirements.txt). Devuelve True si se cifro.
    La contrasena NUNCA se guarda en el manifest ni en reporte.log: solo queda
    el marcador pdf_protegido=True (privacidad de la contrasena).
    """
    if not clave:
        return False
    if not HAVE_PYPDF:
        raise RuntimeError("pypdf no disponible: pip install -r requirements.txt")
    lector = PdfReader(ruta)
    escritor = PdfWriter()
    for pagina in lector.pages:
        escritor.add_page(pagina)
    try:
        escritor.encrypt(clave, algorithm="AES-256")
    except Exception:  # pragma: no cover
        escritor.encrypt(clave, use_128bit=True)
    with open(ruta, "wb") as fh:
        escritor.write(fh)
    return True


def redactar_archivo(entrada, regiones, out_dir, prefijo=None, comando="", filtro_byn=None,
                     pdf=False, marca_agua="CONFIDENCIAL", marca_tamanio=34,
                     marca_alpha=45, marca_color="#ffffff",
                     marca_negrita=False, marca_cantidad=3, pdf_password=None):
    """Redacta `entrada` en una copia dentro de out_dir.

    Genera: <nombre>_redactada.png, <nombre>_manifest.json y reporte.log con la
    cabecera de herramienta. Devuelve un dict con rutas y hashes.
    filtro_byn: opcional, convierte la copia de salida a B/N puro (niveles de
    gris, 2=binario) ANTES de aplicar las regiones.
    pdf: opcional, ademas genera <nombre>_redactada.pdf con la imagen YA
    redactada + marca de agua repetida (evidencia que no se puede quitar de la
    copia publicada). marca_agua: texto (MULTILINEA con "|" o \\n).
    marca_tamanio: tamano de fuente en px. marca_alpha: opacidad 0-255.
    marca_color: color del texto (hex/nombre/RGB). marca_negrita: True = texto
    en NEGRITA (grosor de trazo mayor). marca_cantidad: densidad de repeticion
    1-5 (1 espaciado amplio, 5 muy tupido).
    pdf_password: contrasena OPCIONAL para CIFRAR el PDF (requiere pypdf).
    Nunca se guarda en claro: en manifest/log solo queda pdf_protegido=True.
    """
    if not os.path.isfile(entrada):
        raise FileNotFoundError("No existe la imagen: %s" % entrada)
    if not regiones:
        raise ValueError("No hay regiones para redactar (regiones vacio)")
    os.makedirs(out_dir, exist_ok=True)

    img = cargar_imagen(entrada)
    base = os.path.splitext(os.path.basename(entrada))[0]
    salida = os.path.join(out_dir, (prefijo or base) + "_redactada.png")
    copia = aplicar_redaccion(img, regiones, filtro_byn=filtro_byn)
    copia.save(salida, "PNG")

    salida_pdf = None
    if pdf:
        salida_pdf = os.path.join(out_dir, (prefijo or base) + "_redactada.pdf")
        marca_de_agua(copia, texto=marca_agua or "CONFIDENCIAL",
                      alpha=marca_alpha, tamanio=marca_tamanio,
                      color=marca_color or "#ffffff",
                      negrita=marca_negrita, cantidad=marca_cantidad).save(salida_pdf, "PDF", resolution=150)
        if pdf_password:
            proteger_pdf(salida_pdf, pdf_password)

    hash_orig = hash_sha256(entrada)
    hash_sal = hash_sha256(salida)

    manifest = _metadata_base(entrada, regiones, comando, filtro_byn=filtro_byn)
    manifest.update({
        "salida": os.path.basename(salida),
        "dimensiones": list(img.size),
        "ancho_x_alto": "%dx%d" % img.size,
        "hash_original_sha256": hash_orig,
        "hash_salida_sha256": hash_sal,
        "n_regiones": len(regiones),
        "regiones": regiones,
        "nota": ("El original NO se altera; la salida es una copia redactada. "
                 "Uso local y autorizado; no publicar."),
    })
    if salida_pdf:
        manifest["salida_pdf"] = os.path.basename(salida_pdf)
        manifest["pdf_protegido"] = bool(pdf_password)
        manifest["marca_agua"] = {
            "texto": marca_agua or "CONFIDENCIAL",
            "tamanio": int(marca_tamanio),
            "alpha": int(marca_alpha),
            "color": marca_color or "#ffffff",
            "negrita": bool(marca_negrita),
            "cantidad": int(marca_cantidad),
            "nota": "Marca multilinea (separador '|' o \\n), tamano en px, "
                    "opacidad 0-255, color, negrita (grosor) y cantidad (1-5). "
                    "El PDF lleva la marca de agua repetida sobre la imagen "
                    "redactada (la PNG es la copia limpia censurada).",
        }
    manifest_path = os.path.join(out_dir, (prefijo or base) + "_manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, ensure_ascii=False, indent=2)

    reporte = os.path.join(out_dir, "reporte.log")
    with open(reporte, "a", encoding="utf-8") as fh:
        fh.write("tema=auditoria|tiempo=%s|herramienta=%s|version=%s|autor=%s|comando=%s|nivel=info\n"
                 % (manifest["fecha"], HERRAMIENTA, __version__, AUTOR, comando or "gui"))
        fh.write("entrada=%s hash=%s\n" % (entrada, hash_orig))
        fh.write("salida=%s hash=%s\n" % (salida, hash_sal))
        fh.write("regiones=%d\n" % len(regiones))

    return {
        "salida": salida,
        "salida_pdf": salida_pdf,
        "manifest": manifest_path,
        "reporte": reporte,
        "hash_original": hash_orig,
        "hash_salida": hash_sal,
        "n_regiones": len(regiones),
    }


if __name__ == "__main__":
    print("Modulo de redaccion %s (modos: %s). Usar via redactar.py (CLI) o visor_redaccion.py (GUI)."
          % (__version__, ", ".join(MODOS)))