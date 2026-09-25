#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Archivo compatibility de la versión 2.1.

La implementación mantenida vive en ``catalogo_ciberseguridad.py``. Este
wrapper conserva el nombre anterior para no romper comandos o importaciones
existentes y ya no imprime avisos al ser importado.
"""

from catalogo_ciberseguridad import (  # noqa: F401
    CatalogError,
    Entrada,
    cargar_catalogo,
    encontrar_entradas,
    filtrar_entradas,
    imprimir_tabla,
    main,
    obtener_datos_regulaciones_final,
)


if __name__ == "__main__":
    raise SystemExit(main())
