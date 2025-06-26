# Analizador de Credenciales

Este script analiza archivos en busca de credenciales (usuario:clave, URL:correo:clave, etc.) y evalúa su fuerza basándose en la entropía.  El objetivo es identificar contraseñas débiles que podrían ser vulnerables.

## Instalación

No requiere instalación específica.  Simplemente descarga el script y ejecuta con Python 3.

## Uso

Puedes utilizar el script de dos maneras:

**1. Analizando un archivo:**

```bash
python analizador_credenciales.py -a <ruta_al_archivo>
```

Reemplaza `<ruta_al_archivo>` con la ruta al archivo que deseas analizar (ej., `credenciales.txt`, `log.sql`).

**2. Analizando una carpeta:**

```bash
python analizador_credenciales.py -f <ruta_a_la_carpeta>
```

Reemplaza `<ruta_a_la_carpeta>` con la ruta a la carpeta que contiene los archivos potencialmente sensibles (ej., `datos/`).  El script buscará archivos en esta carpeta y los analizará.

## Funcionalidades

*   **Detección de patrones:** Reconoce varios formatos comunes de credenciales, incluyendo:
    *   `usuario:clave`
    *   `url:correo:clave`
    *   `android://token@url:user:pass`
    *   `rut:clave` (sin sitio)
    *   y más...
*   **Cálculo de entropía:** Calcula la entropía de cada contraseña para estimar su fuerza.  La entropía es una medida de la aleatoriedad y complejidad de la contraseña.
*   **Clasificación de fuerza:** Clasifica las contraseñas en categorías como "Muy Débil", "Débil", "Moderada", "Fuerte" y "Muy Fuerte".
*   **Salida detallada:** Genera un informe que incluye:
    *   La entropía calculada para cada contraseña.
    *   La fuerza de la contraseña según la clasificación.
    *   Una lista de todas las credenciales encontradas.
    *   Un resumen por nivel de fuerza.
    *   Identifica líneas que no pudieron ser procesadas.
*   **Guardado en CSV:**  Guarda los resultados en un archivo CSV para su posterior análisis.

## Requisitos

*   Python 3 (o superior)
*   `argparse` (generalmente incluido con Python)

 