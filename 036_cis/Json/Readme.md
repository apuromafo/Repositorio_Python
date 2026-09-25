# Lector de Controles CIS (Español/Inglés)

Este script de Python permite leer y visualizar los Controles de Seguridad Críticos (CIS Controls) en español o inglés, mostrando cada control y sus salvaguardas de forma organizada en la consola, con una pausa entre cada uno para una lectura cómoda.

## Características

  * **Selección de Idioma:** Permite al usuario elegir entre la versión en español o inglés de los controles.
  * **Visualización Paginada:** Muestra un control a la vez, esperando la acción del usuario (`Enter`) para avanzar al siguiente.
  * **Formato Legible:** Presenta el número, título, resumen y cada salvaguarda con sus detalles (`ID`, `Descripción`, `Tipo de Activo`, `Función de Seguridad`, `IGs`) de manera clara y estructurada.
  * **Limpieza de Pantalla:** Limpia la consola antes de mostrar cada nuevo control para una experiencia de lectura despejada.

## Requisitos

  * Python 3.x
  * Los archivos JSON unificados de los Controles CIS en español (`all_cis_controls_es.json`) y en inglés (`all_cis_controls_en.json`).

## Preparación de los Archivos JSON

Este script asume que ya has generado los archivos JSON unificados (`all_cis_controls_es.json` y `all_cis_controls_en.json`) utilizando un script previo (como el que unifica los controles individuales).

Asegúrate de que estos archivos estén ubicados en el **mismo directorio** que el script `Leer.py`.

## Uso

1.  **Ubica los archivos JSON:** Coloca los archivos `all_cis_controls_es.json` y `all_cis_controls_en.json` en el **mismo directorio** donde está `Leer.py`.

2.  **Ejecuta el script:** Abre tu terminal o línea de comandos, navega hasta el directorio `Json` y ejecútalo con Python:

    ```bash
    python Leer.py
    ```

3.  **Sigue el menú:** El script te presentará un menú de opciones. Simplemente ingresa el número de la opción deseada y presiona `Enter`. Para avanzar entre controles, presiona `Enter` cuando se te indique.

## Estructura de Directorios Esperada

```
/036_cis/Json/
├── Leer.py
├── all_cis_controls_es.json
└── all_cis_controls_en.json
```

## Contenido de los JSON (CIS v8.1.2, marzo 2025)

* 18 controles, 153 salvaguardas en cada idioma.
* Cada salvaguarda incluye: `id`, `title`, `description`, `asset_type`,
  `security_function` e `igs` (IG1/IG2/IG3).
* Fuente oficial: `documentos/CIS_Controls_Version_8.1.2___March_2025.csv`
  (más guía PDF y XLSX en el mismo directorio).