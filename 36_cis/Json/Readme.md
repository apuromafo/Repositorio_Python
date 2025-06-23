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

Asegúrate de que estos archivos estén ubicados en el **mismo directorio** que el script `cis_reader_menu.py`.

## Uso

1.  **Guarda el script:** Guarda el código proporcionado anteriormente como `cis_reader_menu.py` (o el nombre que prefieras) en tu máquina.

2.  **Ubica los archivos JSON:** Coloca los archivos `all_cis_controls_es.json` y `all_cis_controls_en.json` en el **mismo directorio** donde guardaste `cis_reader_menu.py`.

3.  **Ejecuta el script:** Abre tu terminal o línea de comandos, navega hasta el directorio donde guardaste el script y ejecútalo con Python:

    ```bash
    python cis_reader_menu.py
    ```

4.  **Sigue el menú:** El script te presentará un menú de opciones. Simplemente ingresa el número de la opción deseada y presiona `Enter`. Para avanzar entre controles, presiona `Enter` cuando se te indique.

## Estructura de Directorios Esperada

```
/tu_directorio_de_proyecto/
├── cis_reader_menu.py
├── all_cis_controls_es.json
└── all_cis_controls_en.json
```