# README - Script de Análisis de Proceso Palo Alto

## Descripción

Este script de Python proporciona funcionalidades para interactuar con un proceso específico 
(por ejemplo, Palo Alto Networks GlobalProtect) de manera controlada. S
e puede utilizar para análisis, pruebas o exploración de procesos.

## Advertencia

Este script es solo para fines educativos e investigativos. No lo utilices para actividades maliciosas.
Está inspirado en un código en C, pero intenté convertirlo en funcionalidad en python3, al minuto no se aprecia detección en antivirus.

## Requisitos

- Python 3.x (puedes descargarlo desde [python.org](https://www.python.org/downloads/))
- Biblioteca `ctypes` (normalmente viene preinstalada con Python)

## Uso

1. Asegúrate de tener Python 3.x instalado en tu sistema.
2. Descarga el archivo `palo_alto.py`.
3. Ejecuta el script desde la terminal:

   ```
   python palo_alto.py
    ```
	
## Funcionalidades
- Imprime un banner colorido al inicio.
- Crea un proceso suspendido para interactuar con él.
- Busca un patrón específico en la memoria del proceso.
- Imprime los datos encontrados en formato XML.

	