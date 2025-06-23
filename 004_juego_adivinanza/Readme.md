# Juego de Adivinanza

Este es un sencillo juego de adivinanzas donde el usuario debe intentar adivinar un número aleatorio entre 1 y 100.  El juego tiene 10 intentos para completar.

## Descripción

El juego genera un número secreto aleatorio entre 1 y 100. El jugador debe adivinar este número dentro de 10 intentos. Después de cada intento, el programa le indicará si su respuesta es demasiado alta o demasiado baja. Si el jugador no adivina el número en 10 intentos, se declara perdedor.

## Requisitos

*   **Python 3:**  Este juego está escrito en Python 3 y requiere una instalación de Python 3 para ejecutarse.
*   **Módulo `colorama`:** Se utiliza para agregar color a la salida del juego (opcional pero recomendado). Puedes instalarlo usando: `pip install colorama`

## Cómo ejecutar el juego

1.  Asegúrate de tener instalado Python 3 y el módulo `colorama`.
2.  Guarda el código como un archivo `.py` (por ejemplo, `adivina_numero.py`).
3.  Abre una terminal o línea de comandos.
4.  Navega hasta el directorio donde guardaste el archivo.
5.  Ejecuta el juego usando el comando: `python adivina_numero.py`

## Funcionalidades

*   **Número Aleatorio:** El juego genera un número aleatorio entre 1 y 100.
*   **Intentos Limitados:** El jugador tiene 10 intentos para adivinar el número.
*   **Retroalimentación:** Después de cada intento, el programa le indica si su respuesta es demasiado alta o demasiado baja.
*   **Mensaje de Pérdida:** Si el jugador no adivina el número en 10 intentos, se muestra un mensaje indicando que ha perdido y revela el número secreto.
