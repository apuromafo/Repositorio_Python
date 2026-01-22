 
#  guess_the_number_game 🎮🔢

Este repositorio contiene un juego de lógica y agilidad mental basado en consola (CLI). El objetivo es adivinar un número secreto generado aleatoriamente dentro de un rango desafiante, bajo presión de tiempo y con un límite de intentos.

## 📂 Descripción del Proyecto

El script `Script3.py` es una implementación robusta del clásico juego "Adivina el número", diseñada con un enfoque modular y preparada para soporte multi-idioma.

* **Rango de Juego**: El número secreto se genera entre **1 y 300**.
* **Gestión de Intentos**: El jugador dispone de un máximo de **10 intentos** por partida.
* **Presión Temporal**: Incluye un sistema de tiempo límite (60 segundos por intento) compatible con Windows y Linux mediante el uso de hilos (*threading*).
* **Pistas Dinámicas**: El sistema indica si el número secreto es mayor o por el contrario menor al ingresado, ayudando a refinar la búsqueda.
* **Contador de Sesión**: Realiza un seguimiento de cuántas partidas has jugado y ganado en la sesión actual.

---

## 🚀 Forma de Uso

Para iniciar una partida, simplemente ejecuta el script en tu terminal. El juego te guiará a través de una cuenta regresiva antes de empezar.

```bash
python Script3.py

```

### Mecánica de juego:

1. **Inicio**: Aparecerá una bienvenida y una cuenta atrás de preparación.
2. **Entrada**: Introduce un número cuando se te solicite. Si tardas más de 60 segundos, el intento se invalidará.
3. **Resultados**: Al ganar o perder, se mostrarán estadísticas de tiempo total, número de intentos utilizados y el número secreto (en caso de derrota).
4. **Rejugabilidad**: Al finalizar, podrás elegir si quieres empezar una nueva partida sin cerrar el programa.

---

## ⚠️ Disclaimer (Aviso de Uso)

**Este software ha sido creado con fines recreativos y de aprendizaje de lógica de programación en Python.**

1. **Uso Seguro**: El script es seguro y no realiza cambios en el sistema ni requiere privilegios de administrador.
2. **Manejo de Errores**: Se ha implementado una salida limpia mediante `Ctrl+C` (KeyboardInterrupt), asegurando que no queden procesos residuales en segundo plano.
3. **Entorno**: Diseñado para ejecutarse en terminales estándar. Se recomienda una terminal con soporte para colores ANSI para una mejor experiencia visual.

---

## 🛠️ Especificaciones Técnicas

* **Lenguaje**: Python 3.x.
* **Módulos Utilizados**: `random`, `time`, `sys`, `threading`, `queue`.
* **Arquitectura**: Orientado a funciones con un gestor de estados para las partidas.

---
 