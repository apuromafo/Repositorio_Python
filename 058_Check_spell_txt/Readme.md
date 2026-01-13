# 📝 Script de Revisión Ortográfica para Documentos Específicos

Este script de Python ofrece una solución de revisión ortográfica robusta, diseñada para validar textos que contienen **terminología específica (técnica, legal o comercial)** que no está en el diccionario estándar del español. Es ideal para formularios, contratos o documentación con acrónimos y anglicismos necesarios.

---

## ✨ Características Principales

* **Diccionario Personalizado:** Permite definir un conjunto de palabras y acrónimos válidos (`FATCA`, `RUT`, `Online`, `Marketing`, etc.) para evitar falsos positivos.
* **Soporte Multilingüe:** Utiliza la librería `pyspellchecker` con el diccionario base en **español (`es`)**.
* **Manejo de Tildes:** Utiliza expresiones regulares para capturar correctamente palabras con acentos y la letra 'ñ'.
* **Sugerencias de Corrección:** Ofrece la mejor sugerencia de corrección para las palabras mal escritas o desconocidas.
* **Entorno Controlado:** El script está configurado para revisar un archivo de texto específico (`demo.txt` por defecto).

## 🚀 Instalación y Uso

### 1. Requisitos

Asegúrate de tener Python instalado (versión 3.6 o superior).

### 2. Instalación de la Librería

Este script requiere la librería `pyspellchecker`. Instálala usando `pip`:

```bash
pip install pyspellchecker