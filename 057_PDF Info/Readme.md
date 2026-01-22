 
#  _pdf_info_analyzer 📄🔍

Este repositorio contiene herramientas profesionales para el análisis técnico y forense de archivos PDF. El objetivo principal es la detección de elementos maliciosos, extracción de metadatos y la identificación de **Canary Tokens** (trampas de rastreo) que podrían comprometer la privacidad del auditor.

## 📂 Contenido del Módulo

El sistema se compone de dos versiones del analizador, dependiendo de la necesidad de evasión o análisis:

### 1. PDF Info (Estándar)

* **Archivo**: `PDF_info.py`
* **Descripción**: Analizador forense de alto nivel que inspecciona la estructura interna del PDF.
* **Capacidades**:
* **Detección de Canary Tokens**: Identifica patrones de dominios conocidos como `canarytokens.com` o `thinkst.com`.
* **Análisis de Riesgo**: Detecta JavaScript embebido, acciones al abrir el archivo (`/OpenAction`) y flujos sospechosos.
* **Metadatos**: Extracción detallada de autor, software de creación y fechas.



### 2. PDF Info Pro (ROT13 Ofuscado)

* **Archivo**: `PDF_info_con_rot13.py`
* **Descripción**: Versión avanzada diseñada para entornos donde el propio script de análisis necesita protección contra firmas de seguridad o análisis estático simple.
* **Diferencial**: Utiliza codificación **ROT13** en sus patrones de detección internos, decodificándolos solo en tiempo de ejecución para evitar que el script sea detectado como herramienta de seguridad por soluciones automatizadas.

---

## 🚀 Forma de Uso

Ambos scripts aceptan parámetros de línea de comandos para procesar archivos individuales o carpetas completas.

### Análisis simple de un archivo:

```bash
python PDF_info.py -a "documento_sospechoso.pdf"

```

### Análisis masivo de una carpeta con extracción de archivos embebidos:

```bash
python PDF_info_con_rot13.py -c "./descargas" --extraer-embebidos

```

### Opciones principales:

* `-a, --archivo`: Ruta al archivo PDF específico.
* `-c, --carpeta`: Procesa todos los PDFs en una ruta.
* `--json`: Exporta los resultados a un archivo `.json` para su integración con otras herramientas.
* `--paralelo`: Activa el procesamiento multihilo (mucho más rápido para carpetas grandes).

---

## ⚠️ Disclaimer (Descargo de Responsabilidad)

**Esta herramienta está diseñada exclusivamente para fines de ciberseguridad ética y análisis forense.**

1. **Entorno Seguro**: Se recomienda analizar archivos PDF sospechosos en entornos aislados (Sandboxing/VM), ya que la manipulación de archivos maliciosos siempre conlleva un riesgo.
2. **Privacidad**: El autor no se hace responsable por la activación accidental de Canary Tokens durante el análisis si el usuario no sigue las precauciones de red adecuadas.
3. **Uso Legal**: El uso de este software en sistemas sin autorización previa es ilegal. El usuario asume toda la responsabilidad legal por sus acciones.

---

## 🛠️ Requisitos

* **Python 3.x**
* **Librería `pypdf**`:
```bash
pip install pypdf

```

 