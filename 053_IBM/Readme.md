# IBM_Analyzer - Suite de Análisis Estático y Seguridad para Código IBM i 🚀

## 📜 Descripción General

**IBM_Analyzer** es una suite modular de análisis estático diseñada para examinar código fuente de sistemas IBM i: **RPG** (Report Program Generator), **CL** (Control Language) y **PF** (Physical File).

La suite se compone de dos herramientas clave que trabajan en conjunto para proporcionar una visión completa del código.

### Herramienta 1: Análisis Detallado (`step1_IBM_scan_code.py`)
Genera un **informe detallado** por cada archivo, que incluye:
* Resumen de comandos y elementos utilizados.
* Estadísticas de uso y variables/campos declarados.
* Listado de líneas de código no reconocidas.

### Herramienta 2: Escaneo de Seguridad (`step2x_IBM_...py`)
Procesa los informes detallados generados en el Paso 1 para identificar **patrones de seguridad** (DUMP, Hardcoded Credentials, Debug, etc.) basados en estándares CWE y OWASP.

---

## 🛠️ Flujo de Trabajo y Modo de Uso

El análisis completo requiere de dos pasos secuenciales. El Paso 1 genera los datos de entrada necesarios para que el Paso 2 ejecute el escaneo de seguridad.

### 1. PASO 1: Análisis de Código Detallado (`step1_IBM_scan_code.py`)

Esta fase genera un **Header** de resumen y los **Reportes Individuales** (`_detallado_individual.txt`). Todos se guardarán dentro de la subcarpeta `Reporte/` en la ruta de salida que elijas.

| Modo de Análisis | Descripción | Comando de Ejemplo |
| :--- | :--- | :--- |
| **Carpeta (Recursivo)** | Analiza la carpeta y todas sus subcarpetas. **(Recomendado)** | `python step1_IBM_scan_code.py -f <ruta_de_la_carpeta> -r` |
| **Carpeta (No Recursivo)** | Analiza solo los archivos en la carpeta principal. | `python step1_IBM_scan_code.py -f <ruta_de_la_carpeta>` |

> **Nota:** Al ejecutar el script, se le preguntará dónde desea guardar la salida:
> 1. En la misma carpeta del análisis.
> 2. En una nueva subcarpeta con fecha y hora (ej: `salida_20251003_110116`).
> **La carpeta de salida que elija, contendrá la subcarpeta clave `Reporte/`.**

***

### 2. PASO 2: Escaneo de Seguridad (`step2x_IBM_...py`)

Una vez que el Paso 1 ha finalizado, ejecute el escáner de seguridad apuntando a la **carpeta de los reportes generados** (la subcarpeta `Reporte/`).

**Ejecución de Muestra (usando el escáner simple `step2a`):**

| Modo de Análisis | Descripción | Comando de Ejemplo |
| :--- | :--- | :--- |
| **Analizar Reportes** | Analiza de forma recursiva todos los reportes `.txt` en la carpeta indicada. | `python step2a_IBM_simple_scan_finding_report_hallazgo.py -f <ruta_de_salida_del_paso_1>/Reporte -r` |

> **Salida del Paso 2:** El reporte de seguridad (`SECURITY_FINDINGS_...txt`) se guarda en la carpeta configurada internamente en el script (por defecto, `resultados_analisis/`).

---

## 📝 Requisitos

* **Python 3.x**
* **Librerías (Recomendado):** La librería `chardet` (para mejor detección de codificación de texto).

---

## 🌟 Historial de Versiones (v4.1.1 - FINAL COMPLETA)

Esta versión representa una revisión completa con mejoras en la estabilidad, modularidad y generación de nombres de archivos:

* **Modularidad:** Separación lógica entre el análisis de código (`step1`) y el análisis de seguridad (`step2`).
* **Rutas Unificadas:** Todos los reportes (Header e Individuales) se agrupan consistentemente en la subcarpeta `Reporte/`.
* **Detección Mejorada:** Los patrones de inclusión/exclusión del escáner de seguridad han sido actualizados para reconocer los nuevos nombres de los reportes.
* **Archivos Mejorados:** Hash SHA-256 completo, número de líneas y detección de *encoding* incluidos en los reportes.

---

## Disclaimer / Descargo de Responsabilidad

Este proyecto y sus herramientas asociadas se proporcionan **"tal cual"**, sin garantías de ningún tipo.

El uso de esta herramienta es bajo la **exclusiva responsabilidad del usuario**. El desarrollador no se responsabiliza por daños directos, indirectos, incidentales, especiales, consecuentes o punitivos que puedan derivarse del uso o mal uso de esta herramienta.

Esta herramienta está destinada exclusivamente para **fines legales, éticos y con el debido consentimiento**. El uso para actividades maliciosas está estrictamente prohibido y puede ser ilegal.

**¡Usa esta herramienta responsablemente y con ética!**