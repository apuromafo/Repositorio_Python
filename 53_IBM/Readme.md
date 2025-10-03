# IBM_Analyzer - Analizador de Código RPG/CL/PF 🚀

## 📜 Descripción General

**IBM_Analyzer** es una herramienta de análisis estático diseñada para examinar archivos o carpetas que contienen código fuente de sistemas IBM i: **RPG** (Report Program Generator), **CL** (Control Language) y **PF** (Physical File).

Genera un **informe detallado** que incluye:

* Resumen de comandos y elementos utilizados.
* Estadísticas de uso por tipo de elemento.
* Variables y campos declarados.
* Listado de líneas de código no reconocidas.

---

## 🛠️ Modo de Uso (Línea de Comandos)

El script funciona mediante argumentos de línea de comandos (`-a` para archivo, `-f` para carpeta).

| Modo de Análisis | Comando |
| :--- | :--- |
| **Archivo Único** | `python3 IBM_Analyzer_v4.1.1_FINAL.py -a <ruta_del_archivo>` |
| **Carpeta (Recursivo)** | `python3 IBM_Analyzer_v4.1.1_FINAL.py -f <ruta_de_la_carpeta>` |
| **Salida Personalizada** | `python3 ... -a <ruta> -o <nombre_salida.txt>` |

---

## 🌟 Historial de Versiones

### v4.1.1 (2025-09-16) - FINAL COMPLETA

Esta versión representa una revisión completa con las siguientes mejoras y correcciones:

* ✅ **Análisis Recursivo:** Incluye subcarpetas al escanear directorios.
* ✅ **Hash SHA-256:** Corregido para mostrar el valor completo (64 caracteres).
* ✅ **Consistencia de Reporte:** El número de línea está incluido en todas las tablas de resultados.
* ✅ **Comandos PF:** Restaurado el diccionario completo de comandos y elementos de Physical File.
* ✅ **Archivos DESCONOCIDO:** Se proporciona información básica (metadatos) para archivos no reconocidos.
* ✅ **Metadatos Mejorados:** Detección de *encoding* y metadatos de archivo completos (tamaño, fechas, etc.).

---

## 📝 Requisitos

* **Python 3.x**
* **Recomendado:** La librería `chardet` (para mejor detección de codificación de texto).


-----

## Disclaimer / Descargo de Responsabilidad

Este proyecto y sus herramientas asociadas se proporcionan **"tal cual"**, sin garantías de ningún tipo, ya sean expresas o implícitas, incluidas pero no limitadas a las garantías de comerciabilidad, idoneidad para un propósito particular o no infracción.

El uso de esta herramienta es bajo la **exclusiva responsabilidad del usuario**. El desarrollador no se responsabiliza por daños directos, indirectos, incidentales, especiales, consecuentes o punitivos que puedan derivarse del uso o mal uso de esta herramienta, incluyendo pérdida de datos, interrupción de servicios o cualquier otro perjuicio.

Esta herramienta está destinada exclusivamente para **fines legales, éticos y con el debido consentimiento**. El uso para actividades maliciosas, invasión de privacidad, daño a sistemas o terceros está estrictamente prohibido y puede ser ilegal.

Siempre se recomienda realizar pruebas en **entornos controlados y con autorización expresa** para evitar consecuencias legales y daños no deseados.

Al usar este proyecto, el usuario acepta estos términos y condiciones, eximiendo al desarrollador de cualquier responsabilidad.

**¡Usa esta herramienta responsablemente y con ética\!**

----- 