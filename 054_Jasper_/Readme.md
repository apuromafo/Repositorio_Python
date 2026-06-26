# Jasper CLI Suite v2.0

La **Jasper CLI Suite** es una herramienta de orquestación diseñada para la gestión, análisis de seguridad, compilación, descompilación y conversión de archivos de reportes JasperReports (`.jrxml` y `.jasper`).

Esta suite integra capacidades de **análisis estático de seguridad (SAST)** bajo estándares OWASP para identificar vulnerabilidades comunes en reportes dinámicos.

---

## 🛠 Módulos de la Suite

| Módulo | Archivo | Descripción |
| --- | --- | --- |
| **Orquestador** | `main.py` | Lanzador central interactivo para toda la suite. |
| **Análisis** | `analizar.py` | Auditoría de seguridad (SQLi, LFI, RCE, XXE, XSS) y extracción de metadatos. |
| **Conversión** | `convertir.py` | Conversión silenciosa de `.jasper` a PDF. |
| **Compilación** | `compilar.py` | Transformación de fuentes `.jrxml` a binarios `.jasper`. |
| **Descompilación** | `decompilar_v3.py` | Reconstrucción de `.jrxml` a partir de `.jasper` con auditoría integrada. |

---

## 🚀 Requisitos Previos

* **Python 3.x**
* **JDK (Java Development Kit)** instalado y configurado en el PATH (necesario para el puente de compilación/descompilación).
* **Librerías:** Asegúrate de tener instaladas las dependencias necesarias, incluyendo `pyreportjasper`.

---

## 📋 Guía de Uso

Puedes ejecutar cada herramienta de forma independiente o a través del orquestador `main.py`.

### 1. Orquestador Central

Para una experiencia interactiva guiada:

```bash
python main.py

```

### 2. Análisis de Seguridad

Analiza archivos o directorios completos para detectar vulnerabilidades:

```bash
python analizar.py -a archivo.jrxml
python analizar.py -f ./carpeta_reportes/

```

### 3. Compilación

Convierte tus fuentes a formato ejecutable:

```bash
python compilar.py -f ./src/ -o ./bin/

```

### 4. Descompilación y Auditoría

Reconstruye archivos `.jrxml` desde binarios y genera reportes de auditoría:

```bash
python decompilar_v3.py -f ./bin/ -o ./reconstruidos/

```

### 5. Conversión a PDF

Genera documentos PDF de forma silenciosa (sin logs de consola):

```bash
python convertir.py -a reporte.jasper -o ./pdf_final/

```

---

## 🛡 Capacidades de Auditoría (OWASP)

El motor de análisis incluido detecta automáticamente:

* **Inyecciones:** SQL Injection (`$P!{}`), LFI/RFI en imágenes dinámicas.
* **Ejecución de Código:** Detección de clases peligrosas (`Runtime`, `ProcessBuilder`).
* **Seguridad XML:** Detección de posibles ataques XXE.
* **Calidad de Código:** Detección de deuda técnica, tipado débil (`java.lang.Object`) y obsolescencia.

---

## 📜 Historial de Versiones

* **v2.0.0 (2026-05-20):**
* Estandarización total de módulos y flujos de ejecución.
* Optimización de subprocesos con soporte UTF-8 nativo.
* Integración profunda del motor de auditoría en procesos de descompilación.


* **v1.0.0 (2025-09-15):** Lanzamiento inicial de la suite.

---

*Desarrollado para entornos de auditoría y pentesting de reportes Jasper.*

## ⚠️ Aviso Legal / Legal Notice

Esta herramienta es unicamente para fines educativos y de auditoria de seguridad autorizada. El uso no autorizado contra sistemas sin el consentimiento explicito del propietario es ilegal. El usuario asume toda responsabilidad por el uso indebido.

This tool is for educational and authorized security auditing purposes only. Unauthorized use against systems without the owner's explicit consent is illegal. The user assumes all responsibility for misuse.
