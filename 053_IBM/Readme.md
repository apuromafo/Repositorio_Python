# IBM i Unified Auditor (v20.6.0-final) 🚀

## 📜 Descripción General

**IBM i Unified Auditor** es una suite unificada avanzada de análisis estático y auditoría de seguridad diseñada para entornos **IBM i / AS400**. Permite escanear de manera masiva, automatizada e inteligente código fuente desarrollado en **RPG (clásico y Free-form), SQL, DB, CLP (Control Language), PF (Physical Files), LF (Logical Files) y DSPF (Display Files)**.

A diferencia de las versiones previas de la suite (que requerían un flujo secuencial en dos pasos separados `step1` y `step2`), esta versión integra el **análisis de calidad de código** y el **motor de detección de vulnerabilidades** en una única ejecución optimizada.

El script opera de manera **totalmente segura**: es estrictamente de **solo lectura**, garantizando la integridad de los archivos analizados sin alterar el código original.

---

## ✨ Características Principales

* **Análisis Multilenguaje Integrado:** Soporte extendido con diccionarios semánticos avanzados para comandos CL, tokens RPG (incluyendo instrucciones embebidas `EXEC SQL`), sentencias lógicas SQL y layouts de pantallas/archivos.
* **Doble Motor de Detección de Seguridad:**
    * **Motor A (Patrones de Seguridad Críticos):** Identifica vulnerabilidades alineadas con los estándares **CWE** y **OWASP Top 10** (Inyección de comandos vía `QCMDEXC`, elevación de privilegios `USRPRF(*OWNER)`, contraseñas e IPs hardcodeadas, manipulación indebida de `*LIBL`, configuraciones de `DEBUG` activas, entre otros).
    * **Motor B (Fugas en Comentarios):** Escanea metadatos, notas de desarrollo y marcadores técnicos (`TODO`, `FIXME`, `HACK`) que puedan exponer involuntariamente credenciales, rutas del IFS (`/QSYS.LIB`) o variables críticas.
* **Mapeo de Arquitectura e Información:** Identifica llamadas a programas externos (`CALL`), accesos a colas de mensajería (`SNDPGMMSG`), APIs del sistema y flujos de datos (`CPYF`, `OVRDBF`) para generar un mapa técnico del entorno.
* **Robustez de Codificación:** Integración opcional con la librería `chardet` para detectar de forma automática el *encoding* de los miembros fuente y procesarlos sin interrupciones por caracteres inválidos.
* **Reportabilidad Centralizada:** Genera en un solo ciclo un artefacto estructurado JSON consolidado (ideal para integraciones DevSecOps) y un Reporte Master en formato Markdown listo para auditoría.

---

## 🛠️ Requisitos del Sistema

* **Entorno:** Python 3.x instalado en el sistema de ejecución.
* **Dependencias Opcionales (Recomendado):**
    ```bash
    pip install chardet
    ```
    *Nota: Si `chardet` no está presente, el script utilizará un mecanismo nativo de respaldo para la lectura de archivos.*

---

## 🚀 Modo de Uso y Parámetros

El script se ejecuta a través de la interfaz de línea de comandos (CLI) utilizando `argparse`. Soporta el escaneo tanto de archivos individuales como de directorios completos de forma recursiva.

### Estructura del Comando
```bash
python ibm_i_unified_auditor_v20_6.py -t <ruta_objetivo> [opciones]

```

### Argumentos Disponibles:

* `-t`, `--target` *(Obligatorio)*: Ruta del archivo o directorio que se desea auditar.
* `-o`, `--outdir` *(Opcional)*: Directorio donde se guardarán los reportes resultantes (Por defecto: `./OUTPUT_AUDIT_IBM`).
* `-r`, `--recursive` *(Opcional / Flag)*: Si se proporciona y el objetivo es una carpeta, el escáner analizará de forma recursiva todas las subcarpetas.

### Ejemplos Prácticos de Ejecución:

1. **Analizar un Directorio Completo (Recursivo):**
```bash
python ibm_i_unified_auditor_v20_6.py -t ./fuentes_as400 -r

```


2. **Analizar un Archivo Fuente Individual:**
```bash
python ibm_i_unified_auditor_v20_6.py -t ./fuentes_as400/QCLSRC/PROG01.clp

```


3. **Especificar un Directorio de Salida Personalizado:**
```bash
python ibm_i_unified_auditor_v20_6.py -t ./fuentes_as400 -o ./reportes_2026 -r

```



---

## 📊 Artefactos Generados (Entregables)

Al finalizar la auditoría, el script crea una subcarpeta estructurada según la marca de tiempo de la ejecución (`YYYYMMDD_HHMMSS`) conteniendo dos archivos fundamentales:

1. **JSON Consolidado (`FINDINGS_AUDITORIA_IBM_*.json`):**
Contiene el payload estructurado con estadísticas del escaneo, hash SHA-256 de cada archivo analizado, líneas totales, codificación detectada y el listado indexado de hallazgos clasificados por criticidad (**Alta, Media, Baja**) adjuntando su correspondiente mitigación, regla CWE y OWASP. Ideal para su ingesta en páneles SIEM o dashboards de seguridad.
2. **Reporte Master (`REPORTE_MASTER_IBM_*.md`):**
Un informe ejecutivo y técnico en formato Markdown amigable para lectura humana, que condensa las métricas globales, el resumen de criticidades y el desglose detallado línea por línea de cada vector de riesgo descubierto.

---

## 🔒 Reglas de Seguridad Soportadas (Muestra)

| Código de Regla | Criticidad | Descripción | Estándar Asociado |
| --- | --- | --- | --- |
| `COMMAND_INJECTION_QCMDEXC` | **Alta** | Uso dinámico de la API QCMDEXC con concatenación de variables. | CWE-78 / OWASP A03 |
| `ADOPT_AUTHORITY_POTENTIAL` | **Alta** | Uso de la directiva `USRPRF(*OWNER)` con riesgo de elevación de privilegios. | CWE-250 / OWASP A04 |
| `HARDCODED_PASSWORDS` | **Alta** | Credenciales, llaves de servicio o tokens expuestos estáticamente. | CWE-798 / OWASP A07 |
| `SECURITY_DOWNGRADE_SYSVAL` | **Alta** | Alteración o intento de degradación de valores críticos del sistema (`QSECURITY`). | CWE-284 / OWASP A05 |
| `LIBRARY_LIST_MANIPULATION` | **Media** | Modificaciones dinámicas en el `*LIBL` propensas a secuestro de librerías. | CWE-427 / OWASP A05 |
| `DUMP_STATEMENTS` | **Media** | Instrucciones de volcado de memoria técnica activos en entorno productivo. | CWE-215 / OWASP A05 |
| `TODO_FIXME_SENSITIVE` | **Media** | Deuda técnica en comentarios que mencionan credenciales o llaves. | CWE-532 / OWASP A09 |
| `BLIND_MONMSG` | **Baja** | Monitoreo ciego de excepciones con `CPF0000` que silencia fallos. | CWE-391 / OWASP A09 |

---

## ⚖️ Descargo de Responsabilidad (Disclaimer)

Este proyecto y sus herramientas asociadas se proporcionan **"tal cual"**, sin garantías de ningún tipo explicitas o implícitas.

El uso de esta herramienta se realiza bajo la **exclusiva responsabilidad del usuario**. El desarrollador no se responsabiliza por daños directos, indirectos, incidentales o consecuentes que puedan derivarse del uso o mal uso de este software. Esta herramienta está destinada exclusivamente para **fines auditoría legal, ética y con el debido consentimiento explícito** sobre los códigos examinados. El uso para actividades maliciosas o sin autorización está estrictamente prohibido.

 