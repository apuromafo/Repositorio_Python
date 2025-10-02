# 🛡️ Escáner de Patrones - Proyecto Modular

## Descripción

**Escáner de Patrones** es una herramienta modular desarrollada en Python para realizar **análisis estático** de archivos y carpetas en busca de patrones definidos a través de expresiones regulares. Incorpora funcionalidades avanzadas como:

* **Lectura y compilación** de patrones configurables por categoría (sensibles e informativos).
* **Escaneo recursivo** de archivos y carpetas, con detección inteligente de archivos binarios y manejo de tamaños.
* **Extracción y presentación detallada de metadatos** de archivos, incluyendo permisos simbólicos y octales, hashes SHA256, tipo MIME, resolución de imágenes y más.
* **Generación organizada de reportes y hallazgos**, con separación clara entre hallazgos sensibles e informativos.
* **Registro robusto de logs** con rotación y estadísticas.
* Soporte para **impresiones coloreadas** en consola para mejor legibilidad.
* Uso **opcional y condicional** de librerías como Pillow para metadatos imagen sólo si están instaladas.

---

## Estructura del Proyecto

```

/
├── main.py                 \# Archivo principal, punto de entrada
├── scripts/                \# Carpeta con módulos principales
│   ├── configuracion.py    \# Manejo de configuración
│   ├── logger\_manager.py   \# Gestión de logs y reportes
│   ├── patrones.py         \# Carga y compilación de patrones
│   ├── escaneo.py          \# Funciones principales de escaneo
│   ├── metadatos.py        \# Extracción avanzada de metadatos de archivos
│   ├── utilidades.py       \# Funciones utilitarias y de apoyo
│   └── init.py             \# Paquete Python para scripts
├── Pattern/                \# Carpeta con patrones y configuraciones
│   ├── config.json         \# Archivo de configuración de patrones y opciones
│   ├── suggestions.json    \# Recomendaciones para tipos de archivos específicos
│   └── \*.json              \# Archivos con patrones de expresiones regulares
└── README.md               \# Documentación del proyecto (este archivo)

````

---

## Instalación y Requisitos

* **Python 3.8 o superior**

* **Recomendado:** instalar las siguientes librerías opcionales para enriquecer funcionalidad:
    * `chardet` para detección de encoding de texto (`pip install chardet`)
    * `Pillow` para extracción de resolución en imágenes (`pip install pillow`)
    * `ffprobe` (de FFmpeg) debe estar instalado y accesible en PATH para obtener duración de audio/video

---

## Uso Básico

Ejecutar el script principal:

```bash
python main.py
````

Se mostrará un **menú interactivo** para:

  * Escanear archivos individuales o carpetas completas recursivamente.
  * Elegir si reportar patrones sensibles, informativos o ambos.
  * Observar reportes detallados en consola y generar archivos con hallazgos y métricas.

-----

## Línea de Comandos y Parámetros

Actualmente, el escáner funciona con menú interactivo. En futuras versiones se planea incorporar argumentos **CLI** para automatización.

-----

## Resultados y Reportes

  * La carpeta `Scan_Reports/YYYY-MM-DD/` contiene logs, hallazgos y estadísticas ordenadas por fecha y hora.
  * **Hallazgos sensibles e informativos** se guardan en archivos separados para cada archivo escaneado, con nombres que incluyen *timestamp* para evitar solapamientos.
  * **Estadísticas consolidadas** muestran resumen del análisis: archivos procesados, omitidos, hallazgos, líneas analizadas y errores.

-----

## Buenas Prácticas y Lineamientos

  * Mantener actualizados los patrones JSON en la carpeta `Pattern/`.
  * Revisar y actualizar `config.json` para ajustar tamaños máximos, extensiones excluidas y niveles de verbosidad.
  * Para análisis de multimedia e imágenes, asegurarse de tener instalados los requerimientos opcionales.
  * Ejecutar escaneos en entornos que no modifiquen archivos abiertos para asegurar integridad de *hashes* y metadatos.
  * Revisar cuidadosamente los **hallazgos sensibles** para priorizar mitigaciones.
  * Generar reportes en ambientes controlados para evitar exposición accidental de datos sensibles.

-----

## Futuras Mejoras

  * Implementar **línea de comandos** para integración automática.
  * Añadir **paralelización** para acelerar escaneos de carpetas grandes.
  * Agregar interfaz gráfica o web para exploración interactiva de resultados.
  * Incorporar más formatos específicos (**PDF, Office, binarios**) para extracción de metadatos especializados.
  * Añadir comparaciones históricas y detección de modificaciones.

-----

## Disclaimer / Descargo de Responsabilidad

Este proyecto y sus herramientas asociadas se proporcionan **"tal cual"**, sin garantías de ningún tipo, ya sean expresas o implícitas, incluidas pero no limitadas a las garantías de comerciabilidad, idoneidad para un propósito particular o no infracción.

El uso de esta herramienta es bajo la **exclusiva responsabilidad del usuario**. El desarrollador no se responsabiliza por daños directos, indirectos, incidentales, especiales, consecuentes o punitivos que puedan derivarse del uso o mal uso de esta herramienta, incluyendo pérdida de datos, interrupción de servicios o cualquier otro perjuicio.

Esta herramienta está destinada exclusivamente para **fines legales, éticos y con el debido consentimiento**. El uso para actividades maliciosas, invasión de privacidad, daño a sistemas o terceros está estrictamente prohibido y puede ser ilegal.

Siempre se recomienda realizar pruebas en **entornos controlados y con autorización expresa** para evitar consecuencias legales y daños no deseados.

Al usar este proyecto, el usuario acepta estos términos y condiciones, eximiendo al desarrollador de cualquier responsabilidad.

**¡Usa esta herramienta responsablemente y con ética\!**

----- 