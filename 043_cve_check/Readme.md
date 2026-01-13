-----

### 🛡️ NVD CVE Downloader

**`cve_downloader.py`** es un script de Python interactivo diseñado para descargar y almacenar datos de vulnerabilidades **CVE (Common Vulnerabilities and Exposures)** directamente desde la API oficial de la Base de Datos Nacional de Vulnerabilidades (NVD) de NIST.

Esta herramienta es perfecta para investigadores, profesionales de la ciberseguridad o desarrolladores que necesitan una forma rápida y sencilla de consultar y archivar datos de vulnerabilidad por fecha de publicación.

### ✨ Características

  * **Descarga por Rango de Fechas**: Permite descargar CVEs por un mes específico o por un rango de meses (ej. todo un año), evitando la necesidad de descargar bases de datos completas.
  * **Gestión de Archivos**: Almacena los datos descargados en una estructura de carpetas (`cve_data/año/mes.txt`), lo que facilita la organización y el acceso a la información.
  * **Modo Interactivo**: Ofrece un menú de consola simple y amigable para que el usuario navegue y elija qué acción realizar.
  * **Manejo de Errores**: Incluye un control de errores para la conexión a la API y para la manipulación de archivos.
  * **Control de `rate-limit`**: Incluye una pausa entre descargas para evitar exceder el límite de peticiones de la API de NVD.
  * **Información Clave**: Cada archivo de salida contiene información crucial sobre la vulnerabilidad, incluyendo:
      * ID del CVE.
      * Descripción en inglés.
      * Puntuación y severidad **CVSS**.
      * URL oficial en la página de NVD.

-----

### 🚀 Requisitos e Instalación

Este script requiere la librería `requests`.

1.  Asegúrate de tener **Python 3.x** instalado.
2.  Instala la dependencia necesaria con `pip`:
    ```bash
    pip install requests
    ```

-----

### 📖 Uso

Simplemente ejecuta el script desde tu terminal:

```bash
python cve_downloader.py
```

El programa te presentará un menú interactivo con las siguientes opciones:

1.  **Descargar CVEs por mes**: Ingresa el año y el mes para descargar los datos de ese período.
2.  **Descargar rango de meses**: Ingresa el año y el mes de inicio y fin para descargar todos los datos en ese rango.
3.  **Listar meses disponibles localmente**: Muestra todos los archivos de CVE que ya has descargado y están en la carpeta `cve_data`.
4.  **Mostrar CVEs de un mes**: Lee y muestra en la consola el contenido de un archivo de CVE descargado.
5.  **Salir**: Finaliza el script.

### 📁 Estructura de Archivos

Al ejecutar el script, se creará una estructura de directorios para almacenar los datos descargados de forma organizada:

```
.
└── cve_downloader.py
└── cve_data/
    ├── 2024/
    │   ├── 01.txt
    │   ├── 02.txt
    │   └── ...
    └── 2025/
        ├── 01.txt
        └── ...
```

Cada archivo `.txt` contiene un listado de CVEs en formato de texto plano, fácil de leer y de procesar.