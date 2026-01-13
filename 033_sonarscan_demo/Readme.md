
# 🛡️ Orquestador de Análisis SonarQube (v1.0.0)

Este conjunto de scripts tiene como objetivo **simplificar y automatizar** el proceso de preparación del entorno, descarga de dependencias y generación de reportes de análisis de código utilizando **SonarQube** y la herramienta **SonarScanner**.

El corazón del proyecto es el script **`00_Main.py`**, que proporciona un **menú interactivo** para ejecutar cada etapa de forma controlada o lanzar la secuencia completa.

## ⚙️ Requisitos

Asegúrese de tener instalados y configurados los siguientes requisitos:

  * **Python 3.x:** (Recomendado 3.8 o superior).
  * **Java JRE/JDK:** Necesario para ejecutar el SonarScanner y el generador de reportes (CNES JAR).
  * **Módulos de Python:**
    ```bash
    pip install requests
    ```

-----

## 🚀 Guía de Inicio Rápido

Ejecute el script principal para acceder al menú interactivo:

```bash
python 00_Main.py
```

### Opciones del Menú

| Opción | Script | Descripción |
| :---: | :--- | :--- |
| **1** | `01_config.ini.py` | Sincroniza la URL y el Token de `config.ini` con `sonar-project.properties`. |
| **2** | `02_validate_env.py` | Valida si la ruta de SonarScanner está en la variable de entorno **PATH**. |
| **3** | `03_download_scanner.py` | Descarga, descomprime y sugiere agregar el último **SonarScanner** al PATH. |
| **4** | `04_validate_sonarscan.py` | Verifica la conectividad al servidor SonarQube (API) y el ejecutable del Scanner (`-v`). |
| **5** | `05_download_cnes_report.py` | Descarga y/o valida la versión más reciente del JAR de reporte **CNES**. |
| **6** | `06_genera_nombre.py` | **Genera comandos de análisis** (Key, Name, comandos `sonar-scanner`, `mvn`, etc.) de forma interactiva. |
| **7** | `07_reporte.py` | **Genera el reporte** final de SonarQube, aceptando argumentos. |
| **8** | **Secuencia Completa** | Ejecuta los Pasos **1, 2, 3, 4, 5 y 7** automáticamente. |
| **0** | **Salir** | Finaliza el Orquestador. |

-----

## 📝 Uso de la Secuencia Completa (Paso 8)

El Paso 8 ejecuta los pasos de preparación y culmina en la generación del reporte (Paso 7). Para que el **Paso 7** funcione correctamente dentro de la secuencia, requiere argumentos.

Usted puede pasar los argumentos para el reporte **al iniciar el `00_Main.py`**:

### Opción 1: Reporte con Proyecto y Salida

Esta es la forma estándar para un reporte normal:

```bash
python 00_Main.py -p <CLAVE_PROYECTO> -o <RUTA_DE_SALIDA>
# Ejemplo:
python 00_Main.py -p 'BUG-4501' -o 'reportes/analisis_nov'
```

### Opción 2: Reporte Comprimido (ZIP)

Esta opción comprime el reporte en un archivo ZIP con el nombre especificado, simplificando el proceso:

```bash
python 00_Main.py -r <NOMBRE_DEL_REPORTE_ZIP>
# Ejemplo:
python 00_Main.py -r 'Reporte_BUG-4501'
```

> **NOTA:** Si ejecuta el **Paso 7** individualmente o el **Paso 8 (Secuencia Completa)** sin haber proporcionado argumentos, el Orquestador le **preguntará interactivamente** para ingresar los valores necesarios (`-p`, `-o` o `-r`).

-----

## 🛠️ Descripción de los Scripts

### 1\. `01_config.ini.py` (Sincronización)

Asegura que los valores de `url` y `sonar.token` definidos en `config.ini` se apliquen estrictamente al archivo de configuración de escaneo (`sonar-project.properties`).

### 2\. `02_validate_env.py` (Validación de PATH)

Revisa si la variable de entorno **PATH** incluye una ruta al ejecutable de SonarScanner, lo cual es crucial para que el escáner sea invocable desde cualquier parte.

### 3\. `03_download_scanner.py` (Descarga de Scanner)

Descarga la versión más reciente de SonarScanner directamente desde GitHub, la descomprime y sugiere comandos para añadir su ruta al **PATH** del sistema operativo, si es necesario.

### 4\. `04_validate_sonarscan.py` (Verificación API y CLI)

  * **API:** Intenta conectar al servidor SonarQube usando la URL y el Token para verificar la conectividad.
  * **CLI:** Ejecuta `sonar-scanner -v` para confirmar que el ejecutable esté disponible y funcionando.

### 5\. `05_download_cnes_report.py` (Descarga de Reporte JAR)

Verifica la versión más reciente del generador de reportes CNES (`sonar-cnes-report-X.Y.Z.jar`) en GitHub. Si hay una versión más nueva, pregunta si desea descargarla y limpiar las versiones antiguas.

### 6\. `06_genera_nombre.py` (Generar Clave de Proyecto)

Este es un script **altamente interactivo** que guía al usuario para:

1.  Definir la **Clave de Proyecto** (`sonar.projectKey`) bajo la nomenclatura interna (ej. `BUG-XXXX`).
2.  Definir el **Nombre de Proyecto** (`sonar.projectName`).
3.  Generar y mostrar los comandos de escaneo completos (para Windows y Linux/Mac) para diferentes tecnologías (`mvn`, `gradle`, `sonar-scanner`).

### 7\. `07_reporte.py` (Generación de Reporte)

Utiliza el JAR de reporte CNES descargado en el Paso 5 para contactar al servidor SonarQube y generar un reporte en PDF/HTML/CSV/etc.

  * Requiere la **Clave del Proyecto** (`-p`) y la **Ruta de Salida** (`-o`), o bien, la opción de **Reporte Comprimido** (`-r`).

-----

## 💡 Flujo de Trabajo Recomendado

1.  **Configuración:** Ejecute el **Paso 1** para validar y sincronizar la configuración.
2.  **Preparación:** Ejecute la **Secuencia Completa (Paso 8)** sin argumentos para verificar si el entorno está listo (PATH, Scanner, JAR).
    ```bash
    python 00_Main.py 8
    ```
3.  **Generación de Comandos:** Ejecute el **Paso 6** para obtener la clave del proyecto y los comandos de escaneo.
    ```bash
    python 00_Main.py 6
    ```
4.  **Ejecución del Escaneo:** Ejecute el comando generado por el Paso 6 *fuera* del Orquestador (por ejemplo, en el directorio raíz de su proyecto).
5.  **Generación del Reporte:** Ejecute el **Paso 7** con los argumentos del proyecto que acaba de escanear.
    ```bash
    python 00_Main.py 7 -r 'Reporte_BUG-XXXX'
    ```