# 🛠️ Jasper CLI: Herramienta de Análisis y Conversión de Reportes

-----

## 📄 Descripción del Proyecto

**Jasper CLI** es una herramienta de línea de comandos en **Python** diseñada para facilitar el análisis y la conversión de reportes de **JasperReports**. Es ideal para tareas de *pentesting*, desarrollo o simplemente para obtener un resumen rápido de los archivos de reporte.

El proyecto está compuesto por tres *scripts* principales:

  * `analisys.py`: Analiza archivos `.jrxml` y `.jasper`, extrayendo metadatos, textos, expresiones, consultas SQL e imágenes embebidas. Genera un *hash* SHA-256 para cada archivo.
  * `convertir.py`: Convierte archivos `.jasper` a PDF de manera silenciosa y eficiente.
  * `main.py`: Un lanzador principal que proporciona un **menú interactivo** para acceder a las funcionalidades de los otros *scripts*.

-----

## 🌟 Características Principales

### Analizador (`analisys.py`)

  * **Extracción de Metadatos**: Obtiene la versión de Jasper, el nombre del reporte, UUID, lenguaje, dimensiones de la página y más.
  * **Análisis de Contenido**: Detecta y lista textos estáticos, expresiones de campo y la consulta SQL embebida.
  * **Manejo de Imágenes**: Identifica y extrae imágenes embebidas en formato `base64`, guardándolas automáticamente en la carpeta `./imagenes_extraidas`.
  * **Hash de Archivos**: Calcula el *hash* **SHA-256** para cada archivo `.jrxml` o `.jasper` analizado.
  * **Soporte de Lotes**: Permite analizar archivos individuales o carpetas completas.

### Convertidor (`convertir.py`)

  * **Conversión Silenciosa**: Convierte `.jasper` a PDF sin mostrar los molestos mensajes de la **JVM** en la consola.
  * **Protección contra Sobrescritura**: Genera automáticamente un nombre de archivo único si el PDF de salida ya existe.
  * **Manejo de Lotes**: Convierte archivos individuales o todos los `.jasper` dentro de una carpeta.
  * **Información Detallada**: Muestra el progreso y el tiempo de conversión para cada archivo y un resumen final.

### Lanzador (`main.py`)

  * **Menú Interactivo**: Simplifica el uso del proyecto con un menú de opciones intuitivo.
  * **Registro de Acciones**: Opcionalmente, registra cada acción del usuario en un archivo de log llamado `launcher_actions.log`. Esta función puede ser activada o desactivada desde el menú.
  * **Configuración Persistente**: Guarda la configuración de *logging* en `config.json` para que persista entre sesiones.

-----

## ⚙️ Requisitos e Instalación

1.  **Requisitos de Python**: Asegúrate de tener **Python 3.x** instalado.

2.  **Librerías de Python**: Instala las dependencias necesarias con `pip`.

    ```bash
    pip install -r requirements.txt
    ```

    *Nota: `pyreportjasper` requiere que tengas la versión de **Java JRE o JDK** instalada y configurada en tu sistema. Se recomienda JRE 1.8 o superior.*

-----

## 🚀 Uso

El método recomendado es a través del lanzador principal `main.py`.

### Menú Principal (`main.py`)

Simplemente ejecuta el *script* y sigue las instrucciones del menú interactivo.

```bash
python main.py
```

El menú te guiará para elegir entre **analizar** archivos o **convertirlos**, y te pedirá las rutas necesarias.

### Uso Directo de Scripts

Si prefieres usar los *scripts* directamente, aquí tienes la sintaxis:

#### Analizar Archivos

```bash
# Analiza un solo archivo .jrxml
python analisys.py -a <ruta_al_archivo.jrxml>

# Analiza todos los archivos en una carpeta
python analisys.py -f <ruta_a_la_carpeta>

# Salida resumida (solo títulos e imágenes)
python analisys.py -a <ruta_al_archivo.jrxml> -i

# Guardar los resultados en un archivo JSON
python analisys.py -f <ruta_a_la_carpeta> -o salida.json
```

#### Convertir a PDF

```bash
# Convierte un solo archivo .jasper
python convertir.py -a <ruta_al_archivo.jasper>

# Convierte todos los archivos .jasper en una carpeta
python convertir.py -f <ruta_a_la_carpeta>

# Especifica una carpeta de salida diferente
python convertir.py -f <ruta_a_la_carpeta> -o <ruta_carpeta_salida>
```

-----

## 🚨 Aviso Legal y Descargo de Responsabilidad

  * **Propósito:** Este *script* ha sido creado únicamente con fines de **investigación de seguridad**, **auditoría interna** y **desarrollo** en entornos controlados y autorizados.
  * **Uso Ético y Legal:** El usuario es el **único responsable** de asegurar que tiene el permiso expreso y legal para acceder y analizar los archivos de JasperReports. El uso de esta herramienta en sistemas o archivos de terceros sin autorización explícita está estrictamente prohibido y puede ser ilegal.
  * **Limitación:** La conversión a PDF con `convertir.py` asume que el reporte no requiere de parámetros complejos o fuentes de datos específicas. En reportes complejos, la conversión silenciosa podría generar archivos vacíos o incompletos.