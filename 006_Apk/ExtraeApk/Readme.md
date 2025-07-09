# Herramienta de Extracción de APKs

Este script automatiza la extracción de archivos APK (Android Package Kit) desde un dispositivo Android conectado a tu computadora.  Utiliza ADB (Android Debug Bridge) para comunicarse con el dispositivo y realizar las operaciones necesarias.

## Características Principales

*   **Selección de Dispositivo:** Identifica automáticamente los dispositivos Android conectados y te permite seleccionar uno por su serial o Transport ID.
*   **Listado de Aplicaciones:** Muestra una lista de todas las aplicaciones instaladas en el dispositivo, permitiéndote buscar por nombre.
*   **Extracción de APKs:** Extrae archivos APK específicos para un paquete dado a un directorio local, organizando los archivos en subcarpetas nombradas según el paquete.
*   **Manejo de Errores:**  Incluye manejo robusto de errores, como la falta del comando ADB o problemas al comunicarse con el dispositivo.

## Requisitos Previos

*   **Android SDK Platform-Tools:** Debes tener instalado el Android SDK Platform-Tools en tu sistema. Esto incluye el comando `adb`. Asegúrate de que la carpeta donde se encuentra `adb` esté en tu variable de entorno PATH para poder ejecutarlo desde cualquier directorio.
*   **Dispositivo Android:** Un dispositivo Android conectado a tu computadora y autorizado para depuración USB.  Debes habilitar la depuración USB en las opciones de desarrollador del dispositivo.

## Uso

1.  **Guarda el Script:** Guarda el script como un archivo `.py` (por ejemplo, `extract_apks.py`).
2.  **Ejecuta el Script:** Abre una terminal o línea de comandos y navega hasta el directorio donde guardaste el script. Ejecuta el script usando:

    ```bash
    python extract_apks.py
    ```
3.  **Sigue las Instrucciones:** El script te guiará a través del proceso, solicitando que selecciones un dispositivo (si tienes varios conectados) y luego te preguntará si quieres buscar una aplicación por nombre o extraer todos los APKs de una aplicación específica.

## Parámetros y Opciones

*   **Selección de Dispositivo:** El script intentará detectar automáticamente tu dispositivo Android.  Si tienes múltiples dispositivos, se mostrarán en la lista. Puedes seleccionar uno por su serial (identificador único) o Transport ID.
*   **Búsqueda de Aplicaciones:** Puedes ingresar una palabra clave para buscar aplicaciones instaladas que contengan esa palabra clave en su nombre.
*   **Extracción de APKs:** Una vez que hayas seleccionado un paquete de aplicación, el script extraerá todos los archivos APK asociados a ese paquete y los guardará en un directorio local llamado `APKs_[nombre_paquete]`.

## Términos Técnicos y Abreviaturas

*   **ADB (Android Debug Bridge):**  Una herramienta de línea de comandos que te permite comunicarte con un dispositivo Android.
*   **APK (Android Package Kit):** El formato de archivo utilizado para distribuir aplicaciones en Android.
*   **Serial:** Un identificador único asignado a cada dispositivo Android.
*   **Transport ID:** Un identificador que representa la conexión entre tu computadora y el dispositivo Android.  Puede ser el serial o un identificador específico del transport (por ejemplo, Bluetooth).
*   **pm (Package Manager):** Una herramienta de línea de comandos en Android para administrar paquetes de aplicaciones.
*   **shell:**  Un entorno de ejecución de comandos en un sistema operativo, en este caso, en el dispositivo Android.
*   **pull:** Un comando ADB que copia archivos desde un dispositivo a tu computadora.

## Notas Adicionales

*   Asegúrate de tener los permisos necesarios para acceder al dispositivo Android (depuración USB habilitada).
*   Si tienes problemas para ejecutar el script, verifica que `adb` esté correctamente instalado y en tu PATH.
*   El script está diseñado para ser utilizado con dispositivos Android que admiten depuración USB.

