# README del Script de Logcat Interactivo

Este script proporciona una interfaz interactiva para capturar y analizar logs de aplicaciones Android en ejecución utilizando ADB (Android Debug Bridge).  Permite seleccionar dispositivos, aplicaciones, niveles de log y guardar los logs en un archivo.

## Características Principales

*   **Selección de Dispositivo:** El script busca automáticamente dispositivos Android conectados a través de ADB y permite al usuario seleccionar el dispositivo deseado.
*   **Selección de Aplicación:**  El script lista las aplicaciones instaladas en el dispositivo seleccionado y permite al usuario elegir la aplicación para la cual se capturarán los logs.
*   **Filtrado por Niveles de Log:** El usuario puede especificar los niveles de log que desea ver (Verbose, Debug, Info, Warning, Error).
*   **Captura Automática de Logs:**  El script puede lanzar automáticamente la aplicación seleccionada para iniciar la captura de logs.
*   **Guardado de Logs:** Los logs capturados se guardan en un archivo con un nombre basado en el nombre del paquete de la aplicación y la fecha/hora actual.
*   **Detección de Crashes:** El script detecta crashes dentro de la aplicación y muestra los detalles relevantes en la consola.
*   **Coloración de Logs:** Los logs se muestran coloreados según su nivel (Verbose, Debug, Info, Warning, Error) para facilitar la identificación visual.

## Requisitos Previos

*   **ADB (Android Debug Bridge):**  Debe estar instalado y configurado correctamente en tu sistema. Asegúrate de que ADB pueda comunicarse con tus dispositivos Android.
*   **Python 3:** El script está escrito en Python 3.
*   **colorama:**  Una biblioteca para colorear la salida en la consola (instalable con `pip install colorama`).

## Instalación y Ejecución

1.  Guarda el código como un archivo `.py` (por ejemplo, `logcat_interactive.py`).
2.  Asegúrate de que el archivo tenga permisos de ejecución: `chmod +x logcat_interactive.py`.
3.  Ejecuta el script desde la terminal: `./logcat_interactive.py`.

## Uso del Script

1.  **Iniciar Sesión:** El script iniciará un menú interactivo donde podrás seleccionar las opciones.
2.  **Seleccionar Dispositivo:** Selecciona el dispositivo Android conectado a través de ADB.
3.  **Seleccionar Aplicación:** Selecciona la aplicación para la cual deseas capturar los logs.
4.  **Configurar Niveles de Log (Opcional):** Elige los niveles de log que quieres ver. Por defecto, se muestran todos los niveles.
5.  **Lanzar Aplicación (Opcional):** Decide si quieres que el script lance automáticamente la aplicación seleccionada.
6.  **Captura de Logs:** El script comenzará a capturar los logs de la aplicación y los mostrará en la consola, coloreados según su nivel.
7.  **Detener Captura:** Presiona `Ctrl+C` para detener la captura de logs. Los logs se guardarán en un archivo.

## Parámetros y Opciones (Interfaz Interactiva)

*   **Niveles de Log:** Se permite seleccionar niveles de log individuales o todos los niveles.
*   **Lanzar Aplicación:**  Se pregunta al usuario si desea lanzar la aplicación automáticamente.
*   **Selección del Dispositivo:** El script busca y presenta una lista de dispositivos ADB disponibles.

## Variables Importantes

*   `__version__`: La versión actual del script (4.0.0).
*   `LOG_LEVELS`: Una cadena que define los niveles de log disponibles ("VDIWE").
*   `LOG_LEVELS_MAP`: Un diccionario que mapea las letras de los niveles de log a sus índices numéricos.

## Notas Técnicas

*   El script utiliza la biblioteca `subprocess` para ejecutar comandos ADB.
*   La biblioteca `colorama` se utiliza para colorear la salida en la consola, mejorando la legibilidad.
*   Se manejan excepciones (como `CalledProcessError`) para proporcionar mensajes de error más informativos.
*   El script incluye un mecanismo de espera para asegurar que la aplicación esté completamente iniciada antes de comenzar a capturar los logs.
