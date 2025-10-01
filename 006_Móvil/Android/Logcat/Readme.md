 

# README del Script de Logcat para Auditoría (`logcat_filter.py`)

Este script (`logcat_filter.py`) es una herramienta de **línea de comandos** diseñada para simplificar y automatizar la captura de logs de **ADB Logcat**, enfocándose en una aplicación específica. Está optimizado para **auditoría y depuración** al aplicar automáticamente filtros de nivel (`Info`+) y organizar la salida en archivos separados por severidad.

## 🚀 Características Clave (Afin al Script)

  * **Enfoque en la App:** Prioriza la captura de logs para una aplicación específica, ya sea mediante el nombre del paquete como argumento, la **detección automática de la app en primer plano**, o la selección de una lista filtrada de apps de usuario.
  * **Filtro de Nivel Hardcodeado:** Aplica un filtro de nivel **`I` (Info)** por defecto (mostrando Info, Warning, Error, y Fatal) para reducir el ruido del log del sistema.
  * **Selección de Dispositivo Asistida:** Detecta múltiples dispositivos conectados y permite la **selección interactiva** o mediante el argumento `--device`.
  * **Detección Inteligente de Paquetes:** Intenta obtener el paquete en primer plano (*Foreground App*). Si falla, ofrece un menú de **aplicaciones de usuario filtradas** (excluyendo la mayoría de los paquetes de Google/AOSP).
  * **Output Estructurado y Persistente:** Crea un directorio de sesión único y guarda los logs en archivos separados por nivel de severidad (e.g., `error.log`, `info.log`).
  * **Visualización Mejorada:** Muestra los logs en la consola con **coloración por nivel**, **contador de líneas** y **tiempo relativo** desde el inicio de la sesión.

-----

## 🛠 Requisitos Previos

  * **ADB (Android Debug Bridge):** Debe estar instalado y accesible en el `PATH` del sistema.
  * **Python 3:** El script está escrito en Python 3.
  * **`colorama`:** Una biblioteca para manejar colores en la consola.

### Instalación de dependencias:

```bash
pip install colorama
```

-----

## 💻 Uso del Script

El script funciona principalmente mediante argumentos de línea de comandos.

### 1\. Detección Automática (Modo por Defecto)

Ejecuta el script sin argumentos. Intentará **detectar la aplicación en primer plano** y usar su nombre de paquete como filtro. Si la detección falla, te preguntará el paquete o te permitirá seleccionarlo de una lista.

```bash
./logcat_filter.py
```

### 2\. Filtrado por Paquete Específico

Proporciona el nombre del paquete directamente como argumento posicional.

```bash
./logcat_filter.py com.nombre.paquete
```

### 3\. Uso de un Dispositivo Específico

Si tienes varios dispositivos conectados, usa el argumento `-d` o `--device` con el número de serie.

```bash
./logcat_filter.py -d 12345ABCDE
./logcat_filter.py com.nombre.paquete --device 12345ABCDE
```

### Flujo de Ejecución

1.  El script selecciona o te pide que selecciones un dispositivo.
2.  Muestra información detallada del dispositivo.
3.  Determina el paquete a auditar (argumento, detección automática o selección manual).
4.  Crea la carpeta de logs con formato: `paquete-modelo-(Android_VXXX)_YYYYMMDD_HHMMSS`.
5.  **Limpia el buffer de logcat** (`adb logcat -c`).
6.  Comienza la captura, mostrando el *output* filtrado y coloreado en la consola.
7.  Presiona **`Ctrl+C`** para detener la sesión. Todos los logs se cerrarán y se guardarán de forma segura en el directorio creado.

-----

## 📁 Estructura del Output

Todos los logs se guardan dentro del directorio `log_sessions/` en una carpeta de sesión descriptiva.

| Archivo de Log | Contenido Guardado |
| :--- | :--- |
| `fatal.log` | Logs de nivel **F** |
| `error.log` | Logs de nivel **E** (y **F**) |
| `warning.log` | Logs de nivel **W** |
| `info.log` | Logs de nivel **I** |
| `debug.log` | Logs de nivel **D** |
| `verbose.log` | Logs de nivel **V** |

-----

> **Nota Técnica:** El script utiliza el formato `logcat -v brief` y realiza el filtrado de nivel mínimo (`I`) y por paquete **internamente en Python** para un control más preciso y una mejor experiencia de usuario en la consola.