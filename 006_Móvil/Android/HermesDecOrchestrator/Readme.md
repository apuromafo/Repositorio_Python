# 🔮 HermesDecOrchestrator - Herramienta de Automatización y Descompilación de Hermes

Herramienta en **Python** diseñada para automatizar el proceso de descompilación de archivos de *bytecode* de **Hermes** (utilizados por React Native). Este *script* simplifica la gestión de dependencias, el entorno virtual y la ejecución del descompilador de manera interactiva.

-----

## 🛑 Aviso Legal y Descargo de Responsabilidad

  * **Propósito:** Este *script* es una herramienta de automatización desarrollada para fines de **investigación de seguridad** y **análisis de código propio**.
  * **Uso Ético:** El usuario es el **único responsable** de asegurar que tiene el permiso expreso y legal para acceder y descompilar el archivo de destino. El uso de esta herramienta en sistemas o aplicaciones de terceros sin autorización explícita está estrictamente prohibido y puede ser ilegal.
  * **Dependencia:** Esta herramienta funciona como un *wrapper* o orquestador para el repositorio y la utilidad [**hermes-dec de P1sec**](https://github.com/P1sec/hermes-dec), y no contiene la lógica de descompilación en sí misma.

-----

## ✨ Características Principales

  * **Automatización Completa:** Clona, gestiona y actualiza automáticamente el repositorio de `hermes-dec`.
  * **Aislamiento de Entorno:** Ofrece la opción recomendada de instalar las dependencias dentro de un **Entorno Virtual (`venv`)** para evitar conflictos con el entorno principal del sistema.
  * **Menú Interactivo:** Permite elegir entre instalación en entorno virtual o en el *host*.
  * **Gestión de Archivos de Entrada:** Soporta tres métodos de entrada para el archivo `.bundle`:
      * Argumento directo en la línea de comandos (`python script.py ruta/archivo.bundle`).
      * Uso de un archivo predefinido (`DEFAULT_BUNDLE_FILE`).
      * Ingreso manual de la ruta por el usuario.
  * **Compatibilidad:** Diseñado para funcionar en plataformas **Windows** y sistemas basados en **Unix (Linux/macOS)**, asumiendo que `git` y `pip` están instalados.

-----

## 🚀 Uso e Instalación

### Requisitos Previos

Necesitas tener instalados los siguientes comandos en tu sistema:

  * **Git**
  * **Python 3**
  * **Pip**

### Ejecución

El *script* puede ejecutarse con o sin un argumento de línea de comandos para especificar el archivo de entrada.

**A. Ejecución con archivo de entrada directo:**

```bash
python3 orquestador.py /ruta/al/archivo/mi_app.bundle
```

**B. Ejecución interactiva (sin argumento):**

```bash
python3 orquestador.py
```

Al ejecutarlo, el *script* te presentará un menú interactivo:

| Opción | Descripción | Recomendación |
| :--- | :--- | :--- |
| **1** | Descompilar con Entorno Virtual. | **Recomendado** para mantener el sistema limpio. |
| **2** | Descompilar directamente en el Host. | Requiere permisos y puede interferir con otras librerías. |
| **3** | Salir | Terminar la ejecución. |

El archivo descompilado final se guardará como `decompiled_output.js` en el directorio raíz.

-----

## 📜 Historial de Versiones

| Versión | Fecha | Estado | Cambios/Notas |
| :--- | :--- | :--- | :--- |
| **v1.3.1** | 2025-09-23 | ESTABLE | ✅ Corregido: Error de 'FileNotFound' causado por comillas dobles y espacios en la ruta de entrada. ✅ Mejorado: La función de entrada de archivo ahora limpia automáticamente la cadena. |
| **v1.3.0** | 2025-09-23 | | ✅ Añadido: Argumento de línea de comandos para especificar el archivo de entrada. ✅ Añadido: Opción interactiva para procesar un archivo de entrada o ingresar una ruta personalizada. ✅ Añadido: Soporte para rutas de archivos relativas o absolutas. |
| **v1.2.0** | 2025-09-23 | ESTABLE | ✅ Añadido: Control de versiones detallado en la cabecera. ✅ Corregido: Error "fatal: not a git repository". El script ahora clona si no existe y actualiza si ya existe. |
| **v1.1.0** | 2025-09-23 | | ✅ Añadido: Menú interactivo con opciones para entorno virtual o host. ✅ Añadido: Opción para personalizar el nombre del entorno virtual. ✅ Ajustado: Lógica de instalación para trabajar en Windows (sin sudo) y con pip. |
| **v1.0.0** | 2025-09-23 | LANZAMIENTO | ✅ Funcionalidad completa para Windows 11. ✅ Automatizado: clonación del repositorio, instalación de dependencias, y descompilación. ✅ Configuración: usa un nombre de archivo de entrada y salida personalizado. |
| **v0.5.0** | 2025-09-23 | | ✅ Prototipo inicial de descompilación. ✅ Lógica de ejecución del descompilador de Hermes a través de Python. ❌ No maneja control de versiones. |
| **v0.1.0** | 2025-09-23 | INICIO | ✅ Creación del script inicial. ✅ Estructura básica de funciones. |