# 📦 Bundle Extractor Tool (Extractor de Bundles de APK)

Herramienta en **Python** diseñada para automatizar la extracción, identificación y análisis básico de archivos `index.bundle` (o variantes como `index.android.bundle`) contenidos dentro de archivos **APK** (paquetes de aplicaciones de Android).

Esencial para el *pentesting* y el **análisis estático** de aplicaciones móviles que utilizan *frameworks* basados en JavaScript (como React Native con el motor Hermes), ya que facilita el acceso al código fuente.

-----

## ✨ Características Principales

  * **Extracción Optimizada:** Copia el APK, lo trata como un archivo ZIP y lo descomprime en una **carpeta temporal específica**, ubicada junto al APK de entrada.
  * **Búsqueda Robusta:** Busca múltiples variantes de archivos *bundle* comunes dentro del directorio `assets/`.
  * **Información Detallada:** Calcula y muestra el **SHA-256** del APK y del *bundle* extraído, el tamaño legible de ambos archivos, y el **Magic Header** del *bundle* para identificar su formato (p. ej., *bytecode* de Hermes).
  * **Limpieza Automática:** Elimina automáticamente los archivos y directorios temporales (`.zip` y de extracción) al finalizar el proceso.
  * **Menú Interactivo:** Ofrece tres modos de operación al inicio:
      * **Extracción Completa:** Descomprime, busca, extrae y analiza el *bundle*.
      * **Escaneo Rápido:** Solo analiza el contenido del ZIP (APK) para buscar coincidencias, sin extraer.
      * **Análisis de Bundle Existente:** Analiza un archivo *bundle* previamente extraído (para obtener SHA-256 y *Magic Header*).

-----

## 🚀 Uso

### Requisitos

  * **Python 3.x**
  * **Dependencias:** Utiliza solo módulos estándar de Python (`pathlib`, `shutil`, `zipfile`, etc.).

### Ejecución

Ejecuta el *script* sin argumentos e ingresa tu elección en el menú interactivo:

```bash
python3 bundle_extractor.py
```

### Ejemplos de Entrada de Rutas:

Al ser requerido, ingresa la ruta del APK (o *bundle*) que deseas procesar:

```
# Ruta de un APK
📂 Ruta del APK: /home/user/app_debug.apk

# Ruta de un bundle existente
📂 Ruta del bundle: /home/user/index.android.bundle_extracted_20250923_123506.js
```

-----

## 📜 Historial de Versiones

| Versión | Fecha | Estado | Cambios/Notas |
| :--- | :--- | :--- | :--- |
| **v1.1.0** | 2025-09-23 | ESTABLE | ✅ Corregido: Creación de archivos temporales en el mismo directorio del APK de entrada. ✅ Mejorado: Lógica de limpieza de archivos temporales. ✅ Refactorizado: Nombres de funciones para mayor claridad. |
| **v1.0.0** | 2025-09-19 | INICIO | ✅ Primera versión para extraer *bundles* de APKs. ✅ Búsqueda y extracción de archivos *bundle*. ❌ Directorios temporales creados en la ubicación de ejecución (Corregido en v1.1.0). |

-----

## 🛑 Aviso Legal y Descargo de Responsabilidad

  * **Propósito:** Este *script* ha sido creado únicamente con fines de **investigación de seguridad** y **análisis estático** en entornos controlados y autorizados.
  * **Uso Ético y Legal:** El usuario es el **único responsable** de asegurar que tiene el permiso expreso y legal para escanear y analizar cualquier archivo APK. El uso de esta herramienta en aplicaciones de terceros sin autorización explícita está estrictamente prohibido y puede ser ilegal.
  * **Archivos Temporales:** El *script* copia el APK a un archivo ZIP temporal y lo descomprime. Aunque el proceso incluye una limpieza de archivos temporales, el usuario debe asegurarse de que la ubicación de la extracción es segura y controlada.
  * **Limitación:** La detección se basa en patrones de nombres de archivo comunes (`index.android.bundle`, `main.jsbundle`, etc.). Un APK que no contenga estos patrones podría no ser procesado correctamente.