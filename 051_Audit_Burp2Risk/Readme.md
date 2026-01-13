# 🛡️ Burp2Risk - Clasificador de Riesgos de Endpoints

**Versión:** `v1.7.6`

Herramienta en **Python** diseñada para automatizar la clasificación de riesgo de los *endpoints* de una API/Aplicación Web basándose en **palabras clave** en sus rutas y en el contenido del cuerpo/parámetros de las peticiones. Es ideal para priorizar el *testing* de seguridad después de realizar un rastreo con herramientas como **Burp Suite**.



## ✨ Características Principales

  * **Clasificación Automática:** Asigna una puntuación de riesgo del **1 al 10** a cada *endpoint* detectado.
  * **Múltiples Fuentes de Entrada:** Soporta la ingesta de *endpoints* desde:
      * **XML de Burp Suite:** Lee volcados XML completos, decodifica peticiones y analiza la ruta, los parámetros y el cuerpo de la petición.
      * **JSON (OpenAPI/Swagger):** Procesa la estructura de rutas y parámetros de una especificación OpenAPI.
      * **TXT (Lista de URLs):** Analiza un archivo simple con URLs listadas línea por línea.
  * **Motor de Reglas Flexible:** Utiliza un sistema de **palabras clave** en español e inglés para categorizar el riesgo (Financiero, Alto, Medio, Bajo).
  * **Detección de Datos Sensibles:** Prioriza los *endpoints* que contienen términos sensibles (`password`, `token`, `credit_card`) en el cuerpo o los parámetros.
  * **Soporte IDOR:** Identifica patrones comunes de exposición de identificadores (`/recurso/ID`) o palabras clave relacionadas con ID sensibles.
  * **Salida Detallada:** Genera reportes en formato **CSV, JSON y TXT** que incluyen: URL, nivel de riesgo, la razón de la clasificación y sugerencias de mitigación.

-----

## 🚀 Uso e Instalación

### Requisitos

  * **Python 3.6+**
  * No se requieren dependencias externas.

### Ejecución

El *script* utiliza la librería estándar `argparse` para manejar los argumentos de la línea de comandos.

```bash
python3 burp_risk_classifier.py -f <archivo_fuente> -o <formato_salida> --order <orden_salida>
```

### Argumentos del Comando

| Argumento | Descripción | Opciones | Por defecto |
| :--- | :--- | :--- | :--- |
| `-f, --file` | Archivo fuente con los *endpoints* (XML, JSON o TXT). | `ruta/archivo.ext` | **Requerido** |
| `-o, --output` | Formatos de salida para los reportes. | `csv`, `json`, `txt` | `csv` |
| `--order` | Orden de clasificación en el reporte. | `host`, `appearance` | `appearance` |
| `--verbose` | Muestra mensajes de depuración detallados. | (Flag) | Desactivado |

### Ejemplos de Uso

1.  Analizar un volcado de Burp (XML) y generar un reporte CSV ordenado por Host:

    ```bash
    python3 burp_risk_classifier.py -f burp_history.xml -o csv --order host
    ```

2.  Analizar una especificación OpenAPI (JSON) y generar JSON y TXT:

    ```bash
    python3 burp_risk_classifier.py -f api_spec.json -o json txt
    ```

3.  Analizar una lista simple de URLs y generar solo CSV (orden de aparición):

    ```bash
    python3 burp_risk_classifier.py -f urls.txt
    ```

-----

## 🔢 Niveles de Riesgo y Clasificación

| Rango | Nivel de Riesgo | Color (Conceptual) | Prioridad de Testing |
| :--- | :--- | :--- | :--- |
| **8-10** | **Alto/Crítico** | 🔴 Rojo | **Inmediata**. Se detectaron: credenciales, datos financieros, operaciones de eliminación o funciones de administración. |
| **4-7** | **Medio** | 🟠 Naranja | **Alta**. Se detectaron: gestión de usuarios/datos, subidas de archivos, reportes confidenciales o patrones de IDOR. |
| **1-3** | **Bajo** | 🟡 Amarillo/Verde | **Baja**. Se detectaron: información pública, estado del servicio, documentación o contenido estático. |


-----

## 🛑 Aviso Legal y Descargo de Responsabilidad

  * **Propósito:** Esta herramienta proporciona un **análisis heurístico** basado en texto. La puntuación de riesgo generada (**1-10**) es solo una sugerencia de prioridad para la revisión. **No sustituye el juicio experto** de un analista de seguridad.
  * **Burp Suite/OpenAPI:** El *script* puede consumir formatos de archivo generados por **Burp Suite (XML)** o la especificación **OpenAPI/Swagger (JSON)**.
  * **Uso Ético:** El usuario es el único responsable de utilizar esta herramienta de manera **ética y legal**, asegurándose de tener los permisos necesarios para analizar los sistemas en cuestión.

-----