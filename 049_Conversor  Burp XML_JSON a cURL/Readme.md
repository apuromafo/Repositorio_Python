# 💻 Burp XML/JSON a cURL Converter (`xml2curl_converter.py`)

**Versión:** `v2.2.3`

Herramienta en **Python** diseñada para transformar volcados de peticiones HTTP exportadas desde **Burp Suite** (en formato XML) o especificaciones **OpenAPI** (Swagger, en formato JSON) en comandos **cURL** funcionales, facilitando el reenvío y la manipulación de solicitudes.

-----

## ✨ Características Principales

  * **Soporte de Entrada Dual:** Procesa archivos **XML** exportados desde Burp Suite (típicamente desde el Proxy o Site Map) y archivos **JSON** basados en la especificación OpenAPI (v3.x).
  * **Conversión Precisa:** Maneja la decodificación de peticiones codificadas en **Base64** (común en Burp XML) y extrae correctamente métodos, URL, encabezados y cuerpos.
  * **Manejo Inteligente del Cuerpo:** Formatea cuerpos **JSON** y `application/x-www-form-urlencoded` para ser compatibles con el *flag* `--data-raw` de cURL.
  * **Opciones de Salida Flexibles:** Permite organizar los comandos cURL generados de cuatro formas distintas (orden cronológico, por verbo HTTP, por host y verbo, o en un solo archivo maestro).
  * **Limpieza de Encabezados:** Ignora automáticamente encabezados irrelevantes o conflictivos para cURL (e.g., `host`, `content-length`, `connection`).
  * **Modo Interactivo/Argumentos:** Soporta la ejecución mediante argumentos de línea de comandos o un modo interactivo guiado.

-----

## 🚀 Uso e Instalación

### Requisitos

  * **Python 3.6+**
  * No se requieren dependencias externas más allá de las librerías estándar.

### Ejecución

El *script* puede ejecutarse en **modo interactivo** sin argumentos o directamente especificando el archivo de entrada y la opción de salida.

```bash
# Modo Interactivo (solicitará la ruta del archivo y la opción)
python3 xml2curl_converter.py

# Modo Argumentos
python3 xml2curl_converter.py -i <ruta_al_archivo.xml/json> -o <opción_1_a_4>
```

### Opciones de Salida (`-o` / Opción 1-4)

| Opción | Descripción | Estructura de Salida |
| :--- | :--- | :--- |
| **1** | **Orden de Aparición** | `output/curl/orden_aparicion/Curl[N]_[método]_[fecha].txt` |
| **2** | **Ordenado por Verbo** | `output/curl/por_verbo/[método]/Curl[N]_[método]_[fecha].txt` |
| **3** | **Ordenado por Host y Verbo** | `output/curl/por_host_y_verbo/[host_sanitizado]/[método]/Curl[N]_[método]_[fecha].txt` |
| **4** | **Archivo Único** | `output/curl/all_curls_[timestamp].txt` (Todos los comandos en un solo archivo) |

**Ejemplo (Opción 3)**

Si utilizas la opción 3 en un volcado con peticiones a `api.ejemplo.com` y `auth.ejemplo.com`, se crearán las siguientes rutas de directorios:

```
output/curl/por_host_y_verbo/
├── api_ejemplo_com/
│   ├── post/
│   │   ├── Curl1_post_20251001.txt
│   └── get/
│       └── Curl1_get_20251001.txt
└── auth_ejemplo_com/
    └── post/
        └── Curl1_post_20251001.txt
```

-----

## 🗑️ Encabezados Ignorados

El *script* omite por defecto los siguientes encabezados, ya que son gestionados por cURL o son específicos del contexto de Burp/Navegador, y podrían causar errores al reejecutar la petición:

  * `host`
  * `content-length`
  * `user-agent`
  * `accept-encoding`
  * `connection`
  * `postman-token`
  * `cache-control`
  * `pragma`
  * `accept`

-----

## 🛑 Aviso Legal y Descargo de Responsabilidad

  * **Burp Suite:** Las funcionalidades de exportación de peticiones (como XML) son propiedad intelectual de **PortSwigger Ltd.**, creadores de Burp Suite. Este *script* está diseñado para consumir un formato de archivo generado por dicho *software*.
  * **cURL:** La herramienta de línea de comandos cURL y sus librerías asociadas son *software* de código abierto. Este *script* genera comandos compatibles con esta utilidad.
  * **Uso Ético:** Este *script* es una herramienta de apoyo al desarrollo y a la seguridad ofensiva/defensiva. El usuario es el **único responsable** del uso que se le dé a los comandos generados, asegurando que siempre se actúe bajo las leyes y permisos aplicables.