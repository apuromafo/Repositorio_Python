# 📝 Burp XML a OpenAPI 3.0 Converter (`xml2api_converter.py`)

**Versión:** `v1.7.5`

Herramienta en **Python** diseñada para procesar volcados de peticiones HTTP exportadas desde **Burp Suite** (en formato XML) y generar automáticamente especificaciones **OpenAPI (Swagger) 3.0.0** en formato JSON. Esta herramienta facilita la documentación y el análisis de la superficie API de una aplicación web.

-----

## ✨ Características Principales

  * **Generación OpenAPI 3.0.0:** Convierte peticiones web en rutas, métodos, parámetros y cuerpos de solicitud/respuesta válidos bajo la especificación **OpenAPI**.
  * **Soporte de Burp XML:** Lee y procesa el formato de exportación XML de Burp Suite, decodificando automáticamente las peticiones y respuestas codificadas en **Base64**.
  * **Detección de Parámetros:** Identifica parámetros de consulta (`query`), de ruta (`path`) y de encabezado (`header`).
  * **Manejo de Cuerpos (Schema/Example):** Extrae cuerpos JSON, XML y `x-www-form-urlencoded`, generando **esquemas básicos de propiedades y ejemplos**.
  * **Detección de Autenticación:** Detecta encabezados de autenticación **Bearer (JWT)** y configura el esquema de seguridad `bearerAuth` en la sección `components/securitySchemes`.
  * **Opciones de Salida Flexibles:** Permite consolidar la documentación en un único archivo JSON o separarla por host.

-----

## 🚀 Uso e Instalación

### Requisitos

  * **Python 3.6+**
  * No se requieren dependencias externas más allá de las librerías estándar.

### Ejecución

El *script* se ejecuta en **modo interactivo** solicitando la ruta del archivo y la opción de salida.

```bash
python3 xml2api_converter.py
```

### Opciones de Salida

| Opción | Descripción | Estructura de Salida |
| :--- | :--- | :--- |
| **1** | **Archivo Único Consolidado** | Genera un solo archivo JSON con todas las peticiones, utilizando etiquetas (`tags`) para organizar las rutas por host. |
| **2** | **Separado por Host** | Crea directorios y archivos JSON individuales para cada host encontrado en el volcado XML. |

**Ejemplo (Opción 2 - Separado por Host)**

Si utilizas la opción 2 con un volcado que contiene peticiones a `api.ejemplo.com` y `auth.ejemplo.com`, se creará la siguiente estructura de directorios:

```
output/por_host/
├── api_ejemplo_com/
│   └── api_ejemplo_com_api.json
└── auth_ejemplo_com/
    └── auth_ejemplo_com_api.json
```

-----

## 🗑️ Encabezados Ignorados

Los siguientes encabezados son omitidos al generar los parámetros de encabezado de OpenAPI, ya que suelen ser específicos del navegador o del *proxy* y no necesarios en la especificación de la API:

  * `host`
  * `content-length`
  * `user-agent`
  * `accept-encoding`
  * `accept-language`
  * `cookie`
  * `connection`
  * `sec-ch-ua` (y otros relacionados con el navegador/plataforma)
  * `upgrade-insecure-requests`
  * `postman-token`
  * `cache-control`
  * `pragma`
  * `accept`
  * `rut`
  * `origin`

-----

## 🛑 Aviso Legal y Descargo de Responsabilidad

  * **Burp Suite:** Las funcionalidades de exportación de peticiones (como XML) son propiedad intelectual de **PortSwigger Ltd.**, creadores de Burp Suite. Este *script* está diseñado para consumir un formato de archivo generado por dicho *software*.
  * **OpenAPI/Swagger:** OpenAPI es una especificación estándar de código abierto para describir interfaces API. Este *script* genera archivos compatibles con esta especificación.
  * **Uso Ético:** Este *script* es una herramienta de apoyo al desarrollo, la documentación y la seguridad. El usuario es el único responsable del uso que se le dé a los archivos generados, asegurando que siempre se actúe bajo las leyes y permisos aplicables.