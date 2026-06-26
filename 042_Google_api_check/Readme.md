# Google API Check

Validador de claves de API de Google Maps para detectar configuraciones vulnerables.

**`gmaps_auditor.py`** es un script de Python diseñado para auditar y validar si una clave de API de Google Maps está mal configurada y es vulnerable a un uso no autorizado. La herramienta realiza una serie de pruebas automatizadas contra las diversas APIs de Google Maps para determinar si la clave tiene restricciones de uso adecuadas.

**Este script es para uso exclusivo con fines de seguridad ofensiva, auditoría y pruebas de penetración (pentesting). Su propósito es ayudar a los profesionales de la seguridad a identificar configuraciones inseguras y reportarlas de manera responsable.** El uso de esta herramienta con fines maliciosos está estrictamente prohibido y es ilegal.

### 🌟 Características

  * **Amplio Alcance**: Prueba más de 15 APIs de Google, incluyendo Staticmap, Geocode, Elevation, Geolocation, y las APIs de Place y Roads.
  * **Pruebas Automatizadas**: Realiza peticiones `GET` y `POST` para validar el acceso sin restricciones de una clave de API.
  * **Gestión de Dependencias**: Instala automáticamente la librería `tabulate` si no está presente, para una visualización de resultados más clara.
  * **Verificación Manual**: Genera un archivo `.html` para una prueba manual y visual de la API de JavaScript, que no puede ser verificada automáticamente.
  * **Reporte Claro**: Genera un resumen en tabla que muestra el estado de cada API (`Vulnerable`, `No Vulnerable` o `Error`).

-----

### 🚀 Requisitos e Instalación

Este script requiere la librería `requests` y `tabulate`. La segunda se instala automáticamente si no está.

1.  Asegúrate de tener **Python 3.x** instalado.
2.  Instala la dependencia necesaria con `pip`:
    ```bash
    pip install requests
    ```

### 📖 Uso

Este script puede ejecutarse de dos maneras:

#### 1\. Pasando la clave API por la línea de comandos

```bash
python gmaps_auditor.py -a TU_CLAVE_API
```

  * `--api-key` o `-a`: Permite pasar la clave directamente como argumento.

#### 2\. Modo interactivo

```bash
python gmaps_auditor.py
```

  * Si ejecutas el script sin argumentos, te pedirá que ingreses la clave de API directamente en la terminal.

### 📝 Salida y Reporte

El script generará una tabla de resumen con el estado de cada API. Si se encuentra alguna API vulnerable, se proporcionará un **PoC (Proof of Concept)** en formato de URL para que el auditor pueda validar el acceso manualmente.

```
--------------------------------------------------
Resumen del estado de las APIs
--------------------------------------------------
+--------------------+---------------------+
| API                | Estado              |
+====================+=====================+
| Staticmap          | No Vulnerable       |
+--------------------+---------------------+
| Streetview         | No Vulnerable       |
+--------------------+---------------------+
| Directions         | No Vulnerable       |
+--------------------+---------------------+
| Geocode            | Vulnerable          |
+--------------------+---------------------+
| ...                | ...                 |
+--------------------+---------------------+

==================================================
Detalles de vulnerabilidad (Acceso sin restricción de clave)
==================================================
[*] **Geocode**
    Costo: $5 por 1000 solicitudes
    PoC URL: https://maps.googleapis.com/maps/api/geocode/json?latlng=40,30&key=TU_CLAVE_API

... (resto de las APIs vulnerables) ...
```

-----

### ⚠️ AVISO IMPORTANTE

  * **Uso Ético**: Esta herramienta está diseñada para ser utilizada por **profesionales de la seguridad** que tienen el permiso explícito del propietario del activo digital que están auditando.
  * **Responsabilidad**: El uso de esta herramienta en sistemas sin autorización previa es ilegal y puede tener consecuencias legales graves.
  * **Confidencialidad**: Los resultados de la auditoría deben manejarse con la máxima confidencialidad y ser comunicados únicamente al propietario o al equipo de seguridad responsable.
  * ** inspirado en gmapsapiscanner  
-----