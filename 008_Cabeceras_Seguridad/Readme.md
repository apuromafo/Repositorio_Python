
# Cabeceras Seguridad

Script para validar cabeceras de seguridad HTTP de sitios web, inspirado en buenas prácticas de OWASP.

-----

### Funcionalidades y Uso

El script ha evolucionado con el tiempo, añadiendo más opciones y flexibilidad. A continuación se detallan las funcionalidades actuales:

  - **Análisis de cabeceras:** Identifica las cabeceras de seguridad presentes y las faltantes, bloque por bloque.
  - **Análisis profundo de CSP (v1.1+):** Evalúa la política directiva por directiva alineado con CSP Evaluator (Google, CSP v3): severidad por fuente (`unsafe-inline`, `unsafe-eval`, `data:`, wildcards, allowlists JSONP/Angular), herencia de `default-src` (CSP3), y detección de directivas recomendadas ausentes (`form-action`, `base-uri`, `frame-ancestors`, `report-uri`...).
  - **Plan de remediación accionable (v1.3+):** Emite "fichas de incidencia" con pasos concretos por stack: Nginx, Apache, Node.js/Express, PHP, ASP.NET, Cloudflare WAF (Dashboard + Transform Rules + Worker con nonce), Akamai (Property Manager + EdgeWorkers) y CloudFront, con límites reales de cada plataforma y alineación SOC 2 / PCI DSS v4.0.
  - **Infosec de exposición:** Detecta ~60 cabeceras que revelan tecnología/proxies/CDN (Server, X-Powered-By, X-Magento-Tags, Via, etc.) con observación/riesgo/sugerencia.
  - **Verificación HTTP -> HTTPS (v1.4.3):** Comprueba que el sitio responde redirección (30X con Location https) al pedirlo por HTTP.
  - **Versatilidad de peticiones:** Verbo HTTP (`-v` GET/POST/PUT/HEAD/DELETE/PATCH/OPTIONS), cabeceras personalizadas (`-H`), cuerpo JSON (`-b`), proxy (`-p`), certificado (`--cert`) y User-Agent (`-ua`).
  - **Modo estático:** Analiza un JSON generado previamente (`-j`), útil para auditar sin reconectarse o con datos de Burp (`convert_headers.py`).

-----

### Requerimientos y Ejecución

El script está escrito en Python 3 y utiliza las siguientes bibliotecas:

```
argparse: Para gestionar los argumentos de línea de comandos.
requests: Para realizar las peticiones HTTP.
json: Para trabajar con archivos JSON.
datetime: Para gestionar fechas y horas.
tabulate: Para formatear la salida en tablas.
colorama: Para dar color a la salida de la consola.
urllib3: Para funcionalidades adicionales en peticiones HTTP.
ipaddress: Para trabajar con direcciones IP.
```

Puedes instalar los paquetes necesarios con el siguiente comando:

```bash
pip install -r requirements.txt
```

-----

### Ejemplos de Uso

1.  **Análisis básico de una URL:**

    ```bash
    python Cabeceras_Seguridad.py https://ejemplo.com
    ```

2.  **Petición `POST` con cabeceras y cuerpo JSON (verbo con `-v`):**

    ```bash
    python Cabeceras_Seguridad.py https://ejemplo.com -v POST -H "Content-Type: application/json" -b '{"key": "value"}'
    ```

    Para cuerpos de petición más complejos, puedes usar un archivo:

    ```bash
    python Cabeceras_Seguridad.py https://ejemplo.com POST -b cuerpo.json
    ```

    **Nota:** El script detecta automáticamente si el argumento `-b` se refiere a una cadena JSON o a un archivo.

3.  **Uso de proxy:**

    ```bash
    python Cabeceras_Seguridad.py https://ejemplo.com -p 127.0.0.1:8080
    ```

    **Tip:** Si tienes dudas sobre cómo se envían las peticiones, puedes usar un proxy como Burp Suite o ZAP para inspeccionar el tráfico.

4.  **Análisis de un archivo JSON estático:**
    Para evitar hacer una nueva solicitud web, puedes analizar un archivo JSON previamente generado. Esto es útil para auditar datos sin necesidad de conectarse de nuevo a internet.

    ```bash
    python Cabeceras_Seguridad.py --json-file output.json
	python Cabeceras_Seguridad.py -j output.json
    ```

> [\!NOTE]
> El script guarda automáticamente la URL de destino y su IP en el archivo JSON de salida, lo que facilita los análisis futuros y el modo estático (`-j`).

--- 

### Pruebas

La herramienta incluye una suite de pruebas unitaria (unittest/pytest, offline):

```bash
python -m pytest tests -q
```

-----

**Fecha de actualización:** 21 de octubre de 2026 (v1.4.3). Historial completo en `CHANGELOG.md`.

## ⚠️ Aviso Legal / Legal Notice

Esta herramienta es unicamente para fines educativos y de auditoria de seguridad autorizada. El uso no autorizado contra sistemas sin el consentimiento explicito del propietario es ilegal. El usuario asume toda responsabilidad por el uso indebido.

This tool is for educational and authorized security auditing purposes only. Unauthorized use against systems without the owner's explicit consent is illegal. The user assumes all responsibility for misuse.
