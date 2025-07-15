
### Script de Análisis de Cabeceras de Seguridad v0.0.7

Pequeño script pensado en validar las cabeceras de seguridad de un sitio web, inspirado en las buenas prácticas de OWASP.

-----

### Funcionalidades y Uso

El script ha evolucionado con el tiempo, añadiendo más opciones y flexibilidad. A continuación se detallan las funcionalidades actuales:

  - **Análisis de cabeceras:** Identifica las cabeceras de seguridad presentes y las faltantes.
  - **Recomendaciones:** Ofrece sugerencias sobre cabeceras que se podrían eliminar y cabeceras de seguridad recomendadas para configurar.
  - **Versatilidad de peticiones:** Permite realizar peticiones `GET`, `POST`, `PUT`, etc., personalizando las cabeceras y el cuerpo de la solicitud.
  - **Modo estático:** Permite analizar los resultados de una petición previamente guardada en un archivo JSON, evitando la necesidad de hacer una nueva solicitud a la URL.

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

2.  **Petición `POST` con cabeceras y cuerpo JSON:**

    ```bash
    python Cabeceras_Seguridad.py https://ejemplo.com POST -H "Content-Type: application/json" -b '{"key": "value"}'
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
> La versión actual del script (v0.0.7) guarda automáticamente la URL de destino en el archivo JSON, lo que facilita los análisis futuros.

Este es un proyecto funcional para las necesidades actuales de análisis, con potencial para futuras optimizaciones.

-----

**Fecha de actualización:** 15 de julio de 2025.