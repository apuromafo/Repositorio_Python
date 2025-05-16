# buscar_crt.py

Este script en Python busca certificados asociados a un dominio o una organización utilizando el servicio crt.sh. Permite guardar los resultados en formato TXT o JSON y soporta el uso de proxies.

## Autor

Apuromafo

## Inspiración

Inspirado en el repositorio de az7rb.

## Requerimientos

* **Python 3:** Asegúrate de tener Python 3 instalado en tu sistema. Puedes verificar la versión con el comando `python3 --version` o `python --version`.
* **Librería `requests`:** Esta librería es necesaria para realizar las peticiones HTTP al servicio crt.sh. Puedes instalarla usando pip:
    ```bash
    pip install requests
    ```

## Uso

1.  **Descarga el script:** Guarda el contenido del script `certificados_cr.py` en un archivo con ese nombre.
2.  **Hazlo ejecutable (opcional en algunos sistemas):** Abre la terminal o línea de comandos y navega hasta el directorio donde guardaste el script. Ejecuta:
    ```bash
    chmod +x certificados_cr.py
    ```
3.  **Ejecuta el script con las opciones deseadas:**

    * **Mostrar la ayuda:**
        ```bash
        ./certificados_cr.py -h
        ```
        o
        ```bash
        python certificados_cr.py -h
        ```

    * **Buscar por nombre de dominio:** Reemplaza `dominio.com` con el dominio que quieres buscar.
        ```bash
        ./certificados_cr.py -d dominio.com
        ```
        o
        ```bash
        python certificados_cr.py -d dominio.com
        ```

    * **Buscar por nombre de organización:** Reemplaza `"Nombre de la Organización"` con la organización que quieres buscar. Usa comillas si el nombre contiene espacios.
        ```bash
        ./certificados_cr.py -o "Nombre de la Organización"
        ```
        o
        ```bash
        python certificados_cr.py -o "Nombre de la Organización"
        ```

    * **Especificar el formato de salida (TXT por defecto):** Usa `-f json` para guardar los resultados en formato JSON.
        ```bash
        ./certificados_cr.py -d dominio.com -f json
        ```
        o
        ```bash
        python certificados_cr.py -d dominio.com --formato json
        ```

    * **Usar un proxy:** Proporciona la dirección del proxy con la opción `--proxy`.
        ```bash
        ./certificados_cr.py -d dominio.com --proxy http://ip_del_proxy:puerto
        ```
        o con autenticación:
        ```bash
        ./certificados_cr.py -d dominio.com --proxy http://usuario:contraseña@ip_del_proxy:puerto
        ```

## Salida

Los resultados se mostrarán en la terminal y también se guardarán en la carpeta `output`. Los nombres de los archivos serán `dominio.nombre_del_dominio.txt` o `.json`, y `organizacion.nombre_de_la_organizacion.txt` o `.json`.

 