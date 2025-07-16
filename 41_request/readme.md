
# `curl_to_request.py` - Conversor de Comandos `cURL` a Python

`curl_to_request.py` es una herramienta de línea de comandos que convierte automáticamente comandos `cURL` en scripts Python 3 limpios y ejecutables, usando la popular librería `requests`.

El script soporta múltiples modos de uso para una máxima flexibilidad, incluyendo el manejo de peticiones **GET**, **POST**, **PUT**, y **DELETE**, con soporte completo para **headers**, **cookies** y **datos JSON**.

-----

## Características

  * **Conversión Rápida**: Convierte cualquier comando `cURL` en un script Python funcional.
  * **Modos de Uso Múltiples**:
      * **Interactiva**: Pega tu comando `cURL` o una ruta de archivo directamente en la consola.
      * **Argumento de Archivo**: Proporciona la ruta de un archivo de texto con el comando `cURL`.
  * **Generación de Archivos**: Al finalizar, puedes elegir si el script generado se muestra en la consola o se guarda en un archivo `.py`.
  * **Manejo de Datos**: Extrae y formatea automáticamente `headers`, `cookies` y el cuerpo de datos (`-d`, `--data`).
  * **Manejo de Errores**: Incluye bloques `try...except` para una ejecución segura de las peticiones.

-----

## Requisitos

  * Python 3.x
  * La librería `requests`. Instálala con el siguiente comando:
    ```bash
    pip install requests
    ```

-----

## Guía de Uso

### 1\. Modo Interactivo

Este es el método más rápido y flexible. Solo ejecuta el script sin argumentos y te pedirá la entrada.

```bash
python curl_to_request.py
```

Al ver el mensaje, puedes:

  * **Pegar un comando `cURL`**: El script leerá lo que pegues hasta que ingreses una línea en blanco (presionando Enter dos veces).

    ```bash
    Pegue aquí sus comandos curl o la ruta de un archivo.
    Para finalizar, ingrese una línea en blanco y presione Enter dos veces.
    curl -X GET 'https://api.github.com/users/google'

    ```

      * **Pegar la ruta de un archivo**: Si la primera línea es una ruta válida a un archivo, el script leerá su contenido y lo procesará.

    <!-- end list -->

    ```bash
    Pegue aquí sus comandos curl o la ruta de un archivo.
    Para finalizar, ingrese una línea en blanco y presione Enter dos veces.
    C:\Users\tu_usuario\Documents\comandos.txt
    ```

### 2\. Modo con Argumento

Si ya tienes un archivo con tus comandos, puedes pasarlo directamente como un argumento.

```bash
# Ejemplo: archivo llamado `comandos.txt`
python curl_to_request.py comandos.txt
```

### 3\. Opciones de Salida

Después de procesar la entrada, el script te preguntará cómo quieres el resultado:

```
Presione ENTER para mostrar en pantalla o escriba un nombre de archivo para guardar (ej: mi_script.py):
```

  * **Mostrar en Consola**: Presiona **Enter** para ver el código impreso directamente.
  * **Guardar en Archivo**: Escribe un nombre de archivo (ej. `api_request.py`) y presiona **Enter**. El script guardará el código en ese archivo.

-----

## Ejemplo de un `cURL` y su Salida

**Comando de entrada (en un archivo o pegado):**

```bash
curl 'https://httpbin.org/post' \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json' \
  --data-raw '{
    "message": "Hola, mundo!"
  }'
```

**Salida generada (`mi_script.py`):**

```python
# -*- coding: utf-8 -*-
import requests
import json
import urllib.parse
from datetime import datetime

# --- Solicitud POST a: https://httpbin.org/post ---
try:
    response = requests.post(
        'https://httpbin.org/post',
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json"
        },
        json={
            "message": "Hola, mundo!"
        }
    )
    response.raise_for_status()

    content_type = response.headers.get('Content-Type', 'unknown')
    print(f"Tipo de contenido: {content_type}")

    if 'application/json' in content_type:
        try:
            data = response.json()
            print(json.dumps(data, indent=4))
        except json.JSONDecodeError as e:
            print(f"Advertencia: No se pudo parsear como JSON. Imprimiendo texto sin procesar. Error: {e}")
            print(response.text)
    elif 'text/html' in content_type:
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"content_{timestamp}.html"
        print(f"Contenido es HTML. Guardando en: {filename}")
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(response.text)
    elif 'text/' in content_type:
        print("Contenido es texto. Imprimiendo texto:")
        print(response.text)
    elif 'application/octet-stream' in content_type:
        filename = 'response_content'
        with open(filename, 'wb') as f:
            f.write(response.content)
        print(f"Archivo binario descargado: {filename}")
    else:
        print("Tipo de contenido no reconocido. Imprimiendo texto sin procesar:")
        print(response.text)

except requests.exceptions.RequestException as e:
    print(f"Error en la solicitud: {e}")

print("\n" + "="*80 + "\n")
```