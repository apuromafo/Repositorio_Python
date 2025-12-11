# 📖 README.md

## `converter_xml_to_json.py`

### 🚀 Conversor de XML (incluyendo SOAP) a JSON

Este script de Python convierte archivos XML estándar y mensajes SOAP en estructuras JSON limpias. Está diseñado para simplificar la salida eliminando namespaces, manejando correctamente atributos y simplificando elementos que solo contienen texto.

### ✨ Características Principales

  * **Soporte SOAP:** Detecta y extrae automáticamente el contenido del `Body` de mensajes SOAP, eliminando el envoltorio (`Envelope`, `Header`).
  * **Simplificación de Texto:** Convierte elementos con solo texto (ej. `<tag>valor</tag>`) directamente a valores JSON (ej. `"tag": "valor"`), evitando la clave `"#text"` innecesaria.
  * **Manejo de Atributos:** Los atributos XML se representan en el JSON con el prefijo `@` (ej. `@id`).
  * **Gestión de Namespaces:** Elimina los prefijos de namespace (ej. `soapenv:`, `web:`) para una salida JSON más limpia.
  * **Herramienta de Línea de Comandos:** Permite especificar archivos de entrada y salida fácilmente.
  * **Control de Versión:** Incluye la versión del script (`-v`).

### 📥 Requisitos

Este script solo utiliza librerías estándar de Python, por lo que no necesita instalaciones adicionales:

  * Python 3.x
  * Librerías estándar: `xml.etree.ElementTree`, `json`, `argparse`, `sys`, `collections`.

### 💻 Uso

Para ejecutar el script, utiliza la siguiente sintaxis en tu terminal:

```bash
python converter_xml_to_json.py -a <archivo_entrada.xml> [-o <archivo_salida.json>]
```

| Opción | Argumento | Descripción | Obligatorio |
| :---: | :---: | :--- | :---: |
| `-a` / `--archivo` | `<ruta>` | Ruta al archivo XML/SOAP de entrada. | Sí |
| `-o` / `--output` | `<ruta>` | Ruta al archivo donde se guardará el JSON resultante. Si se omite, el resultado se imprime en la consola. | No |
| `-v` / `--version` | N/A | Muestra la versión actual del script. | No |

#### Ejemplos de Ejecución

1.  **Convertir e imprimir en pantalla:**

    ```bash
    python converter_xml_to_json.py -a demo.txt
    ```

2.  **Convertir y guardar en un archivo:**

    ```bash
    python converter_xml_to_json.py -a soap_request.xml -o output.json
    ```

3.  **Ver la versión:**

    ```bash
    python converter_xml_to_json.py -v
    ```

-----

# 📄 Ejemplo: `demo.txt`

Este archivo contiene una mezcla de elementos para probar la funcionalidad de simplificación de texto, atributos y repetición de etiquetas.

```xml
<catalogo xmlns:prod="http://ejemplo.com/productos" version="1.0">
    <producto id="P101" categoria="electronica">
        <nombre>Smartwatch X9</nombre>
        <precio moneda="EUR">129.99</precio>
        <stock>15</stock>
        <caracteristicas>
            <peso>50g</peso>
            <color>Negro</color>
        </caracteristicas>
    </producto>
    <producto id="P102" categoria="libros">
        <nombre>Python Avanzado</nombre>
        <precio moneda="USD">45.00</precio>
        <stock>20</stock>
    </producto>
    <producto id="P103" categoria="electronica">
        <nombre>Auriculares BT</nombre>
        <precio moneda="EUR">55.50</precio>
        <stock>10</stock>
    </producto>
</catalogo>
```

-----

# 💡 Resultado Esperado (JSON)

Al ejecutar `python converter_xml_to_json.py -a demo.txt`, la salida JSON será:

```json
{
    "catalogo": {
        "@version": "1.0",
        "producto": [
            {
                "@id": "P101",
                "@categoria": "electronica",
                "nombre": "Smartwatch X9",
                "precio": {
                    "@moneda": "EUR",
                    "#text": "129.99"
                },
                "stock": "15",
                "caracteristicas": {
                    "peso": "50g",
                    "color": "Negro"
                }
            },
            {
                "@id": "P102",
                "@categoria": "libros",
                "nombre": "Python Avanzado",
                "precio": {
                    "@moneda": "USD",
                    "#text": "45.00"
                },
                "stock": "20"
            },
            {
                "@id": "P103",
                "@categoria": "electronica",
                "nombre": "Auriculares BT",
                "precio": {
                    "@moneda": "EUR",
                    "#text": "55.50"
                },
                "stock": "10"
            }
        ]
    }
}
```

 