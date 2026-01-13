-----

### 💻 `curl2py` - Conversor de Comandos `curl` a Scripts de `requests`

**`curl2py`** es un script de Python que automatiza la conversión de uno o varios comandos `curl` en código Python, utilizando la popular librería `requests`. Su objetivo principal es ayudar a los profesionales de la seguridad y desarrolladores a automatizar peticiones web complejas extraídas de la consola o de archivos de texto.

**Advertencia:** Esta herramienta está diseñada para ser utilizada por profesionales de la seguridad y desarrolladores con fines de **auditoría, automatización y pruebas**. El uso de este script en sistemas sin autorización previa es ilegal y no está respaldado.

### ✨ Características Principales

  * **Versatilidad de Entrada**: Acepta comandos `curl` directamente como argumento, desde la entrada estándar (consola) o desde un archivo de texto.
  * **Análisis Robusto**: Analiza y extrae automáticamente el método HTTP (`GET`, `POST`), la URL, las cabeceras (`-H`), las cookies (`-b`), y los datos (`-d`).
  * **Generación de Código Limpio**: Genera un script de Python con un formato legible y bien estructurado, listo para ser ejecutado.
  * **Manejo de Respuestas**: El código generado incluye lógica para manejar y mostrar diferentes tipos de contenido de respuesta, como JSON, HTML y archivos binarios.
  * **Salida Flexible**: Permite imprimir el script generado en la consola o guardarlo directamente en un archivo `.py`.

-----

### 🚀 Requisitos

Este script no requiere librerías externas para su ejecución, ya que el código generado se basa en la librería `requests`.

Para ejecutar los scripts resultantes, necesitas instalar `requests`:

```bash
pip install requests
```

### 📖 Uso

Para usar el script, ejecuta `curl2py.py` seguido de la opción de entrada deseada.

#### 1\. Desde la línea de comandos

Si tienes un comando `curl` simple, puedes pasarlo como argumento:

```bash
python curl2py.py "curl 'https://api.example.com/data' -H 'User-Agent: MyAgent'"
```

#### 2\. Desde un archivo

Si tienes una lista de comandos `curl` en un archivo de texto (por ejemplo, `comandos.txt`), puedes usar la ruta del archivo como argumento.

```bash
python curl2py.py comandos.txt
```

#### 3\. Modo Interactivo (Consola)

Si no pasas ningún argumento, el script entrará en modo interactivo. Podrás pegar tus comandos `curl` directamente en la consola.

```bash
python curl2py.py
# Pega aquí tus comandos.
# Para finalizar, pulsa Enter en una línea vacía y luego Ctrl+D (Linux/macOS) o Ctrl+Z (Windows).
```

### 📁 Salida

El script te preguntará si deseas guardar el resultado en un archivo o imprimirlo en la consola.

  * **Guardar en un archivo**: Ingresa el nombre del archivo (ej. `script_de_prueba.py`) cuando se te solicite. El script añadirá automáticamente la extensión `.py` si no la has incluido.
  * **Mostrar en la consola**: Simplemente presiona `Enter` sin escribir nada para ver el script impreso en tu terminal.

-----

### ⚠️ Advertencia de Seguridad

El código generado por este script replica la funcionalidad de los comandos `curl` originales. Es responsabilidad del usuario asegurarse de que las peticiones se realizan a sistemas en los que tiene **autorización explícita** para hacerlo. El uso de este script para actividades no autorizadas es una violación de la ley.