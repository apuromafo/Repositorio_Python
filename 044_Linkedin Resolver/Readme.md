-----

### 🔗 LinkedIn URL Resolver

**`linkedin_resolver.py`** es un script de Python diseñado para resolver enlaces acortados de LinkedIn (`lnkd.in`) y obtener sus URLs finales. Esta herramienta es especialmente útil para obtener la dirección web original de publicaciones de LinkedIn, incluso si el enlace pasa por páginas de advertencia intermedias.

-----

### 🌟 Características

  * **Resolución de URLs:** Convierte enlaces acortados de `lnkd.in` a la URL de destino real.
  * **Manejo de Páginas Intermedias:** Es capaz de extraer la URL final de las páginas de advertencia de LinkedIn.
  * **Modo "Anónimo":** Utiliza una nueva sesión de `requests` y un `User-Agent` genérico para simular una navegación limpia y sin cookies, lo que puede ayudar a evitar bloqueos de red.
  * **Entrada/Salida Flexible:**
      * Lee texto desde un archivo de entrada (`-a`).
      * Lee texto directamente de la consola si no se especifica un archivo.
      * Guarda la salida en un archivo (`-o`).
      * Imprime la salida en la consola si no se especifica un archivo de salida.
  * **Marca de Tiempo (`--timestamp-output`):** Permite añadir una marca de tiempo (`YYYYMMDD_HHMMSS`) al nombre del archivo de salida para evitar la sobreescritura.

-----

### 🛠️ Instalación

Asegúrate de tener **Python 3** instalado en tu sistema. Luego, instala las bibliotecas necesarias (`requests` y `beautifulsoup4`) usando `pip`:

```bash
pip install requests beautifulsoup4
```

-----

### 🚀 Uso

Guarda el script como `linkedin_resolver.py` (o el nombre que prefieras).

La sintaxis básica para ejecutarlo es:

```bash
python linkedin_resolver.py [OPCIONES]
```

#### Opciones Disponibles

| Opción                          | Descripción                                                                                                                              |
| :------------------------------ | :--------------------------------------------------------------------------------------------------------------------------------------- |
| `-a, --archivo <ruta_archivo>`  | **(Opcional)** Especifica la ruta al archivo de texto de entrada que contiene los enlaces de LinkedIn.                                   |
| `-o, --output <ruta_salida>`    | **(Opcional)** Especifica la ruta donde se guardará el texto procesado. Si no se usa, la salida se imprimirá en la consola.                |
| `-t, --timestamp-output`        | **(Opcional)** Añade una marca de tiempo (`YYYYMMDD_HHMMSS`) al nombre del archivo de salida.                                            |

#### Comportamiento de `--timestamp-output`

  * **Con `-o`:** La marca de tiempo se inserta antes de la extensión del archivo (ejemplo: `mi_salida_20250730_093400.txt`).
  * **Sin `-o`:** Se genera un nombre de archivo por defecto con la marca de tiempo (ejemplo: `resolved_linkedin_urls_20250730_093400.txt`).

-----

### 📝 Ejemplos

#### 1\. Procesar texto desde la consola y mostrar en la terminal

```bash
python linkedin_resolver.py
# Pega tu texto aquí (luego presiona Enter y Ctrl+D en Linux/macOS o Ctrl+Z en Windows para finalizar).
```

#### 2\. Procesar un archivo de entrada y mostrar el resultado en la consola

```bash
python linkedin_resolver.py -a mi_post.txt
```

#### 3\. Procesar un archivo y guardar en un archivo de salida específico

```bash
python linkedin_resolver.py -a mi_post.txt -o post_resuelto.txt
```

#### 4\. Procesar un archivo y guardar en un archivo con marca de tiempo (nombre por defecto)

```bash
python linkedin_resolver.py -a mi_post.txt -t
# Esto creará un archivo como "resolved_linkedin_urls_20250730_093400.txt"
```

#### 5\. Procesar un archivo y guardar en un archivo con nombre y marca de tiempo personalizados

```bash
python linkedin_resolver.py -a mi_post.txt -o informe_linkedin.md -t
# Esto creará un archivo como "informe_linkedin_20250730_093400.md"
```

-----

### ⚠️ Notas Importantes

  * **Fiabilidad:** Aunque se han implementado métodos robustos (seguimiento de redirecciones y búsqueda de enlaces específicos en el HTML), la fiabilidad de la resolución de URLs externas puede variar. Esto depende de cómo LinkedIn y los sitios de destino manejan sus enlaces y redirecciones.
  * **Rendimiento:** Cada solicitud de URL se realiza de manera individual. Si procesas un gran número de enlaces, ten en cuenta que el proceso puede tomar tiempo.

## ⚠️ Aviso Legal / Legal Notice

Esta herramienta es unicamente para fines educativos y de auditoria de seguridad autorizada. El uso no autorizado contra sistemas sin el consentimiento explicito del propietario es ilegal. El usuario asume toda responsabilidad por el uso indebido.

This tool is for educational and authorized security auditing purposes only. Unauthorized use against systems without the owner's explicit consent is illegal. The user assumes all responsibility for misuse.
