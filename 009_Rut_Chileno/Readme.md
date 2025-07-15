# RUT Chileno v4.0

Descripción:

Este script de Python es un validador de RUTs chilenos con funcionalidades para trabajar como texto o inclusive como fichero. Permite crear RUTs de forma aleatoria o secuencial, personalizables por rango, cantidad y formato. Además, ofrece la opción de guardar los resultados en un archivo.

La **versión 4.0** incluye una nueva funcionalidad que permite generar RUTs con o sin el dígito verificador, proporcionando mayor flexibilidad para distintas necesidades.

Incluye un banner de texto coloreado para una mejor visualización.
La creación fue hecha paso a paso de forma manual, en forma autónoma, 
pero la optimización de código fue con IA para mejorar cualquier error gramatical y para implementar uno a uno estos componentes a esta versión.

Requerimientos:
* **Python**: Requiere Python 3.x para ejecutarse.
* **Librerías estándar de Python**.


Saludos

---

## WIKI

### Forma de Uso de forma interactiva y CLI 

#### Modo Interactivo
Solo ejecuta el script sin ningún argumento para entrar al modo interactivo. El programa te guiará paso a paso con preguntas sobre el modo de generación, cantidad, formato y si deseas incluir el dígito verificador.

![Pasted image 20241113232810](https://github.com/user-attachments/assets/0167faef-68b7-4b65-8455-a3a9723303ca)

#### Modo CLI
Para ver todas las opciones disponibles, usa el comando de ayuda:

```bash
python generador_ruts.py -h
````

Esto mostrará una ayuda detallada con todas las opciones disponibles, las cuales se irán actualizando.

Opciones:

```
 -h, --help            show this help message and exit
 -m, --modo {a,s}      Modo de operación: "a" para aleatorio o "s" para secuencial.
 -r, --rango INICIAL FINAL
                       Rango en millones para generación aleatoria (INICIAL FINAL). Por defecto: [10, 20].
 -c, --cantidad CANTIDAD
                       Cantidad de RUTs a generar (por defecto: 50).
 -p, --con-puntos      Generar RUTs con puntos. Por defecto: sin puntos.
 -g, --con-guion       Generar RUTs con guión. Por defecto: sin guión.
 -sdv, --sin-digito-verificador
                       Generar RUTs sin el dígito verificador.
 -o, --rut-inicial RUT_INICIAL
                       RUT inicial para generación secuencial.
 -f, --archivo ARCHIVO
                       Nombre del archivo de salida (por defecto: ruts_generados.txt).
 -v, --verbose         Mostrar la tabla de opciones en la salida y en el archivo.
 -val, --validar VALIDAR [VALIDAR ...]
                       Validar uno o más RUTs (Ej: 12345678-K ).
 -vo, --archivo-salida ARCHIVO_SALIDA
                       Nombre del archivo para guardar los resultados de la validación.
```

-----

### Ejemplos de uso

#### Modo Interactivo

```bash
python3 rutchile.py
```

**En modo aleatorio:**

**Modo secuencial:**

#### Modo CLI

**Generación secuencial con todas las opciones:**
Este comando genera 500 RUTs secuenciales, comenzando desde 12345678, con puntos y guion, y guarda el resultado en el archivo `poc01.txt`.

```bash
python .\rutchile.py -m s -o 12345678 -c 500 -p -g -f poc01.txt
```

**Generación aleatoria con todas las opciones:**
Este comando genera 500 RUTs aleatorios, con puntos y guion, y guarda el resultado en el archivo `poc02.txt`.

```bash
python .\rutchile.py -m a -o 12345678 -c 500 -p -g -f poc02.txt
```

**NUEVO en v4.0: Generar sin dígito verificador:**
Este comando genera 500 RUTs aleatorios sin el dígito verificador.

```bash
python .\rutchile.py -m a -c 500 --sin-digito-verificador
```

**Con información detallada (verbose):**
Añadiendo el argumento `-v` o `--verbose` se mostrará una tabla con las variables y opciones usadas en la ejecución, tanto en la terminal como en el archivo de salida.

```bash
python .\rutchile.py -m s -o 12345678 -c 500 -p -g -f poc01.txt -v
```
 
 