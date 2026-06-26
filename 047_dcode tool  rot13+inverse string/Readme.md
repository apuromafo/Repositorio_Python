-----

# Dcode.py

**Dcode.py** es un script de Python 🐍 diseñado para la decodificación y codificación de múltiples capas, útil para desafíos de seguridad y CTFs (Capture The Flag). Puede procesar una cadena de texto o un archivo, aplicando secuencias de decodificación predefinidas o usando un modo de fuerza bruta para encontrar la combinación correcta de forma automática.

-----

## 🚀 Características Principales

  - **Modo Normal**: Decodifica o codifica una cadena o archivo usando una secuencia de algoritmos especificada.
  - **Modo de Fuerza Bruta (-fb)**: Prueba automáticamente todas las combinaciones de decodificación posibles (invertir, ROT13, Base64) para encontrar el resultado más legible.
  - **Análisis Heurístico**: Utiliza la **entropía de Shannon** y un diccionario de palabras clave para determinar si una decodificación es "plausible" o simplemente basura.
  - **Soporte de Archivos**: Puede procesar archivos línea por línea, ignorando comentarios (`#`).

-----

## 🛠️ Instalación y Requisitos

Este script solo requiere la instalación de Python 3. No hay dependencias externas adicionales.

```bash
# Verifica si tienes Python 3 instalado
python3 --version
```

-----

##  (Uso)

El script se ejecuta desde la línea de comandos. Usa el argumento `-h` o `--help` para ver todas las opciones disponibles.

```bash
python3 Dcode.py --help
```

### 1\. Decodificación de una cadena

Utiliza el argumento `-s` o `--string` para pasar la cadena directamente.

#### Con una secuencia de algoritmos específica:

Los algoritmos se definen con `--algoritmos` (`-alg`). Por defecto, la secuencia es `321`.

  - **`1`**: Invertir la cadena
  - **`2`**: Aplicar ROT13
  - **`3`**: Aplicar Base64

**Ejemplo**: Decodificar una cadena que fue codificada con Base64, luego ROT13 y finalmente invertida.

```bash
# Nota: La decodificación se aplica en orden inverso a la secuencia.
python3 Dcode.py -s "m98f/C2yU2r/lYy/m11jU2j" -alg 321
```

### 2\. Decodificación de un archivo (con fuerza bruta)

Utiliza el argumento `-a` o `--archivo` junto con `-fb` o `--fuerzabruta`. El script intentará decodificar cada línea que se parezca a una cadena codificada.

**Ejemplo**: Decodificar todas las cadenas encontradas en el archivo `codigos.txt`.

```bash
python3 Dcode.py -a codigos.txt -fb
```

-----

## 📝 Ejemplos Prácticos

### Modo de Fuerza Bruta para una cadena

```bash
# La cadena "ZWJsYXN0S3RGR34=" es "flag{test}" codificada en Base64 e invertida.
python3 Dcode.py -s "ZmxhZ3tzdG9wX3JldmVyc2luZ30=" -fb
```

**Salida Esperada:**

```
🔍 [Fuerza Bruta] Cadena: ZmxhZ3tzdG9wX3JldmVyc2luZ30=
    ✅ [3] → Entropía: 3.864 | 'flag{stop_reversing}'
```

### Modo de Fuerza Bruta para un archivo

Imagina que `datos.txt` contiene varias líneas, como estas:

```
# Esta es una cadena de prueba
ZmxhZ3tzdG9wX3JldmVyc2luZ30=
SGVsbG8sIHdvcmxkIQ==
```

Al ejecutar el script en modo de fuerza bruta:

```bash
python3 Dcode.py -a datos.txt -fb
```

**Salida Esperada:**

```
🔍 [Fuerza Bruta] Línea 2: ZmxhZ3tzdG9wX3JldmVyc2luZ30=
    ✅ [3] → Entropía: 3.864 | 'flag{stop_reversing}'

🔍 [Fuerza Bruta] Línea 3: SGVsbG8sIHdvcmxkIQ==
    ✅ [3] → Entropía: 3.515 | 'Hello, world!'
```

### Modo de codificación

Utiliza el argumento `-e` o `--encode` para invertir el proceso.

**Ejemplo**: Codificar una cadena con ROT13, luego invertirla y finalmente codificarla en Base64.

```bash
python3 Dcode.py -s "Hello, world!" -e -alg 213
```

## ⚠️ Aviso Legal / Legal Notice

Esta herramienta es unicamente para fines educativos y de auditoria de seguridad autorizada. El uso no autorizado contra sistemas sin el consentimiento explicito del propietario es ilegal. El usuario asume toda responsabilidad por el uso indebido.

This tool is for educational and authorized security auditing purposes only. Unauthorized use against systems without the owner's explicit consent is illegal. The user assumes all responsibility for misuse.
