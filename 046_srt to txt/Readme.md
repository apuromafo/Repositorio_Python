# SRT to TXT

Conversor de subtítulos SRT/WEBVTT a texto plano.

### Descripción del Proyecto

**`srt_to_txt.py`** es una herramienta de línea de comandos en Python diseñada para extraer y limpiar el texto de archivos de subtítulos (`.srt` y `.vtt` / `.webvtt`). La principal función del script es eliminar las marcas de tiempo, los números de secuencia y cualquier otro metadato, dejando solo el diálogo o el texto del subtítulo en un archivo de texto plano (`.txt`).

Es ideal para investigadores, creadores de contenido o cualquier persona que necesite procesar grandes volúmenes de transcripciones de video de forma rápida y automatizada.

### Características Principales

  * **Soporte Multi-Formato**: Procesa subtítulos tanto en formato **SRT** como **WEBVTT**.
  * **Procesamiento de Archivos y Carpetas**: Puedes convertir un solo archivo o procesar automáticamente todos los archivos de subtítulos en una carpeta completa.
  * **Nomenclatura Personalizable**: Genera nombres de archivo de salida basados en un patrón flexible que puede incluir el nombre original, la fecha y la hora.
  * **Manejo de Salida**: Te permite especificar una carpeta de salida y sobrescribir archivos existentes si es necesario.

-----

### Requisitos e Instalación

Este script no requiere librerías externas. Solo necesitas tener **Python 3.x** instalado en tu sistema.

Puedes verificar tu versión de Python con el siguiente comando:

```bash
python3 --version
```

-----

### Uso

Para usar el script, ejecuta el comando `python3` seguido del nombre del script y las opciones que desees.

```bash
python3 srt_to_txt.py [OPCIONES]
```

#### ⚙️ Opciones de la Línea de Comandos

| Opción                   | Descripción                                                                                                |
| :----------------------- | :--------------------------------------------------------------------------------------------------------- |
| `-a`, `--archivo`        | **(Obligatorio)** Ruta del archivo de subtítulos individual a procesar.                                    |
| `-f`, `--carpeta`        | **(Obligatorio)** Ruta de la carpeta con archivos de subtítulos para procesar en lote.                     |
| `-o`, `--salida`         | **(Obligatorio)** Ruta de la carpeta donde se guardarán los archivos de salida (`.txt`).                   |
| `-p`, `--patron`         | **(Opcional)** Define un patrón de nombre para los archivos de salida. Sobrescribe la configuración interna del script. Puedes usar las siguientes variables: `{nombre}`, `{fecha}`, `{hora}`. |
| `--sobrescribir`         | **(Opcional)** Si está presente, sobrescribe los archivos de salida existentes sin pedir confirmación.      |

**Nota:** `-a` y `-f` son opciones mutuamente excluyentes, es decir, solo puedes usar una de las dos.

-----

### Ejemplos de Uso

#### 1\. Procesar un único archivo

Limpia el archivo `video_sub.srt` y guarda el resultado como `subtitulo_limpio.txt` en la carpeta `./salida`.

```bash
python3 srt_to_txt.py -a video_sub.srt -o ./salida -p "{nombre}_limpio"
```

#### 2\. Procesar todos los archivos de una carpeta

Limpia todos los archivos de subtítulos en la carpeta `./subtitulos/` y guarda el resultado en la carpeta `./salida`. El nombre de los archivos de salida incluirá el nombre original y la fecha.

```bash
python3 srt_to_txt.py -f ./subtitulos/ -o ./salida -p "{nombre}_{fecha}"
```

#### 3\. Forzar la sobreescritura

Limpia todos los archivos de subtítulos en la carpeta `./subtitulos/` y sobrescribe los archivos de salida existentes en `./salida` sin aviso.

```bash
python3 srt_to_txt.py -f ./subtitulos/ -o ./salida --sobrescribir
```

-----

## ⚠️ Aviso Legal / Legal Notice

Esta herramienta es unicamente para fines educativos y de auditoria de seguridad autorizada. El uso no autorizado contra sistemas sin el consentimiento explicito del propietario es ilegal. El usuario asume toda responsabilidad por el uso indebido.

This tool is for educational and authorized security auditing purposes only. Unauthorized use against systems without the owner's explicit consent is illegal. The user assumes all responsibility for misuse.
