 
# 🎥 Combinador de Video y Audio (FFmpeg)

Este script de Python automatiza el proceso de **unir un stream de video (.ts) y un stream de audio (.ts)** en un único archivo de salida **.mp4**, utilizando la herramienta de línea de comandos **FFmpeg**.

También incluye un análisis post-conversión para mostrar la duración, resolución y calidad estimada del archivo final.

---

## 🛠️ Requisitos

Asegúrate de tener instalado lo siguiente en tu sistema:

1.  **Python 3**
2.  **FFmpeg:** Debe estar instalado y accesible desde el `PATH` del sistema.

---

## 🚀 Uso

### 1. Configuración de Archivos

El *script* está configurado para buscar los archivos en el siguiente directorio y con los siguientes nombres:

| Elemento | Variable | Ruta Predeterminada |
| :--- | :--- | :--- |
| **Directorio de trabajo** | `DIRECTORIO_TRABAJO` | `Video/` |
| **Video de entrada** | `ARCHIVO_VIDEO_ENTRADA` | `Video/video.ts` |
| **Audio de entrada** | `ARCHIVO_AUDIO_ENTRADA` | `Video/audio.ts` |
| **Salida final** | `ARCHIVO_SALIDA` | `Video/video_ok.mp4` |

**Antes de ejecutar:** Coloca tu archivo `video.ts` y `audio.ts` dentro de una carpeta llamada `Video` en el mismo directorio que el *script* de Python.

### 2. Ejecución

Ejecuta el *script* desde tu terminal:

```bash
python video_audio_ts_en_uno.py
````

### 3\. Salida de Consola

El *script* mostrará un resumen de las acciones tomadas y las características del archivo de salida:

```
✅ Archivos de entrada y directorio validados correctamente.

🛠️ Ejecutando comando ffmpeg...
Comando: ffmpeg -y -i Video\video.ts -i Video\audio.ts -c:v copy -c:a aac -map 0:v:0 -map 1:a:0 -shortest Video\video_ok.mp4

🎉 ¡Éxito! El archivo se ha generado correctamente en: 'Video\video_ok.mp4'

--- Características del Archivo de Salida ---
🕒 Duración total: 00:02:48.00 (168.00 segundos)
🖼️  Resolución de Video: 1280x720
📊 Bitrate de Video: 2.02 Mbps (Estimado)
🔊 Bitrate de Audio: Aprox. 128-192 Kbps (AAC predeterminado)
```

-----

## ⚙️ Comando FFmpeg Utilizado

El *script* utiliza el siguiente comando para combinar los *streams*:

```bash
ffmpeg -y -i video.ts -i audio.ts -c:v copy -c:a aac -map 0:v:0 -map 1:a:0 -shortest output.mp4
```

| Opción | Descripción |
| :--- | :--- |
| `-i [archivo]` | Especifica los archivos de entrada (video y audio). |
| `-c:v copy` | Copia el *stream* de video sin recodificar (rápido y sin pérdida de calidad de video). |
| `-c:a aac` | Recodifica el audio al formato AAC (estándar para MP4). |
| `-map 0:v:0` | Mapea el primer *stream* de video de la primera entrada. |
| `-map 1:a:0` | Mapea el primer *stream* de audio de la segunda entrada. |
| `-shortest` | Termina la codificación cuando el *stream* más corto finaliza. |

```
 