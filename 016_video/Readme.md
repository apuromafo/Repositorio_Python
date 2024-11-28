# Video Converter
Este script permite convertir archivos de video en varios formatos a MP4 utilizando `ffmpeg`. ## Requisitos 
- **ffmpeg**: Asegúrate de tener `ffmpeg` disponible en tu sistema.
- _FFmpeg_ está liberado bajo una _licencia_ GNU Lesser General Public _License (FFmpeg está mayormente bajo las licencias GPL y LGPL, que son licencias de software libre)
-
En Windows, puedes instalarlo con Chocolatey usando el siguiente comando: 
- ```choco install ffmpeg```
para validarlo puedes usar
```
ffmpeg.exe -version
```
 
 
El script puede convertir los siguientes formatos a MP4:

- `.ts`
- `.flv`
- `.mkv`
- `.avi`
- `.mov`
- `.wmv`

## Uso

Para utilizar el script, ejecuta uno de los siguientes comandos:

```
python video.py -f /ruta/a/carpeta/con/videos -o /ruta/a/carpeta/salida
```

o, si deseas guardar los archivos convertidos en la misma carpeta de entrada:

```
python video.py -f /ruta/a/carpeta/con/videos
```

## Ejemplo

Aquí tienes un ejemplo de cómo usar el script:


```
python .\video.py -f .\poc1\
```

### Salida Esperada

Al ejecutar el script, deberías ver una salida similar a la siguiente:


```
2024-11-28 00:49:51 ::  INFO ::  video_converter :: Convertido: .\poc1\video_converted_20241128_004819.mp4
Convertido: .\poc1\video_converted_20241128_004819.mp4
Proceso de conversión finalizado. Tiempo transcurrido: 91.78 segundos.
```

## Notas

- Asegúrate de que las rutas sean correctas y que los archivos de entrada existan.

