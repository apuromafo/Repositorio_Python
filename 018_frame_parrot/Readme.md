# Animación ASCII de Loro(parrot)

## Descripción

Este programa genera una animación ASCII de un loro en la terminal. La animación está inspirada en el comando `curl.exe ascii.live/parrot`. El código utiliza una serie de "frames" (cuadros) representados como arte ASCII, y los muestra en secuencia para simular el movimiento del loro.

## Autor

- **Autor**: Apuromafo  
- **Versión**: 0.0.1  
- **Fecha**: 28.11.2024  

## Requisitos

- Python 3.x
- Terminal que soporte caracteres ASCII y limpieza de pantalla (`cls` para Windows o `clear` para Unix/Linux/Mac).

## Instalación

No es necesario instalar dependencias adicionales. Simplemente asegúrate de tener Python instalado en tu sistema.

## Uso

Para ejecutar la animación, simplemente ejecuta el script de Python:

```bash
python ascii_loro.py
```

Esto iniciará la animación del loro en tu terminal.

## Código Fuente

El archivo principal es `ascii_loro.py`, que contiene la lógica para mostrar la animación. A continuación se describe brevemente su funcionamiento:

- **`clear_screen()`**: Limpia la pantalla para preparar cada frame.
- **`display_frame(frame)`**: Muestra un frame específico en la terminal.
- **`animate_loro(frames, delay=0.1)`**: Recibe una lista de frames y los muestra uno por uno con un retraso entre ellos para crear la ilusión de movimiento.

Los frames están almacenados en la variable `loro_frames`, que es una lista de cadenas de texto ASCII que representan al loro en diferentes posiciones.

## Licencia

Este proyecto está bajo la licencia [MIT](LICENSE). Consulta el archivo `LICENSE` para más detalles.

## Créditos

- Inspirado en el comando `curl.exe ascii.live/parrot`.
- Arte ASCII generado por pequeños ascii

---

¡Esperamos que disfrutes de esta pequeña animación ASCII !
```
 