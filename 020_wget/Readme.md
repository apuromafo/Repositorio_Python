
# **Downloader - Herramienta de Descarga Inspirada en Wget**

## **Descripción**
Este script es una herramienta de descarga inspirada en `wget`, diseñada para descargar archivos específicos desde un sitio web. Está optimizada para ser amigable con hispanohablantes y no requiere dependencias externas adicionales más allá de la biblioteca estándar de Python.

El script permite:
- Descargar archivos con extensiones permitidas (por ejemplo: `.pdf`, `.jpg`, `.zip`, etc.).
- Validar URLs antes de intentar la descarga.
- Crear automáticamente la carpeta de destino si no existe.
- Saltar archivos ya existentes para evitar sobrescribirlos.

---

## **Requisitos**
- **Python 3.x**: El script está diseñado para funcionar con Python 3.6 o superior.
- **Sin dependencias externas**: Solo utiliza módulos de la biblioteca estándar de Python (`os`, `re`, `urllib`, `argparse`).

---

## **Instalación**
1. Clona este repositorio o copia el script `wgetCLI.py` en tu máquina.
2. Asegúrate de tener Python instalado. Puedes verificarlo ejecutando:
   ```bash
   python --version
   ```
3. ¡Listo! No se requiere ninguna instalación adicional.

---

## **Uso**
El script se ejecuta desde la línea de comandos. Sigue estos pasos:

### **Sintaxis Básica**
```bash
python wgetCLI.py <URL_DEL_SITIO> <CARPETA_DESTINO>
```

### **Parámetros**
- `<URL_DEL_SITIO>`: La URL del sitio web desde donde deseas descargar los archivos.
- `<CARPETA_DESTINO>`: La ruta de la carpeta donde se guardarán los archivos descargados.

### **Ejemplo**
Supongamos que deseas descargar archivos desde `https://ejemplo.com/recursos` y guardarlos en `/home/usuario/descargas`. Ejecuta el siguiente comando:

```bash
python wgetCLI.py https://ejemplo.com/recursos /home/usuario/descargas
```

### **Salida Esperada**
La salida en la consola podría verse así:

```
Iniciando descarga desde: https://ejemplo.com/recursos
Archivo descargado: /home/usuario/descargas/documento.pdf
Archivo descargado: /home/usuario/descargas/imagen.jpg
El archivo ya existe, saltando: /home/usuario/descargas/archivo.zip
Archivo no permitido, saltando: https://ejemplo.com/video.mp4
Descargas completadas en: /home/usuario/descargas
```

---

## **Extensiones Permitidas**
El script solo descarga archivos con las siguientes extensiones:
- `.pdf`
- `.jpg`, `.jpeg`
- `.png`
- `.gif`
- `.zip`
- `.docx`

Si necesitas agregar más extensiones, modifica la lista `EXTENSIONES_PERMITIDAS` en el código:

```python
EXTENSIONES_PERMITIDAS = ['.pdf', '.jpg', '.jpeg', '.png', '.gif', '.zip', '.docx']
```

---

## **Notas Importantes**
1. **Archivos Existentes**:
   - Si un archivo ya existe en la carpeta de destino, el script lo omitirá para evitar sobrescribirlo.
   
2. **Carpeta de Destino**:
   - Si la carpeta de destino no existe, el script la creará automáticamente.

3. **Errores Comunes**:
   - Si la URL no es válida, el script mostrará un mensaje de error.
   - Si ocurre un problema durante la descarga, el error se imprimirá en la consola.

---

## **Autor**
- **Nombre**: Apuromafo
- **Versión**: 0.0.3
- **Fecha**: 28.11.2024

 