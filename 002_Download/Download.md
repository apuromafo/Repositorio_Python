# Downloader GUI 

![[Pasted image 20241118192258.png]]

## Descripción 
Este proyecto es una aplicación de interfaz gráfica de usuario (GUI) en Python que permite descargar archivos desde URLs especificadas y gestionar la descarga de múltiples sitios listados en un archivo de texto.
 También muestra la dirección IP actual del usuario y permite elegir si abrir o no el archivo descargado. 
## Características 
- **Interfaz de usuario intuitiva**: Facilita la entrada de la URL de origen y el nombre del archivo de destino. 
- **Descarga de múltiples archivos**: Permite la carga de un archivo `.txt` que contenga URLs, facilitando la descarga en lote. 
- **Visualización de la IP**: Muestra la dirección IP actual del usuario. 
- **Opciones de descarga**: Permite elegir si abrir el archivo descargado automáticamente. 

## Requisitos 
- Python 3.x - Bibliotecas: `requests`, `tkinter` 
- ## Instalación 
1. Clona el repositorio o descarga los archivos del proyecto. 
2. Asegúrate de tener Python 3 instalado en tu sistema. 
3. Instala la biblioteca `requests` si aún no lo has hecho: ```bash pip install requests

## Uso

1. Ejecuta el script `downloader.py`:
    
    ```
    python downloader.py
    ```
    
2. Ingresa la URL de origen y el nombre del archivo de destino.
    
3. Si deseas descargar múltiples archivos, crea un archivo de texto (por ejemplo, `urls.txt`) que contenga las URLs, cada una en una nueva línea.
    
4. Haz clic en "Download" para iniciar la descarga.
    
5. La dirección IP actual aparecerá en el campo correspondiente.
    
6. Selecciona si deseas abrir el archivo descargado o no.

