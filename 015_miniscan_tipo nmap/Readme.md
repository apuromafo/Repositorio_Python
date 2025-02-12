###Escáner de Puertos con Banner Grabbing

Este script es un escáner de puertos simple que permite identificar puertos abiertos en un objetivo y obtener información del banner de servicios en esos puertos. Además, incluye manejo avanzado de errores, verificación de dependencias y soporte para la instalación automática de módulos necesarios.

Requisitos
Python 3.x : Asegúrate de tener Python 3.x instalado en tu sistema.
Nmap : Este script utiliza Nmap para ciertas funcionalidades. Si no está instalado, el script intentará notificarte y detenerse hasta que lo instales.
Módulos de Python : Los módulos necesarios (socket, argparse, etc.) se instalarán automáticamente si no están presentes.
Instalación de Dependencias
El script verificará automáticamente si las dependencias necesarias están instaladas. Si falta algún módulo de Python, intentará instalarlo usando pip. Si nmap no está instalado, el script te notificará y detendrá la ejecución hasta que lo instales manualmente.

Para instalar Nmap manualmente:

Linux :
 
```bash
sudo apt-get install nmap
```

macOS :
  
```bash
brew install nmap
```
 
Windows : Descarga e instala Nmap desde https://nmap.org/download.html .
Uso
Para ejecutar el escáner, utiliza el siguiente comando:
 
```python
python3 port_scanner.py <objetivo> --puertos <lista_de_puertos>
```
 
Parámetros
```
<objetivo>: La dirección IP o el dominio que deseas escanear.
--puertos: Una lista de puertos a escanear. Puedes incluir rangos, por ejemplo, 20-80 para escanear de 20 a 80. Por defecto, el script escanea todos los puertos (1-65535).
```
Ejemplo de uso:

```python
python3 port_scanner.py 192.168.1.1 --puertos 20-100 443 8080
```
 
 
 
Salida Esperada
El script mostrará los puertos abiertos junto con el banner y el servicio asociado. Por ejemplo:

```
Puerto 22 está abierto. Banner: SSH-2.0-OpenSSH_7.9, Servicio: SSH
Puerto 80 está abierto. Banner: HTTP/1.1 200 OK, Servicio: HTTP
```

Si no se encuentran puertos abiertos, el script informará:


```
No se encontraron puertos abiertos.
```
