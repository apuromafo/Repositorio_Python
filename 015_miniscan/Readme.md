# Escáner de Puertos con Banner Grabbing 
Este script es un escáner de puertos simple que permite identificar puertos abiertos en un objetivo y obtener información del banner de servicios en esos puertos. 
## Requisitos 
- **Python 3.x**: Asegúrate de tener Python 3.x instalado en tu sistema. ## Uso Para ejecutar el escáner, utiliza el siguiente comando: 
- ```bash python port_scanner.py <objetivo> --puertos <lista_de_puertos>

### Parámetros

- `<objetivo>`: La dirección IP o el dominio que deseas escanear.
- `--puertos`: Una lista de puertos a escanear. Puedes incluir rangos, por ejemplo, `20-80` para escanear de 20 a 80.

### Salida Esperada

El script mostrará los puertos abiertos junto con el banner y el servicio asociado. Por ejemplo:


```
Puerto 22 está abierto. Banner: SSH-2.0-OpenSSH_7.9, Servicio: SSH
Puerto 80 está abierto. Banner: HTTP/1.1 200 OK, Servicio: HTTP
```

Si no se encuentran puertos abiertos, el script informará:



```
No se encontraron puertos abiertos.
```

## Notas

- Asegúrate de tener permisos adecuados para escanear el objetivo.
- El escaneo de puertos puede ser considerado intrusivo. Usa este script con responsabilidad y solo en redes donde tengas permiso para hacerlo.