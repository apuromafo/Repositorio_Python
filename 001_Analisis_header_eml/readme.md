# Validación de Headers de EML

## 01 Datos básicos

Para analizar un correo electrónico en formato EML, ejecuta el siguiente comando:

python .\analisisheader.py .\correo.eml


 

### Salida esperada a tener en cuenta:
```
Información del correo:
Asunto: Asunto
Remitente: remitente
Destinatario: Destinatario
Cuerpo: Cuerpo del mensaje
```


## 02 Datos básicos más MTAs

En el contexto defensivo, **MTAs** se refiere a **Mail Transfer Agents**. Estos son servidores de correo que se encargan de la transferencia y entrega de mensajes de correo electrónico
Para obtener información básica del correo y extraer los MTAs, ya está integrado en el uso

python .\analisisheader.py .\correo.eml

### Salida esperada sin la api AbuseIPDB
Información del correo:
Asunto: Asunto
Remitente: remitente
Destinatario: Destinatario
Cuerpo: Cuerpo del mensaje

MTAs encontrados:
IP: 111.111.111.11
web: sitio.com
onion: qqvbgcu6kohbkxbs.onion


 

## 02 Datos básicos más MTAs y validación con AbuseIPDB (API gratuita)

Para realizar un análisis completo con validación de MTAs usando la API de AbuseIPDB, ejecuta:

python .\analisisheader.py .\correo.eml

 

### Salida esperada:
Información del correo:
Asunto: Asunto
Remitente: remitente
Destinatario: Destinatario
Cuerpo: Cuerpo del mensaje

MTAs encontrados:
IP: 111.111.111.11 : pass (IP de host)
web: sitio.com : pass (IP de host: 222.222.222.222)
onion: qqvbgcu6kohbkxbs.onion : Invalid IP

 

## Notas adicionales

- Asegúrate de tener un archivo `config.api` con tu clave de API para habilitar la validación de IPs.
- Si no se proporciona un archivo EML como argumento, el script entrará en modo interactivo, permitiendo la entrada manual de la ruta del archivo.