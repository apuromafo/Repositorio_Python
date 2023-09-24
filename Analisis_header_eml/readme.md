validación de header de eml.
 
 ## 01 Datos básicos

```
python3 .\scriptv1.py .\correo.eml
```
```
Información del correo:
Asunto: Asunto
Remitente: remitente
Destinatario: Destinatario
Cuerpo: Cuerpo del mensaje
```

 ## 02 Datos básicos mas mta
```
python3 .\scriptv2.py .\correo.eml
```
```
Información del correo:
Asunto: Asunto
Remitente: remitente
Destinatario: Destinatario
Cuerpo: Cuerpo del mensaje

MTAs encontrados:
IP:111.111.111.11
web: sitio.com
onion:qqvbgcu6kohbkxbs.onion
```


 ## 03 Datos básicos mas mta,  más validación con abuseip (api sdk free)
```
python3 .\scriptv3.py .\correo.eml
```
```
Información del correo:
Asunto: Asunto
Remitente: remitente
Destinatario: Destinatario
Cuerpo: Cuerpo del mensaje

MTAs encontrados:
IP:111.111.111.11 : pass (IP de host:
web: sitio.com : pass (IP de host:222.222.222.222)
onion:qqvbgcu6kohbkxbs.onion  :Invalid IP
```   
