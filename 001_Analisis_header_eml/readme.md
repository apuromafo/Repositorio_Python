
---

# Validación de Headers de EML

Herramienta para analizar encabezados de correos electrónicos en formato EML, extraer información relevante, validar MTAs (Mail Transfer Agents) y detectar posibles indicadores de phishing.

## Índice
1. [Datos básicos](#01-datos-básicos)
2. [Datos básicos más MTAs](#02-datos-básicos-más-mtas)
3. [Validación con AbuseIPDB](#03-validación-con-abuseipdb-api-gratuita)
4. [Detección de cabeceras de phishing](#04-detección-de-cabeceras-de-phishing)
5. [Notas adicionales](#notas-adicionales)

---

## 01 Datos básicos

Para analizar un correo electrónico en formato EML, ejecuta el siguiente comando:

```bash
python .\analisisheader.py .\correo.eml
```

### Salida esperada:
```
Información del correo:
Asunto: Asunto
Remitente: remitente
Destinatario: Destinatario
Cuerpo: Cuerpo del mensaje
```

---

## 02 Datos básicos más MTAs

En el contexto defensivo, **MTAs** se refiere a **Mail Transfer Agents**. Estos son servidores de correo que se encargan de la transferencia y entrega de mensajes de correo electrónico.

Para obtener información básica del correo y extraer los MTAs, ya está integrado en el uso:

```bash
python .\analisisheader.py .\correo.eml
```

### Salida esperada sin la API de AbuseIPDB:
```
Información del correo:
Asunto: Asunto
Remitente: remitente
Destinatario: Destinatario
Cuerpo: Cuerpo del mensaje

MTAs encontrados:
IP: 111.111.111.11
web: sitio.com
onion: qqvbgcu6kohbkxbs.onion
```

---

## 03 Validación con AbuseIPDB (API gratuita)

Para realizar un análisis completo con validación de MTAs usando la API de AbuseIPDB, asegúrate de tener un archivo `config.api` con tu clave de API.

Ejecuta el siguiente comando:

```bash
python .\analisisheader.py .\correo.eml
```

### Salida esperada:
```
Información del correo:
Asunto: Asunto
Remitente: remitente
Destinatario: Destinatario
Cuerpo: Cuerpo del mensaje

MTAs encontrados:
IP: 111.111.111.11 : pass (IP de host)
web: sitio.com : pass (IP de host: 222.222.222.222)
onion: qqvbgcu6kohbkxbs.onion : Invalid IP
```

---

## 04 Detección de cabeceras de phishing

La herramienta también detecta cabeceras relacionadas con phishing o indicadores de seguridad como Trend Micro. Esto incluye cabeceras como `X-TrendMicro-Phishing`, `X-Spam-Flag`, `X-Virus-Scanned`, entre otras.

### Salida esperada:
```
Cabeceras relacionadas con phishing:
- X-TrendMicro-Phishing
- X-Spam-Flag: YES
- X-Virus-Scanned
```

Si no se encuentran cabeceras sospechosas, se mostrará:
```
Cabeceras relacionadas con phishing:
- Ninguna cabecera sospechosa encontrada.
```

---

## Notas adicionales

1. **Archivo `config.api`:**
   - Asegúrate de tener un archivo `config.api` en el mismo directorio que el script. Este archivo debe contener tu clave de API de AbuseIPDB.
   - Ejemplo de contenido del archivo `config.api`:
     ```
     tu_clave_de_api_aqui
     ```

2. **Modo interactivo:**
   - Si no se proporciona un archivo EML como argumento, el script entrará en modo interactivo, permitiendo la entrada manual de la ruta del archivo.
   - Para salir del modo interactivo, ingresa `salir`.

3. **Límites de la API de AbuseIPDB:**
   - La API gratuita de AbuseIPDB tiene un límite de 1,000 solicitudes por día. Asegúrate de no exceder este límite.

4. **Requisitos:**
   - Python 3.x
   - Bibliotecas necesarias: `email`, `re`, `socket`, `http.client`, `json`, `os`, `argparse` (todas están incluidas en la biblioteca estándar de Python).

5. **Compatibilidad:**
   - El script ha sido probado en sistemas Windows y Linux. Asegúrate de usar la ruta correcta del archivo EML según tu sistema operativo.

---
 