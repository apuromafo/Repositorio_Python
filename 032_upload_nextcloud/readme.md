# 📁 Script de Subida a Nextcloud

Este script permite subir archivos o carpetas completas a un servidor **Nextcloud** y generar un enlace público de descarga.

---

## ✅ Características

- Subida individual de archivos.
- Subida recursiva de carpetas.
- Generación automática de enlaces públicos con permisos de solo lectura.

---

## 🛠️ Requisitos

Asegúrate de tener instaladas las siguientes dependencias:

```bash
pip install requests
```

---

## ⚙️ Configuración

Antes de usar el script, debes configurar los siguientes parámetros al inicio del archivo:

```python
NEXTCLOUD_URL = "https://tu-servidor-nextcloud.com"
USERNAME = "tu_usuario"
PASSWORD = "tu_contraseña"
```

Reemplaza con tus credenciales reales de Nextcloud.

---

## 📤 Uso

### Subir un archivo

```bash
python nextcloud_upload.py --archivo /ruta/a/tu/archivo.txt
```

### Subir una carpeta completa

```bash
python nextcloud_upload.py --carpeta /ruta/a/tu/carpeta
```

---

## 🧾 Salida Ejemplo

```
✅ Archivo subido exitosamente: /ruta/local/archivo.txt -> /archivo.txt
🔗 Enlace compartido:
   https://tu-servidor-nextcloud.com/s/XXXXXXXXXXXXXX
```

---

## ⚠️ Notas importantes

- Este script utiliza autenticación básica (HTTPBasicAuth), por lo tanto, asegúrate de usar una conexión HTTPS.
- Guarda tus credenciales de forma segura. No compartas este script si contiene información sensible.



## ⚠️ Aviso Legal / Legal Notice

Esta herramienta es unicamente para fines educativos y de auditoria de seguridad autorizada. El uso no autorizado contra sistemas sin el consentimiento explicito del propietario es ilegal. El usuario asume toda responsabilidad por el uso indebido.

This tool is for educational and authorized security auditing purposes only. Unauthorized use against systems without the owner's explicit consent is illegal. The user assumes all responsibility for misuse.
