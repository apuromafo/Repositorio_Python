 
# CORS Auditor Master (v1.6.0) 🛡️

Script universal para auditar CORS manteniendo la autenticación. Soporta los 3 escenarios comunes de entrada de datos.

## 📖 Cómo usarlo

### 1. Preparar la entrada (`input.txt`)
Pega en el archivo cualquiera de estos tres formatos:
1. **Comando cURL** completo.
2. **JSON** (generado por `convert_headers.py`).
3. **Bloque de Headers** (Copiado directo de la pestaña Headers de Burp).

### 2. Ejecutar
```bash
# Detecta automáticamente el formato en input.txt
python3 Cors_auditor.py -p 127.0.0.1:8080

# Usando un archivo específico
python3 Cors_auditor.py -i peticion.txt -p 127.0.0.1:8080

```

## 📂 Organización de Evidencias

El script clasifica todo por dominio y fecha:

* **`Vulnerables/`**: Tu evidencia para el reporte.
* **`No_Vulnerables/`**: Pruebas de robustez fallidas.
* **`audit_source.txt`**: Datos originales de la prueba.

## 🔍 Por qué es importante enviar Auth/Tokens

Muchos servidores solo activan las políticas de CORS una vez que el usuario está autenticado. Si auditas sin tokens, podrías obtener falsos negativos.
 Este script asegura que el **Bearer Token**, las **Cookies** y cualquier **Custom Auth Header** se envíen en cada vector de ataque.

```
 