
# 🔎 JWT File Extractor & Decoder (Extractor y Decodificador de JWT)

Herramienta en **Python** diseñada para escanear archivos de texto (*logs*, volcados de tráfico, bases de datos) en busca de posibles **JSON Web Tokens (JWT)**, decodificar sus secciones de *Header* y *Payload*, y guardar la información legible en un archivo de salida y en una auditoría de *log* separada.

-----

## 🛑 Aviso Legal y Descargo de Responsabilidad

  * **Propósito:** Este *script* ha sido creado únicamente con fines de **investigación**, **análisis** y **desarrollo de seguridad**. Su función es asistir en la extracción de datos en un entorno controlado y autorizado.
  * **Uso Ético:** El usuario es el **único responsable** de asegurar que tiene el permiso explícito y legal para escanear y analizar los archivos de entrada. El uso de esta herramienta para acceder o analizar información confidencial, privada o de terceros sin la debida autorización está estrictamente prohibido y puede ser ilegal.
  * **Limitación:** Este *script* **no verifica la firma** (*Signature*) del JWT. Solo extrae y decodifica las secciones *Header* y *Payload*, que están codificadas en **Base64Url**. Un *token* decodificable no implica que sea válido o que su firma sea correcta.

-----

## ✨ Características Principales

  * **Extracción de JWT:** Utiliza una **expresión regular robusta** para buscar el patrón estándar de JWT (`Header.Payload.Signature`).
  * **Decodificación Automática:** Decodifica las secciones *Header* y *Payload* (codificadas en Base64Url) a **formato JSON legible**.
  * **Rutas Absolutas:** Manejo mejorado de rutas, permitiendo el escaneo de archivos desde **cualquier directorio del sistema**.
  * **Output de Auditoría:** Genera un archivo de *log* separado (`auditoria_[fecha].log`) que registra la ejecución, errores y la cantidad de *tokens* encontrados.
  * **Archivos de Salida Limpios:** Los *tokens* decodificados se guardan en un archivo de salida con formato limpio y legible por humanos.

-----

## 🚀 Uso e Instalación

### Requisitos Previos

  * **Python 3.x**
  * **Dependencias:** El *script* solo utiliza librerías **estándar** de Python (`re`, `json`, `base64`, `sys`, `logging`, `os`, `datetime`).

### Ejecución

El *script* requiere exactamente **dos argumentos**: el archivo de entrada y el archivo de salida.

**Formato de Uso:**

```bash
python3 jwt_extractor.py <archivo_entrada> <archivo_salida>
```

**Ejemplo de Uso:**

Si tienes un volcado HTTP llamado `traffic.txt` y quieres guardar los resultados en `decoded_tokens.txt` en el mismo directorio:

```bash
python3 jwt_extractor.py traffic.txt decoded_tokens.txt
```

#### Notas sobre las Rutas

  * Si proporcionas una ruta de archivo de entrada que no existe, el *script* mostrará un error.
  * Si el archivo de salida se proporciona con una ruta relativa, se creará por defecto en el mismo directorio que el archivo de entrada para mantener la organización.

-----

## 📜 Historial de Versiones

| Versión | Fecha | Estado | Cambios/Notas |
| :--- | :--- | :--- | :--- |
| **v1.1.0** | 2025-09-23 | ESTABLE | ✅ Añadido: Control de rutas absolutas para escanear archivos desde cualquier directorio. ✅ Mejorado: Manejo de errores para rutas de archivo no encontradas. ✅ Ajustado: Lógica para la creación de archivos de salida en el mismo directorio del archivo de entrada por defecto. |
| **v1.0.0** | 2025-09-19 | INICIO | ✅ Prototipo inicial para extracción y decodificación de JWTs. ✅ Funcionalidad básica para escanear archivos locales. ❌ No maneja rutas relativas fuera del directorio de ejecución. |