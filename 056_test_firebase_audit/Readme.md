# 🛡️ Auditor de Reglas de Seguridad de Firebase (REST API)

Este script de Python (`security_audit.py`) es una **herramienta de prueba de concepto (PoC)** diseñada para auditar rápidamente las **Reglas de Seguridad** de tus servicios de Firebase (**Firestore**, **Realtime Database**, y **Cloud Storage**) comprobando si permiten acceso **público (no autenticado)** de lectura o escritura.

-----

## ⚙️ Requisitos

  * **Python 3.x**
  * Biblioteca `requests`:



```bash
pip install requests
```

-----

## 🛠️ Configuración

Antes de ejecutar el script, debes configurar la sección `--- 0. CONFIGURACIÓN DEL PROYECTO ---` dentro del archivo `security_audit.py` con tus credenciales reales y datos de prueba.

### Configuración de Firebase (`FIREBASE_CONFIG`):

Reemplaza los valores *dummy* por la configuración de tu proyecto de Firebase. Puedes encontrar estos valores en la **Consola de Firebase**, bajo **Configuración del Proyecto**.

```python
FIREBASE_CONFIG = {
    "apiKey": "TU_API_KEY_AQUI",
    "authDomain": "tu-proyecto.firebaseapp.com",
    "projectId": "tu-project-id",
    # ... otros campos
}
```

### Token de Autenticación (`AUTH_TOKEN`):

Deja el valor *dummy* si solo quieres probar el acceso público. Para realizar pruebas de acceso autenticado (sección B de las pruebas), debes proporcionar un **JWT Token ID válido** generado por Firebase para un usuario.

### Archivo de Prueba de Storage (`STORAGE_TEST_FILENAME`):

**CRÍTICO**: Debes reemplazar `"test_file_for_audit.txt"` con el nombre de un **archivo real que exista** en tu Cloud Storage Bucket. Si el archivo no existe, la prueba de lectura devolverá **404 (inconcluso)**.

-----

## ▶️ Uso

Ejecuta el script directamente desde la terminal:

```bash
python security_audit.py
```

-----

## 📋 Interpretación de Resultados

El script imprimirá un resumen al final para cada servicio (**CFS**, **CS**, **RTDB**).

| Servicio y Prueba | Código HTTP 200 (Éxito) | Código HTTP 403 / 401 (Denegado) | Acceso Anónimo |
| :--- | :--- | :--- | :--- |
| **Lectura/Escritura** | **🔴 VULNERABLE**. La regla permite la acción sin autenticación. | **🟢 SEGURO**. La regla bloquea correctamente el acceso. |

**Nota sobre Cloud Storage (CS)**: Si la prueba de lectura de archivo (**GET**) devuelve **404**, significa que el archivo de prueba no se encontró, y el resultado de seguridad es **inconcluso** para esa prueba específica.

🛑 Descargo de Responsabilidad y Uso Ético
ESTA HERRAMIENTA ES SOLO PARA FINES EDUCATIVOS Y DE AUDITORÍA DE SEGURIDAD INTERNA.

CRÍTICO: Nunca ejecutes este script o cualquier otra prueba de seguridad similar contra proyectos de Firebase que no te pertenezcan o para los cuales no tengas autorización explícita y por escrito de su propietario. La realización de pruebas no autorizadas puede considerarse un ataque y es ilegal.

Se recomienda encarecidamente ejecutar estas pruebas solo en un entorno de desarrollo/staging o durante una ventana de auditoría autorizada por tu equipo de seguridad.