# 📊 Jasper CLI Suite v2.0

**Jasper CLI Suite** es una herramienta integral de línea de comandos en Python diseñada para el análisis, compilación, descompilación y conversión de reportes de **JasperReports**. Esta suite es especialmente útil para tareas de pentesting, auditoría de seguridad y mantenimiento de reportes.

---

## 🛠️ Módulos Principales

La suite consta de cuatro herramientas especializadas accesibles desde un lanzador central:

1. **Analizar (`analisys.py`)**: Realiza auditorías de archivos `.jrxml` y `.jasper`, extrayendo metadatos, textos, consultas SQL e imágenes embebidas en Base64.
2. **Convertir (`convertir.py`)**: Convierte archivos `.jasper` a formato PDF de forma silenciosa, evitando la salida ruidosa de la JVM.
3. **Compilar (`compilar.py`)**: Compila archivos fuente `.jrxml` en binarios `.jasper` utilizando un puente Java dedicado.
4. **Descompilar (`decompilar_v3.py`)**: Reconstruye archivos `.jrxml` a partir de binarios `.jasper` y realiza un análisis de seguridad automatizado en busca de vulnerabilidades comunes (SQLi, RCE, LFI, etc.).

---

## 🚀 Características Destacadas

* **Auditoría de Seguridad**: El módulo de descompilación incluye un motor de análisis que detecta riesgos como:
    * **Inyecciones (SQLi, LFI)**
    * **Ejecución de Comandos (RCE)**
    * **Exposición de Datos Sensibles (PII)**
* **Operaciones Silenciosas**: Conversión eficiente sin mensajes innecesarios en consola.
* **Gestión de Archivos**: Generación de hashes SHA-256 para integridad, manejo de rutas inteligente y protección contra sobrescritura.
* **Lanzador Interactivo (`main.py`)**: Interfaz sencilla para ejecutar cualquiera de los módulos sin recordar comandos largos.

---

## ⚙️ Instalación

1.  **Requisitos**: Asegúrate de tener instalado Java JRE o JDK (versión 1.8 o superior).
2.  **Dependencias de Python**: Instala las librerías necesarias ejecutando:
    ```bash
    pip install -r requirements.txt
    ```

---

## 📖 Uso

El método recomendado es a través del lanzador interactivo:

```bash
python main.py