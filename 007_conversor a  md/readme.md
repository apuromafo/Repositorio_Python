
# 📄 Conversor de Documentos HTML y PDF a Markdown

## ✅ Funcionalidades principales  
- **Conversión de HTML a Markdown**  
  - Transforma archivos HTML en Markdown con una marca de tiempo (YYYYMMDD_HHMMSS) en el nombre del archivo.  
  - Mantiene la estructura básica del contenido original.

- **Conversión de PDF(s) a Markdown**  
  - Procesa archivos PDF individuales o directorios conteniendo múltiples PDFs.  
  - Usa un contenedor Docker (markitdown:latest) para procesar los archivos.  
  - Genera archivos con marca de tiempo en su nombre.

---

## 📲 Uso  

### ✅ Modo interactivo  
Ejecuta el script sin argumentos:  
```bash
python conv.py
```

**Menú disponible:**  
- **Convertir HTML a Markdown**:  
  - Ingresa la ruta del archivo HTML y una carpeta de salida (opcional).  
- **Convertir PDF(s) a Markdown (usando Docker)**:  
  - Ingresa la ruta del archivo PDF o directorio con PDFs, y una carpeta de salida (opcional).  
- **Salir**: Finaliza el programa.

---

### ✅ Modo de línea de comandos  
Ejemplos de uso:

#### Convertir un archivo HTML a Markdown:  
```bash
python conv.py --html_entrada "ejemplo.html" [--salida "ejemplo_salida"]
```

**Salida:** `ejemplo_YYYYMMDD_HHMMSS.md` (en la carpeta especificada).

#### Convertir PDFs de un directorio a Markdown:  
```bash
python conv.py --pdf_entrada "C:\\MisPDFs" --salida "C:\\SalidaMarkdown"
```

**Salida:** `C:\\SalidaMarkdown\informe_YYYYMMDD_HHMMSS.md` (para cada PDF).

---

## 📦 Instalación  

### ✅ Requisitos  
- Python 3.x  
- **markdownify** (para HTML a Markdown):  
  ```bash
  pip install markdownify
  ```
- **Docker** (para procesar PDFs):  
  - Instala Docker Desktop en [https://www.docker.com/products/docker-desktop/](https://www.docker.com/products/docker-desktop/)  
  - Clona el repositorio de `markitdown`:  
    ```bash
    git clone https://github.com/microsoft/markitdown.git
    cd markitdown
    ```
  - Construye la imagen:  
    ```bash
    docker build -t markitdown:latest .
    ```

---

## ⚠️ Notas importantes  
- Los archivos Markdown generados incluyen una marca de tiempo para evitar sobrescrituras.  
- La conversión de PDFs utiliza **OCR** si el texto está en capas, pero no procesa imágenes sin texto (ejemplo: PDFs escaneados).  
- `markdownify` usa licencia MIT.

---

## 📝 Licencia  
Este script está bajo la licencia MIT.  
Uso y distribución autorizados de acuerdo con los términos de la licencia [MIT](https://mit-license.org/).

---

## 🔚 Contacto o más información  
Puedes enviar sugerencias o reportar errores a través del repositorio en GitHub:  
[https://github.com/tu-usuario/conversor-markdown](https://github.com/tu-usuario/conversor-markdown)

---

### ✅ Ejemplo de salida (Markdown generado)  
```markdown
# Conversor de Documentos HTML y PDF a Markdown

## 📄 Funcionalidades principales  
- **Conversión de HTML a Markdown**  
  - Transforma archivos HTML en Markdown con una marca de tiempo (YYYYMMDD_HHMMSS) en el nombre del archivo.  
  - Mantiene la estructura básica del contenido original.

- **Conversión de PDF(s) a Markdown**  
  - Procesa archivos PDF individuales o directorios conteniendo múltiples PDFs.  
  - Usa un contenedor Docker (markitdown:latest) para procesar los archivos.  
  - Genera archivos con marca de tiempo en su nombre.

## 📲 Uso  

### ✅ Modo interactivo  
Ejecuta el script sin argumentos:  
```bash
python conv.py
```

**Menú disponible:**  
- **Convertir HTML a Markdown**:  
  - Ingresa la ruta del archivo HTML y una carpeta de salida (opcional).  
- **Convertir PDF(s) a Markdown (usando Docker)**:  
  - Ingresa la ruta del archivo PDF o directorio con PDFs, y una carpeta de salida (opcional).  
- **Salir**: Finaliza el programa.

### ✅ Modo de línea de comandos  
Ejemplos de uso:

#### Convertir un archivo HTML a Markdown:  
```bash
python conv.py --html_entrada "ejemplo.html" [--salida "ejemplo_salida"]
```

**Salida:** `ejemplo_YYYYMMDD_HHMMSS.md` (en la carpeta especificada).

#### Convertir PDFs de un directorio a Markdown:  
```bash
python conv.py --pdf_entrada "C:\\MisPDFs" --salida "C:\\SalidaMarkdown"
```

**Salida:** `C:\\SalidaMarkdown\informe_YYYYMMDD_HHMMSS.md` (para cada PDF).

## 📦 Instalación  

### ✅ Requisitos  
- Python 3.x  
- **markdownify** (para HTML a Markdown):  
  ```bash
  pip install markdownify
  ```
- **Docker** (para procesar PDFs):  
  - Instala Docker Desktop en [https://www.docker.com/products/docker-desktop/](https://www.docker.com/products/docker-desktop/)  
  - Clona el repositorio de `markitdown`:  
    ```bash
    git clone https://github.com/microsoft/markitdown.git
    cd markitdown
    ```
  - Construye la imagen:  
    ```bash
    docker build -t markitdown:latest .
    ```

## ⚠️ Notas importantes  
- Los archivos Markdown generados incluyen una marca de tiempo para evitar sobrescrituras.  
- La conversión de PDFs utiliza **OCR** si el texto está en capas, pero no procesa imágenes sin texto (ejemplo: PDFs escaneados).  
- `markdownify` usa licencia MIT.
```
 

## ⚠️ Aviso Legal / Legal Notice

Esta herramienta es unicamente para fines educativos y de auditoria de seguridad autorizada. El uso no autorizado contra sistemas sin el consentimiento explicito del propietario es ilegal. El usuario asume toda responsabilidad por el uso indebido.

This tool is for educational and authorized security auditing purposes only. Unauthorized use against systems without the owner's explicit consent is illegal. The user assumes all responsibility for misuse.
