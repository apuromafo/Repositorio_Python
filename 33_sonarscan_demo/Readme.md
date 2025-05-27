# SonarQube Report Generator

Herramienta de línea de comandos para generar reportes de seguridad desde SonarQube usando plantillas personalizadas.

---

## 🧩 Descripción

Este script permite a los equipos de ciberseguridad:
- Generar informes técnicos automáticamente desde SonarQube.
- Comparar y actualizar valores desde `sonar-scanner.properties` si hay diferencias.
- Comprimir resultados en ZIP (opcional).
- Ser multiplataforma (Windows, Linux, macOS).

---

## ✅ Requisitos

1. **Java instalado**  
   Asegúrate de tener Java disponible:  
   ```bash
   java -version
   ```

2. **Sonar Scanner configurado**  
   Debe existir el archivo:
   ```
   sonar-scanner.properties
   ```
   Con estas claves:
   ```ini
   sonar.host.url=https://tu-instancia.sonarqube.com/
   sonar.token=squ_xx_xxxxxxxxxxxxxxx
   ```

3. **Archivos necesarios**
   - `sonar-cnes-report-X.Y.Z.jar`
   - Plantilla Word: `code-analysis-template.docx`  
     *(Recomendado dentro de una carpeta llamada `plantillas/`)*

---

## ⚙️ Configuración

Crea un archivo `config.ini` con esta estructura:

```ini
[SonarQube]
sonar.token = squ_xx_xxxxxxxxxxxxxxx
url = https://tu-instancia.sonarqube.com/
NombreReporte = Nombre Reporte
ruta_jar = sonar-cnes-report-5.0.2.jar
ruta_plantilla = code-analysis-template.docx
```

Si no existe, el script lo crea automáticamente con valores por defecto.

---

## 🚀 Uso del Script

### 1. Mostrar ayuda
```bash
python reporte.py -h
```

### 2. Generar reporte normal
```bash
python reporte.py -p mi-proyecto -o ./salida
```

### 3. Generar reporte comprimido
```bash
python reporte.py -r BUG-XXXX
```

---

## 📁 Estructura recomendada

```
Sonar_Report/
│
├── reporte.py              # Este script
├── config.ini               # Se genera automáticamente
├── sonar-cnes-report-5.0.2.jar
└── plantillas/
    └── code-analysis-template.docx
```

---

## 🛠️ Variables de entorno (opcionales)

| Variable         | Descripción |
|------------------|-------------|
| `SONAR_PROYECTO` | Nombre del proyecto en SonarQube |
| `SONAR_SALIDA`   | Carpeta base donde guardar los resultados |
| `SONAR_REPORTE`  | Genera un ZIP con el resultado |
| `SONAR_BASE_DIR` | Ruta base donde están los recursos |
| `SONAR_CONFIG`   | Archivo de configuración personalizado |

---

## 📌 Notas importantes

- El script puede funcionar sin `config.ini`, creándolo automáticamente.
- Pregunta si quieres actualizarlo si detecta cambios en `sonar-scanner.properties`.
- Es multiplataforma: funciona en Windows, Linux y macOS.
- Usa mensajes claros en español para facilitar su uso en equipo.

 