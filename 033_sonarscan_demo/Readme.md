# 🚀 Orquestador de Seguridad Ofensiva - SonarQube

Herramienta profesional de automatización para el ciclo de vida de análisis estático (SAST). Este ecosistema garantiza un proceso **transparente, validado y estandarizado** bajo nomenclaturas de tickets (BUG/GVDR), eliminando errores manuales en la configuración y reporte.

---

## 🎮 Interfaz Principal (`00_Main.py`)

El flujo de trabajo se gestiona desde un único punto de control. Al ejecutar el orquestador, tendrás acceso a la siguiente estructura lógica:

### **Fase A: Preparación y Entorno**

* **[1] Configuración**: Sincroniza URL y Tokens en `config.ini` y `sonar-project.properties`.
* **[2] Saneamiento**: Limpia rutas obsoletas en el PATH de Windows y valida el entorno.
* **[3] Scanner CLI**: Descarga y despliega la última versión oficial de SonarScanner.
* **[4] Test de Vuelo**: Valida la conectividad API y la ejecución del binario antes de escanear.
* **[5] Motor de Reportes**: Descarga el JAR de CNES Report desde los releases oficiales.

### **Fase B: Ejecución de Análisis**

* **[6] Generador de Comandos**: Interfaz interactiva para crear el comando de escaneo basado en el ticket (Maven, Gradle, .NET, CLI). **Genera la identidad del proyecto.**

### **Fase C: Cierre y Entrega**

* **[7] Módulo de Reportes**: Generación de entregables técnicos (CNES) y oficiales (Regulatory).
* **[8] SECUENCIA COMPLETA**: Ejecuta automáticamente los pasos del 1 al 5 y finaliza con el reporte (Paso 7).



---

## 🚀 Guía de Inicio Rápido

### Modo Orquestado (Recomendado)

Para mantener la fluidez y validación de todos los pasos:

```bash
python 00_Main.py

```

### Modo Directo (Expertos)

Si ya tienes el entorno configurado y solo necesitas alguna funcion, solo usa python con el numero respectivo y ve el uso normal, ejemplo 
```bash
python 07_reporte.py -p BUG-1787 -o salida 

```

---

## 📂 Caja de Herramientas (Archivos Clave)

| Archivo | Rol en el Sistema |
| --- | --- |
| `config.ini` | **Fuente de Verdad**: Almacena URL, Token, Plantillas y Autor. |
| `temp_project_name.txt` | **Puente**: Pasa el nombre del proyecto entre el generador y el reporte. |
| `sonar-project.properties` | **Sync**: Configuración técnica para el motor de escaneo. |
| `Reportes_Generados/` | **Salida**: Almacén automatizado de resultados y archivos ZIP. |

---

## 📝 Requisitos del Sistema

* **Python 3.8+**
* **Java JRE/JDK 11+** (Requerido para SonarScanner y CNES Report)
* **Acceso a Red**: Conexión activa a la VPN corporativa.

---

**Seguridad Ofensiva** | *Automatizando la calidad del código.*