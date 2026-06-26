# SCA Auditoría Grype

Este script de Python automatiza el análisis de vulnerabilidades en código fuente (SCA - Software Composition Analysis) utilizando **Grype** a través de **Docker**. Genera un reporte detallado en formato `.txt` con un resumen ejecutivo y detalles técnicos por cada hallazgo.

## 🚀 Características

* **Análisis automático:** Utiliza la imagen oficial de `anchore/grype`.
* **Reportes limpios:** Genera un archivo `.txt` con tablas de resumen por severidad.
* **Enlaces directos:** Incluye referencias a **OSV**, **GitHub Advisories** y **NVD (NIST)**.
* **Manejo de errores:** Verifica si Docker está corriendo y gestiona tiempos de espera.
* **Sin instalación local:** No necesitas instalar Grype en tu sistema, solo tener Docker.

## 📋 Requisitos Previos

1. **Python 3.x** instalado.
2. **Docker** instalado y en ejecución.
3. Permisos para ejecutar comandos de Docker.

## 🛠️ Instalación

1. Copia el archivo `SCA_Auditoria_grype.py` a tu carpeta de herramientas o a la raíz del proyecto a analizar.
2. (Opcional) Asegúrate de tener conexión a internet la primera vez para que el script descargue la imagen de Grype.

## 📖 Modo de Uso

Puedes ejecutar el script de dos maneras:

### 1. Analizar el directorio actual

```bash
python SCA_Auditoria_grype.py

```

### 2. Analizar una ruta específica

```bash
python SCA_Auditoria_grype.py /ruta/al/proyecto

```

## 📊 Ejemplo del Reporte Generado

El script creará un archivo llamado `auditoria_grype_nombre_20251230_1300.txt` con el siguiente formato:

```text
================================================================================
REPORTE DE SEGURIDAD GRYPE - MI_PROYECTO
FECHA: 30/12/2025 13:00:00
================================================================================

RESUMEN DE HALLAZGOS
+--------------------+---------------+
| SEVERIDAD          | CANTIDAD      |
+--------------------+---------------+
| Critical           | 2             |
| High               | 5             |
...
+--------------------+---------------+
| TOTAL ÚNICOS       | 7             |
+--------------------+---------------+

DETALLE DE VULNERABILIDADES (ORDENADO POR SEVERIDAD)
================================================================================
ID #1 | CVE-2023-XXXX | [CRITICAL]
  - REFERENCIAS:
      -> https://nvd.nist.gov/vuln/detail/CVE-2023-XXXX
  - DESCRIPCIÓN: Vulnerabilidad crítica detectada en...
  - SOLUCIÓN:    Upgrade to version 1.2.3
  - AFECTA A:
      [!] lib-name (v1.2.0) en ./package.json
------------------------------------------------------------

```

## ⚠️ Notas

* El script siempre intenta actualizar la base de datos de vulnerabilidades antes de empezar. Si falla o no hay internet, intentará usar la versión local de la imagen.
* El tiempo de espera para la actualización está configurado en **60 segundos**.

--- 

## ⚠️ Aviso Legal / Legal Notice

Esta herramienta es unicamente para fines educativos y de auditoria de seguridad autorizada. El uso no autorizado contra sistemas sin el consentimiento explicito del propietario es ilegal. El usuario asume toda responsabilidad por el uso indebido.

This tool is for educational and authorized security auditing purposes only. Unauthorized use against systems without the owner's explicit consent is illegal. The user assumes all responsibility for misuse.
