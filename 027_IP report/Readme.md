 

#  _ip_report 🌐🔍

Este repositorio contiene una herramienta de automatización para analistas de seguridad y equipos de SOC. Su objetivo es agilizar la verificación de reputación de direcciones IP consultando de forma masiva bases de datos de inteligencia de amenazas.

## 📂 Descripción del Proyecto

El script `main.py` actúa como un motor de consulta que centraliza la información de dos de las plataformas más importantes en el ámbito de la ciberseguridad: **VirusTotal** y **AbuseIPDB**.

* **Análisis de Reputación**: Determina instantáneamente si una dirección IP ha sido reportada por actividades maliciosas (malware, phishing, escaneo de puertos).
* **Visualización por Colores**: La salida en terminal utiliza un sistema de semáforos (verde, amarillo, naranja, rojo) basado en el nivel de confianza y el número de detecciones.
* **Consultas por Lotes**: Capacidad para leer archivos de texto con múltiples IPs, ideal para analizar logs de servidores o Firewalls.
* **Gestión de APIs**: Implementa retardos automáticos para evitar el bloqueo de claves API gratuitas.

---

## 🚀 Instalación y Uso

### 1. Preparación del Entorno

Clona el repositorio y asegúrate de tener instalada la librería necesaria:

```bash
pip install requests

```

### 2. Configuración de API Keys

Debes editar el archivo `config.py` e introducir tus propias llaves (tokens) obtenidas de:

* [VirusTotal](https://www.virustotal.com/)
* [AbuseIPDB](https://www.abuseipdb.com/)

### 3. Ejecución

Para iniciar el reporte interactivo:

```bash
python main.py

```

**Flujo de ejecución:** El script te preguntará qué motor deseas utilizar y luego procesará la lista de IPs proporcionada en tu archivo de origen.

---

## ⚠️ Disclaimer (Descargo de Responsabilidad)

**Esta herramienta se proporciona con fines educativos y de auditoría técnica.**

1. **Uso Autorizado**: El usuario es responsable de asegurar que el escaneo de las direcciones IP no infringe ninguna normativa local o los términos de servicio de los proveedores de API.
2. **Límites de Uso**: El uso excesivo de este script con cuentas gratuitas puede llevar a la suspensión de tus credenciales en las plataformas de terceros.
3. **Privacidad**: No introduzcas direcciones IP sensibles o privadas si no deseas que sean consultadas en bases de datos externas públicas.
4. **No Responsabilidad**: El autor no se hace responsable por daños o bloqueos derivados del uso de este software.

---

## 🛠️ Requisitos

* **Python 3.x**
* **API Keys activas** (VirusTotal y AbuseIPDB)
* **Módulo `requests**`

---
 