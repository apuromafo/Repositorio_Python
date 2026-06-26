# 📱 Herramientas de Análisis Móvil (006_Móvil)

Este directorio contiene una colección de scripts y herramientas desarrolladas en **Python 3** para auditorías de seguridad en dispositivos móviles, cubriendo tanto ecosistemas Android como iOS.

## 📂 Estructura del Proyecto

* **[Android](./Android/):** Herramientas específicas para análisis de APKs, interacción con ADB, y detección de vulnerabilidades en aplicaciones Android.
* **[iOS](./iOS/):** Scripts para análisis de IPAs, inspección de binarios Mach-O y herramientas auxiliares para entornos jailbroken.

## 🚀 Requisitos Generales

Para ejecutar la mayoría de los scripts en estas carpetas, asegúrate de tener instalado:

- **Python 3.x**
- **ADB (Android Debug Bridge)** para pruebas en Android.
- **Frida-tools** (opcional, recomendado para instrumentación dinámica).

## 🛠️ Instalación de Dependencias

Se recomienda usar un entorno virtual:

```bash
python -m venv venv
source venv/bin/activate  # En Windows: venv\Scripts\activate
pip install -r requirements.txt

## ⚠️ Aviso Legal / Legal Notice

Esta herramienta es unicamente para fines educativos y de auditoria de seguridad autorizada. El uso no autorizado contra sistemas sin el consentimiento explicito del propietario es ilegal. El usuario asume toda responsabilidad por el uso indebido.

This tool is for educational and authorized security auditing purposes only. Unauthorized use against systems without the owner's explicit consent is illegal. The user assumes all responsibility for misuse.
