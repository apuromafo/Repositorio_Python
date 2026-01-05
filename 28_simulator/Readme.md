 --

# SIMlog - Multi-Brand Log Simulator

**SIMlog** es un script en Python diseñado para la generación y simulación de logs sintéticos de múltiples fabricantes de red y sistemas operativos. 
Su propósito principal es apoyar a los equipos de **Red Team** y **Pentesting** en la validación de reglas de detección, inundación de logs (noise generation) y pruebas de integración con SIEMs (como Wazuh, QRadar, Splunk o Elastic).

## 🚀 Características

* **Soporte Multi-Marca**: Genera logs con formatos específicos de:
* **Fortinet** (FortiGate)
* **Cisco** (IOS, FTD)
* **Palo Alto Networks** (PAN-OS)
* **Windows** (Event IDs de seguridad: 4624, 4625, 4720, etc.)
* **Linux** (Eventos de autenticación, procesos, red y auditoría)
* **MikroTik**
* **Huawei** (USG6300)


* **Variabilidad de Datos**: Utiliza placeholders para inyectar datos aleatorios como direcciones IP, nombres de usuario, Event IDs, procesos y acciones de firewall, evitando patrones estáticos fácilmente detectables.
* **Protocolos de Transporte**: Soporte para envío de logs vía **UDP** y **TCP**.
* **Validación de Infraestructura**: Incluye funciones para verificar la disponibilidad del servidor Syslog antes del envío.

## 🛠️ Casos de Uso en Operaciones Ofensivas

1. **Evasión y Ruido (Noise Generation)**: Durante un ejercicio de Red Team, el script puede ser utilizado para generar un volumen alto de logs legítimos (falsos positivos) que ayuden a ocultar actividades maliciosas reales entre el ruido de la red.
2. **Validación de Blue Team (Defensive Testing)**: Verificar si el equipo de defensa (SOC) tiene correctamente configuradas sus alertas para eventos críticos como:
* Intentos de fuerza bruta (Event ID 4625 en Windows).
* Creación de usuarios o escalada de privilegios.
* Conexiones bloqueadas por políticas de Firewall.


3. **Pruebas de Ingesta**: Confirmar que los parsers del SIEM están interpretando correctamente los campos de marcas específicas (ej. campos CEF de Palo Alto).

## ⚙️ Configuración

El script permite configurar los siguientes parámetros en el bloque principal:

* `SYSLOG_SERVER`: IP del colector de logs (Wazuh, QRadar, etc.).
* `SYSLOG_PORT`: Puerto de destino (por defecto `514`).
* `PROTOCOL`: Protocolo de transporte (`UDP` o `TCP`).

## 📋 Requisitos

* Python 3.x
* No requiere librerías externas (utiliza `socket`, `time`, `random` y `datetime`).

## 📝 Ejemplo de ejecución

```bash
python3 Simulador.py

```

Al ejecutarse, el script mostrará una pantalla de inicio, validará la conexión con el servidor configurado y comenzará a transmitir las ráfagas de logs simulados según las plantillas definidas para cada fabricante.

---

**Descargo de Responsabilidad**: Este script debe ser utilizado exclusivamente en entornos controlados y con la debida autorización.
 El uso indebido para causar denegación de servicio en sistemas de monitoreo puede tener consecuencias legales.