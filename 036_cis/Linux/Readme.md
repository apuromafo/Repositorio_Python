
# Script de Evaluación y Inventario del Sistema

Este script realiza una evaluación básica del sistema operativo y genera un inventario de software instalado. Está diseñado para proporcionar información útil sobre el estado actual del sistema, lo que puede ser valioso para la seguridad, el mantenimiento y la resolución de problemas.

## Funcionalidades Principales

*   **Evaluación de Seguridad:**  Verifica la configuración básica de seguridad, incluyendo el firewall (UFW/iptables/firewalld), registros del sistema (rsyslog, journald, auditd) y actualizaciones de software.
*   **Inventario de Software:** Detecta y cuenta los paquetes instalados utilizando diferentes gestores de paquetes comunes (dpkg, rpm, pacman).
*   **Información del Sistema:**  Obtiene información sobre el kernel, la arquitectura del sistema y la cantidad de memoria RAM disponible.
*   **Detección de Dispositivos USB:** Intenta listar los dispositivos USB conectados.

## Requisitos Previos

*   Acceso a la terminal (shell).
*   Permisos suficientes para ejecutar comandos y acceder a información del sistema.

## Instalación y Ejecución

1.  Guarda el script como un archivo, por ejemplo, `evaluacion_sistema.sh`.
2.  Haz que el script sea ejecutable: `chmod +x evaluacion_sistema.sh`
3.  Ejecuta el script: `./evaluacion_sistema.sh`

## Salida del Script

El script produce información en la consola, incluyendo:

*   Información sobre la versión del sistema operativo (SO).
*   Detalles de la arquitectura del procesador.
*   Cantidad de memoria RAM disponible.
*   Número de paquetes instalados utilizando diferentes gestores de paquetes.
*   Lista de servicios systemd que están actualmente en ejecución.
*   Información sobre dispositivos USB conectados (si los hay).

## Configuración y Personalización

*   **Firewall:**  El script recomienda configurar el firewall (UFW/iptables/firewalld) para cerrar puertos innecesarios.  Asegúrate de entender las implicaciones de seguridad antes de realizar cambios en la configuración del firewall.
*   **Logging:** Asegúrate de que los servicios de logging estén activos y configurados correctamente para facilitar la resolución de problemas.
*   **Seguridad Adicional:** Considera instalar herramientas adicionales de seguridad como antivirus y detectores de rootkit.

##  Control 2: Inventario de Software (Detalles)

El script utiliza diferentes gestores de paquetes (dpkg, rpm, pacman) para determinar la cantidad de software instalado en el sistema.  Esto proporciona una visión general del entorno de software.

## Notas Importantes

*   **Dependencias:** El script depende de que los comandos necesarios estén disponibles en el sistema.
*   **Errores:** Si se encuentran errores al parsear información (por ejemplo, la cantidad de RAM), se mostrará un mensaje de advertencia.  Esto puede indicar problemas con la configuración del sistema o la disponibilidad de archivos de información.

 