
# Script de Evaluación y Inventario del Sistema (Linux)

Este script (`linux.py`) realiza una evaluación básica del sistema operativo y genera un inventario de software instalado. Está diseñado para proporcionar información útil sobre el estado actual del sistema, lo que puede ser valioso para la seguridad, el mantenimiento y la resolución de problemas. Referencia: CIS Controls v8.1.

## Funcionalidades Principales

*   **Evaluación de Seguridad:**  Verifica la configuración básica de seguridad, incluyendo el firewall (UFW/iptables/firewalld), registros del sistema (rsyslog, journald, auditd) y actualizaciones de software.
*   **Inventario de Software:** Detecta y cuenta los paquetes instalados utilizando diferentes gestores de paquetes comunes (dpkg, rpm, pacman).
*   **Información del Sistema:**  Obtiene información sobre el kernel, la arquitectura del sistema y la cantidad de memoria RAM disponible.
*   **Detección de Dispositivos USB:** Intenta listar los dispositivos USB conectados.

## Requisitos Previos

*   Acceso a la terminal (shell).
*   Permisos suficientes para ejecutar comandos y acceder a información del sistema.

## Instalación y Ejecución

```bash
cd 036_cis/Linux
python3 linux.py [--json RUTA]
```

* `--json RUTA`: exporta los hallazgos (`SECURITY_FINDINGS`) a JSON.
* Cada comando externo tiene timeout de 30 s y las variables interpoladas
  van saneadas con `shlex.quote()`.

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

## Auditoría formal con OpenSCAP (ComplianceAsCode)

`linux.py` es la revisión rápida. Para evidencia formal use OpenSCAP con el
perfil CIS del contenido SSG ([ComplianceAsCode/content](https://github.com/ComplianceAsCode/content)):

```bash
# RHEL/Fedora - Debian (sid): ssg-debian / ssg-debderived / ssg-nondebian
sudo dnf install -y openscap-scanner scap-security-guide

# Descubrir el datastream y los perfiles CIS disponibles
ls /usr/share/xml/scap/ssg/content/
oscap info /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml | grep -i cis

# Evaluar (solo lectura) con reporte HTML + ARF reutilizable
sudo oscap xccdf eval \
  --profile xccdf_org.ssgproject.content_profile_cis \
  --results-arf /tmp/arf.xml --report /tmp/report.html \
  /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml

# Remediar con Ansible generado (CAMBIA el sistema: probar en lab primero)
ls /usr/share/scap-security-guide/ansible/
ansible-playbook -i "localhost," -c local /usr/share/scap-security-guide/ansible/rhel9-playbook-cis.yml
```

Flujo sugerido: `linux.py` (rápido) → Lynis (profundo) → OpenSCAP perfil CIS
(formal) → Ansible SSG (remedia) → Vagrant (lab).

 