# Auditoría de Seguridad del Sistema

Este script realiza una auditoría básica de seguridad del sistema, verificando varios controles clave relacionados con la defensa contra malware, la gestión de cuentas y la seguridad de la red.  El objetivo es proporcionar una visión general rápida del estado de seguridad del sistema.

## Funcionalidades Principales

*   **Verificación de Software:** Obtiene un inventario de software instalado en el sistema.
*   **Seguridad de Red:** Realiza pruebas para identificar vulnerabilidades de red.
*   **Gestión de Cuentas:**  Verifica la configuración y control de acceso de las cuentas de usuario.
*   **Control de Acceso:** Evalúa los mecanismos de control de acceso implementados.
*   **Auditoría de Registros:** Examina los registros del sistema en busca de eventos relevantes.
*   **Defensa contra Malware:**  Verifica el estado y la configuración de Windows Defender y otras soluciones antivirus detectadas.

## Ejecución del Script

El script se ejecuta mediante el comando `invoke_cis_controls_audit()`.  Se recomienda ejecutarlo con privilegios de administrador para garantizar el acceso a todos los datos necesarios.

## Dependencias

*   **WMI (Windows Management Instrumentation):** El script utiliza WMI para obtener información sobre el sistema, incluyendo el estado de Windows Defender y otras soluciones antivirus.
*   **wevtutil:** Se utiliza para consultar registros del sistema.
*   **subprocess:**  Para ejecutar comandos externos como `wevtutil`.

## Resultados de la Auditoría

El script imprime los resultados de la auditoría en la consola, incluyendo:

*   Un mensaje indicando que la auditoría se ha completado exitosamente (en verde).
*   Una solicitud para revisar los resultados y tomar las acciones correctivas necesarias (en amarillo).
*   Mensajes de error si ocurre algún problema durante la ejecución.  Los errores se muestran en rojo.

## Detalles Técnicos

### Citas Clave:

*   `get_software_inventory()`: Obtiene un inventario del software instalado.
*   `test_network_security()`: Realiza pruebas para identificar vulnerabilidades de red.
*   `test_account_management()`: Verifica la configuración y control de acceso de las cuentas de usuario.
*   `test_access_control()`: Evalúa los mecanismos de control de acceso implementados.
*   `test_audit_logs()`: Examina los registros del sistema en busca de eventos relevantes.
*   `test_malware_defense()`: Verifica el estado y la configuración de Windows Defender y otras soluciones antivirus detectadas.

###  Estado de Windows Defender (WMI):

El script consulta el estado de Windows Defender utilizando WMI, específicamente el namespace `root\Microsoft\Windows\Defender`.  Se verifica si Windows Defender está habilitado, se obtiene la última actualización de firmas y el estado de la protección en tiempo real.

###  Otras Soluciones Antivirus (WMI):

Además de Windows Defender, el script también detecta otras soluciones antivirus utilizando WMI, consultando el namespace `root\SecurityCenter2`.

## Posibles Problemas y Soluciones

*   **Permisos de Administrador:** El script requiere permisos de administrador para acceder a información sensible del sistema.
*   **WMI No Disponible:** Si la conexión WMI no está disponible, el script omitirá la verificación de defensa contra malware.  Asegúrese de que WMI esté correctamente configurado en su sistema.
*   **Errores de WMI:** Los errores de WMI pueden indicar problemas con la configuración de WMI o la disponibilidad del servicio.

