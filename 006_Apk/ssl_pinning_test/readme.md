# Auditoría Móvil de Seguridad - Script

Este script automatiza el proceso de auditoría de aplicaciones Android, permitiendo la eliminación de SSL pinning y anti-root.  Está diseñado para ser utilizado en entornos controlados y con fines de investigación y desarrollo. **Utilizar este script conlleva riesgos y debe hacerse bajo su propia responsabilidad.**

## Descripción General

El script utiliza herramientas como `apktool` y `uber-apk-signer` para descompilar, modificar y recompilar un archivo APK.  Permite la eliminación de características de seguridad comunes en aplicaciones Android, tales como:

*   **SSL Pinning:**  Evita que la aplicación se conecte a servidores con certificados SSL no autorizados.
*   **Anti-Root:**  Detecta si la aplicación está ejecutándose en un dispositivo rooteado y toma medidas para evitar su funcionamiento.

## Requisitos Previos

1.  **Java Development Kit (JDK):** Necesario para ejecutar `apktool`. Asegúrate de tener una versión compatible.
2.  **apktool:** Descarga e instala `apktool` desde [https://ibotpeaches.github.io/ApkTool/](https://ibotpeaches.github.io/ApkTool/).  Asegúrate de que el archivo `apktool.jar` esté en la ruta especificada en la variable `APKTOOL`.
3.  **uber-apk-signer:** Descarga e instala `uber-apk-signer` desde [https://github.com/Uber/uber-apk-signer](https://github.com/Uber/uber-apk-signer). Asegúrate de que el archivo `uber-apk-signer.jar` esté en la ruta especificada en la variable `APKSIGNER`.
4.  **Clave de Firma (keystore):** Necesitas una clave de firma personalizada (`my-release-key.jks`) para firmar el APK modificado.  Puedes crear una clave de prueba utilizando herramientas como `jarsigner` o `keytool`.
5.  **Variables de Entorno:** Asegúrate de que las variables de entorno `APKTOOL`, `APKSIGNER` y `KEYSTORE` estén correctamente configuradas con las rutas a tus archivos.

## Uso del Script

1.  **Guarda el script:** Guarda el código como un archivo `.py` (por ejemplo, `auditor_mobile.py`).
2.  **Ejecuta el script:** Abre una terminal y ejecuta el script usando Python:

    ```bash
    python auditor_mobile.py <ruta_al_apk> --ssl --antiroot
    ```

    *   `<ruta_al_apk>`: Reemplaza esto con la ruta al archivo APK que deseas auditar.
    *   `--ssl`:  Opcional. Elimina el SSL pinning.
    *   `--antiroot`: Opcional. Elimina el anti-root.
    *   `--all`: Opcional. Elimina tanto el SSL pinning como el anti-root.

## Variables de Configuración

El script utiliza las siguientes variables de configuración:

*   `APKTOOL`: Ruta al archivo `apktool.jar`.  Ejemplo: `"herramientas\\apktool\\apktool.jar"`
*   `APKSIGNER`: Ruta al archivo `uber-apk-signer.jar`. Ejemplo: `"herramientas\\uber-apk-signer\\uber-apk-signer.jar"`
*   `KEYSTORE`: Ruta al archivo de clave de firma (`my-release-key.jks`).  Ejemplo: `"my-release-key.jks"`
*   `KEY_ALIAS`: Nombre del alias de la clave en el keystore. Ejemplo: `"alias_name"`
*   `KEY_PASSWORD`: Contraseña para la clave de firma. Ejemplo: `"apuromafo"`

## Estructura de Directorios

El script crea los siguientes directorios (si no existen):

*   `output/`:  Contiene archivos temporales y el APK modificado.
    *   `output/decompiled/`: Descompilación del APK.
    *   `output/repackaged.apk`: APK recompilado con las modificaciones.
    *   `output/signed.apk`: APK firmado.

## Funcionalidades Detalladas

*   **`validate_arguments()`:**  Valida los argumentos de la línea de comandos, asegurando que se especifique al menos una opción para eliminar SSL pinning o anti-root.
*   **`log(message)`:** Imprime mensajes en la consola con un prefijo "[LOG]".
*   **`decompile_apk(apk_path)`:** Descompila el APK usando `apktool`.
*   **`modify_ssl_pinning(decompiled_dir)`:**  Elimina las configuraciones de SSL pinning del archivo `network_security_config.xml` y realiza cambios en archivos `.smali` para deshabilitar llamadas relacionadas con SSL.
*   **`modify_antiroot(decompiled_dir)`:** Elimina las comprobaciones de root (por ejemplo, buscando paquetes relacionados con la superuser) y desactiva llamadas relacionadas en los archivos `.smali`.
*   **`recompile_apk(decompiled_dir)`:** Recompila el APK usando `apktool`.
*   **`sign_apk(apk_path)`:** Firma el APK modificado utilizando `uber-apk-signer`.
*   **`clean_up(decompiled_dir)`:** Elimina los directorios y archivos temporales creados durante la ejecución del script.

## Notas Importantes

*   Este script está diseñado para fines de auditoría y pruebas.  No debe ser utilizado para actividades ilegales o no éticas.
*   La efectividad de las modificaciones puede variar dependiendo de cómo esté protegido el APK original.
*   Asegúrate de tener una copia de seguridad del archivo APK original antes de ejecutar este script.
*   El script utiliza la variable `KEY_PASSWORD` para la firma del APK.  **No incluyas esta contraseña directamente en el código fuente.**  Utiliza un archivo de configuración o un método más seguro para gestionar las credenciales.
 