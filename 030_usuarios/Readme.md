
# 💻 User Manager CLI (Gestión de Usuarios Multiplataforma)

**Versión:** 2.0 | **Fecha:** 2025-10-01

Herramienta **CLI (Command Line Interface)** en Python diseñada para la administración y auditoría de cuentas de usuario en entornos de sistemas operativos (**Windows**, **Linux** y **macOS**).

El *script* abstrae los comandos nativos de cada sistema (como `net user`, `useradd`, `dscl`, etc.) para ofrecer una **interfaz unificada**. Es una herramienta esencial para el análisis de privilegios, la gestión de acceso y tareas de *pentesting* o auditoría interna.

-----

## ✨ Características Principales (v2.0)

  * **Soporte Multiplataforma:** Implementación de lógica específica para Windows, Linux y macOS.
  * **Detección Avanzada de Entorno:** Identifica la distribución de Linux o la versión específica de Windows/macOS al inicio.
  * **Verificación de Privilegios:** Realiza una verificación robusta de permisos de **root/Administrator** antes de ejecutar cualquier comando sensible (crear/eliminar).
  * **Modo Interactivo:** Incluye un menú interactivo fácil de usar si el *script* se ejecuta sin argumentos.
  * **Manejo de Encoding:** Lógica mejorada para manejar la codificación **UTF-8** en la salida de comandos.

-----

## 🚀 Uso

### Requisitos

  * **Python 3.x**
  * **Privilegios:** Las operaciones de crear y eliminar requieren privilegios de administrador/root.

### Ejecución

El *script* puede ejecutarse en **modo interactivo** o con **comandos directos** a través de la línea de comandos.

#### 1\. Modo Interactivo

Si no se proporciona ningún argumento, se inicia el menú interactivo:

```bash
python3 script_usuarios.py
```

#### 2\. Modo Línea de Comandos (CLI)

Utiliza subcomandos para ejecutar operaciones específicas:

| Comando | Descripción | Ejemplo de Uso |
| :--- | :--- | :--- |
| `listar` | Muestra los usuarios del sistema (filtrando cuentas de servicio). | `python3 script_usuarios.py listar` |
| `crear <nombre>` | Crea un nuevo usuario. **Requiere privilegios.** | `sudo python3 script_usuarios.py crear usuario_prueba` |
| `eliminar <nombre>` | Elimina un usuario y su directorio *home* (`-r` en Linux). **Requiere privilegios.** | `sudo python3 script_usuarios.py eliminar usuario_prueba` |
| `grupos` | Muestra grupos del sistema o de un usuario específico. | `python3 script_usuarios.py grupos --usuario admin` |
| `info <nombre>` | Muestra información detallada de un usuario (ID, grupos, directorios). | `python3 script_usuarios.py info root` |
| `--info-sistema` | Muestra únicamente la información detallada del entorno actual y los privilegios. | `python3 script_usuarios.py --info-sistema` |

-----

## 📜 Historial de Versiones (Changelog)

| Versión | Fecha | Estado | Cambios/Notas |
| :--- | :--- | :--- | :--- |
| **v2.0** | 2025-10-01 | ESTABLE | ✅ Detección avanzada de entorno (distro Linux, versión Windows/macOS). ✅ Verificación robusta de privilegios multiplataforma. ✅ Mejoras en manejo de *encoding* UTF-8. ✅ Información detallada del sistema al inicio. ✅ Validación de comandos disponibles. |
| **v1.0** | 2025-09-30 | INICIO | 🎯 Versión inicial con funciones básicas de listar, crear y eliminar usuarios. |

-----

## 🛑 Aviso Legal y Descargo de Responsabilidad

  * **Propósito:** Este *script* ha sido creado únicamente con fines de **investigación de seguridad**, **auditoría interna** y **administración de sistemas propios o autorizados** (*White Hat*).
  * **Uso Ético y Legal:** El autor no se hace responsable por el uso inadecuado o ilegal de esta herramienta. El usuario es el único responsable de asegurar que tiene el permiso expreso y legal para ejecutar comandos y modificar configuraciones de usuarios en el sistema objetivo.
  * **Riesgo de Datos:** Las funciones de creación y, en particular, **eliminación de usuarios son IRREVERSIBLES**. Utiliza este *script* con **extrema precaución**.
  * **Compatibilidad:** Aunque se han realizado esfuerzos para la compatibilidad multiplataforma, pueden existir diferencias de comandos o *encodings* en sistemas o versiones no estándar.