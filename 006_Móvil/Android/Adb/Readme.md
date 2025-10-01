🛠️ ADB Multi-Platform Manager (VENV Focus)
Versión: 3.8.0

Herramienta de apoyo en Python para instalar, validar y gestionar ADB Tools (Android Debug Bridge) de forma multi-plataforma. Su diseño prioriza la integración y uso de ADB dentro de un Entorno Virtual de Python (VENV) para mantener el entorno de trabajo limpio y aislado.

✨ Características Principales
Instalación Flexible: Descarga e instala los binarios de ADB y Fastboot de Google en el sistema Host (global) o directamente en la carpeta de binarios de tu VENV activo.

Multi-Plataforma: Soporte nativo y detección para Windows, Linux, WSL y macOS (Darwin).

Validación Automática: Comprueba si ADB está correctamente configurado y accesible en el PATH del sistema o del VENV.

Gestión de Dispositivos (v3.8.0): Menú interactivo para listar dispositivos conectados, verificar su estado de conexión (device/unauthorized) y determinar el estado de Root (acceso su).

Configuración Persistente: Guarda la ruta de instalación por defecto y el estado del logging en un archivo config/config_adb.json.

Registro de Eventos: Opción para activar el logging de todas las acciones en un archivo local (adb_validator.log).

🚀 Uso e Instalación
Requisitos
Necesitas tener Python 3.8 o superior instalado en tu sistema.

1. Preparación (Recomendado)
Se recomienda encarecidamente trabajar dentro de un Entorno Virtual de Python.

# Crear el VENV (si aún no existe)
python3 -m venv venv

# Activar el VENV
# Windows:
.\venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

2. Ejecución
Una vez activado el VENV, simplemente ejecuta el script:

python3 adb_manager.py
# (Asegúrate de reemplazar 'adb_manager.py' con el nombre de tu archivo)

Opciones del Menú
El script presentará un menú interactivo con las siguientes opciones:

Validar Instalación de ADB: Comprueba si ADB ya existe y funciona.

Instalar/Actualizar ADB Tools: Procede a la descarga e instalación en la ruta configurada (VENV o Host).

Gestión de Dispositivos ADB: Entra al módulo de detección de dispositivos, verificación de Root y reinicio del servidor ADB.

Ver/Configurar Rutas de Instalación: Permite cambiar la ruta por defecto para instalaciones en modo Host.

Activar/Desactivar Logging: Controla el registro de eventos en el archivo adb_validator.log.

Mostrar Guías Manuales: Muestra instrucciones para la instalación manual en Host o VENV.

Salir.

📱 Módulo de Gestión de Dispositivos
La opción [3] Gestión de Dispositivos ADB te permite:

Listar todos los dispositivos detectados (adb devices).

Verificar si el dispositivo está en estado device (listo para usar) o unauthorized (requiere aceptación del USB Debugging).

Verificar el estado de Root en tiempo real.

Reiniciar el servidor ADB (adb kill-server/start-server) para resolver problemas de conectividad.

🛑 Aviso Legal
Las herramientas de Android Debug Bridge (ADB) y Fastboot son propiedad intelectual de Google y/o sus respectivos autores. 
Este script solo facilita su descarga, gestión e integración en entornos de desarrollo.