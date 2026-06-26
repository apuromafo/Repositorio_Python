# **⚙️ Orquestador Pwndoc con Docker Compose**

Este script de Python simplifica la gestión del despliegue de la aplicación de pentesting [Pwndoc](https://github.com/pwndoc/pwndoc) utilizando **docker-compose**. Su objetivo es automatizar tareas comunes como el clonado del repositorio, la construcción de las imágenes, el levantamiento de los contenedores y la verificación de la disponibilidad del servicio.

## **🚀 Requisitos Previos**

Asegúrate de tener instalado y en ejecución lo siguiente en tu sistema antes de usar el orquestador:

1. **Python 3.x**: Necesario para ejecutar el script de orquestación.  
2. **Docker Daemon**: (Docker Desktop o el servicio Docker) \- **Debe estar en ejecución**.  
3. **Git**: Necesario para clonar el repositorio y usar la acción update.

## **📝 Uso**

Asumiendo que el script se llama pwndoc\_orchestrator.py, puedes ejecutarlo especificando la acción deseada:

python pwndoc\_orchestrator.py \<acción\>

## **🛠️ Acciones Disponibles**

| Acción | Descripción | Nota Importante |
| :---- | :---- | :---- |
| up | **Configura y Levanta la Aplicación (Build & Run).** Verifica Docker, clona el repositorio de Pwndoc si no existe, construye las imágenes, inicia los contenedores en segundo plano (-d) y comprueba que el servicio web esté accesible. | La acción principal para el primer uso. |
| logs | Muestra los logs en tiempo real del servicio de *backend* (pwndoc-backend). | Útil para la depuración (Debugging). |
| stop | Detiene los contenedores en ejecución (mantiene los datos y el estado). | Ejecuta docker-compose stop. |
| start | Inicia los contenedores previamente detenidos y verifica su estado. | Ejecuta docker-compose start. |
| down | Baja y elimina todos los contenedores, redes y volúmenes por defecto creados por docker-compose. | **¡PRECAUCIÓN\!** Esto elimina los contenedores, pero los datos de MongoDB suelen persistir en volúmenes. |
| update | Detiene la aplicación, actualiza el código fuente con git pull, reconstruye las imágenes y vuelve a levantar el servicio. | Debe ejecutarse dentro de la carpeta pwndoc (o después de haber usado up). |

## **🌟 Primer Uso (Configuración Rápida)**

Para desplegar Pwndoc por primera vez, simplemente ejecuta:

python pwndoc\_orchestrator.py up

Una vez que el script finalice con éxito, Pwndoc estará accesible en:

### **🌐 Acceso a Pwndoc**

* **URL:** https://localhost:8443

### **⚠️ Aviso de Seguridad**

La aplicación usa un certificado SSL autofirmado por defecto. Es normal que su navegador muestre una advertencia de seguridad. **Se recomienda encarecidamente cambiar los certificados SSL y la clave secreta JWT** para cualquier entorno de producción.

## ⚠️ Aviso Legal / Legal Notice

Esta herramienta es unicamente para fines educativos y de auditoria de seguridad autorizada. El uso no autorizado contra sistemas sin el consentimiento explicito del propietario es ilegal. El usuario asume toda responsabilidad por el uso indebido.

This tool is for educational and authorized security auditing purposes only. Unauthorized use against systems without the owner's explicit consent is illegal. The user assumes all responsibility for misuse.
