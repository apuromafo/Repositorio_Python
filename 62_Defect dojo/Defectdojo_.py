# Códigos ANSI para colores
BLUE = "\033[94m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
END = "\033[0m"
BOLD = "\033[1m"

# --- PASO 1: Preparación del Entorno ---
print(f"{BOLD}{BLUE}\n*************************************************************{END}")
print(f"{BOLD}{BLUE}PASO 1: CONFIGURACIÓN INICIAL Y CLONACIÓN DEL CÓDIGO{END}")
print(f"{BOLD}{BLUE}*************************************************************{END}")

print(f"{BOLD}1.1 -> Configurar Git para terminaciones de línea LF (Necesario para Docker en Windows).{END}")
print(f"       {BOLD}{GREEN}COMANDO: git config --global core.autocrlf input{END}")
print(f"       {BOLD}{GREEN}COMANDO: git config --global core.eol lf{END}")

print(f"{BOLD}\n1.2 -> Clonar el repositorio principal de DefectDojo.{END}")
print(f"       {BOLD}{GREEN}COMANDO: git clone https://github.com/DefectDojo/django-DefectDojo.git{END}")
print(f"       {BOLD}{GREEN}COMANDO: cd django-DefectDojo{END}")

print(f"{BOLD}\n1.3 -> Crear el archivo de entorno (.env) usando la configuración 'postgres-redis'.{END}")
print(f"       {BOLD}{GREEN}COMANDO: Copy-Item -Path 'docker/environments/postgres-redis.env' -Destination '.env'{END}")
print(f"       {BOLD}{RED}❗ Acción manual: ¡Edita el archivo .env para establecer DD_ADMIN_PASSWORD!{END}")


# --- PASO 2: Construir e Iniciar Servicios ---
print(f"{BOLD}{BLUE}\n*************************************************************{END}")
print(f"{BOLD}{BLUE}PASO 2: CONSTRUCCIÓN E INICIO DE CONTENEDORES{END}")
print(f"{BOLD}{BLUE}*************************************************************{END}")

print(f"{BOLD}2.1 -> Construir las imágenes de Docker. (Puede tardar varios minutos).{END}")
print(f"       {BOLD}{GREEN}COMANDO: docker compose --profile postgres-redis build{END}")

print(f"{BOLD}\n2.2 -> Iniciar todos los servicios (uWSGI, NGINX, Postgres, Celery) en segundo plano.{END}")
print(f"       {BOLD}{GREEN}COMANDO: docker compose --profile postgres-redis up -d{END}")


# --- PASO 3: Verificación, Acceso y Gestión de Contraseña ---
print(f"{BOLD}{BLUE}\n*************************************************************{END}")
print(f"{BOLD}{BLUE}PASO 3: VERIFICACIÓN Y ACCESO{END}")
print(f"{BOLD}{BLUE}*************************************************************{END}")

print(f"{BOLD}3.1 -> Verificar que todos los servicios estén 'running'.{END}")
print(f"       {BOLD}{GREEN}COMANDO: docker compose ps{END}")

print(f"{BOLD}\n3.2 -> ACCESO A LA APLICACIÓN:{END}")
print(f"       {YELLOW}Esperar 30 segundos para la inicialización completa y abrir en el navegador:{END}")
print(f"       {YELLOW}URL: http://localhost:8080{END}")
print(f"       {YELLOW}Usuario: admin{END}")

print(f"{BOLD}\n3.3 -> CAMBIO DE CONTRASEÑA (si se necesita):{END}")
print(f"       {YELLOW}Si olvidaste la contraseña o deseas cambiarla, usa:{END}")
print(f"       {BOLD}{GREEN}COMANDO: docker compose exec uwsgi /bin/bash -c 'python manage.py changepassword admin'{END}")

print(f"\n{BOLD}{GREEN}¡Despliegue finalizado!{END}")