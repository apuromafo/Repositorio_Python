# -*- coding: utf-8 -*-
# Script de guía rápida para la instalación, acceso y uso de BlackStone
# utilizando Docker Compose y sus funcionalidades clave.

# Códigos ANSI para colores (sin dependencias adicionales)
BLUE = "\033[94m"    # Azul
GREEN = "\033[92m"   # Verde
RED = "\033[91m"     # Rojo
YELLOW = "\033[93m"  # Amarillo
END = "\033[0m"      # Restablecer color
BOLD = "\033[1m"     # Negrita

# --- TÍTULO Y DESCRIPCIÓN (FASE 1: INSTALACIÓN) ---
print(f"{BOLD}{BLUE}\n*************************************************************{END}")
print(f"{BOLD}{BLUE}📦 GUÍA COMPLETA DE BLACKSTONE (INSTALACIÓN Y USO) 📦{END}")
print(f"{BOLD}{BLUE}*************************************************************{END}")
print(f"{YELLOW}FASE 1: Sigue los pasos para desplegar BlackStone usando Docker Compose.{END}")

# --- PASO 1: CLONAR EL REPOSITORIO ---
print(f"{BOLD}{GREEN}\n--- PASO 1: Clonar el Repositorio de GitHub ---{END}")
print(f"{BOLD}Acción:{END} Obtener el código fuente de BlackStone.")
print(f"{BOLD}Comando:{END} {RED}git clone https://github.com/micro-joan/BlackStone{END}")
print(f"{YELLOW}Asegúrate de tener Git instalado en tu sistema.{END}")

# --- PASO 2: ACCEDER AL DIRECTORIO ---
print(f"{BOLD}{GREEN}\n--- PASO 2: Acceder al Directorio ---{END}")
print(f"{BOLD}Acción:{END} Moverse al directorio recién clonado.")
print(f"{BOLD}Comando:{END} {RED}cd BlackStone{END}")

# --- PASO 3: LEVANTAR LOS CONTENEDORES CON DOCKER ---
print(f"{BOLD}{GREEN}\n--- PASO 3: Levantar los Contenedores de Docker ---{END}")
print(f"{BOLD}Acción:{END} Iniciar la aplicación en segundo plano ({BOLD}-d{END} detach).")
print(f"{BOLD}Comando:{END} {RED}docker-compose up -d{END}")
print(f"{YELLOW}❗ REQUISITO: Debes tener Docker y Docker Compose instalados y en ejecución.{END}")
print(f"{YELLOW}Espera unos minutos a que todos los servicios se inicien completamente.{END}")

# --- PASO 4: ACCESO INICIAL ---
print(f"{BOLD}{GREEN}\n--- PASO 4: Detalles de Acceso y URL ---{END}")
print(f"{BOLD}Acceso Web:{END} Abre tu navegador y navega a la URL de tu instancia (generalmente {RED}http://localhost:8080{END} o similar).")
print(f"{BOLD}Credenciales Iniciales:{END}")
print(f"       {GREEN}👤 Usuario: {RED}blackstone{END}")
print(f"       {GREEN}🔑 Contraseña: {RED}blackstone{END}")


# ----------------------------------------------------------------------------------
# --- FASE 2: USO DE BLACKSTONE Y GENERACIÓN DE INFORMES ---
# ----------------------------------------------------------------------------------
print(f"{BOLD}{BLUE}\n--- FASE 2: USO DE BLACKSTONE Y GENERACIÓN DE INFORMES ---{END}")

# --- PASO 5: CONFIGURACIÓN INICIAL Y TOKENS ---
print(f"{BOLD}{GREEN}\n--- PASO 5: Configuración de Tokens API ---{END}")
print(f"{BOLD}Acción:{END} Habilitar fuentes externas de datos.")
print(f"{YELLOW}1. Ve a la Configuración del Perfil dentro de BlackStone.{END}")
print(f"{YELLOW}2. Añade los tokens de API de {BOLD}Hunter.io{END} y {BOLD}haveibeenpwned.com{END}.")
print(f"{BOLD}{RED}❗ IMPORTANTE: {END}Estos tokens son cruciales para el enriquecimiento automático de datos.")

# --- PASO 6: REGISTRO DE CLIENTE Y RECOLECCIÓN DE DATOS ---
print(f"{BOLD}{GREEN}\n--- PASO 6: Registro del Cliente Auditado y Recolección ---{END}")
print(f"{BOLD}Acción:{END} Registrar el objetivo y comenzar el análisis de información pública.")
print(f"{YELLOW}1. Registra un cliente junto con su página web en la base de datos.{END}")
print(f"{YELLOW}2. En los detalles del cliente, verás la información recopilada automáticamente:{END}")
print(f"       {GREEN}          - Datos del propietario (Nombre, Redes, Correo, Teléfono).{END}")
print(f"       {GREEN}          - Comprobación de contraseñas expuestas (Hacked Passwords).{END}")
print(f"       {GREEN}          - Subdominios, información de interés de Google y correos de trabajadores.{END}")
print(f"{BOLD}{RED}⚠️ NOTA: {END}El uso de esta aplicación es para fines profesionales de seguridad. El autor no se hace responsable de un mal uso.")

# --- PASO 7: CREACIÓN Y EDICIÓN DEL INFORME ---
print(f"{BOLD}{GREEN}\n--- PASO 7: Creación y Edición del Informe ---{END}")
print(f"{BOLD}Acción:{END} Documentar y seleccionar las vulnerabilidades encontradas.")
print(f"{YELLOW}1. Crea un nuevo informe: añade Fecha, Nombre y la Empresa a auditar.{END}")
print(f"{YELLOW}2. Una vez creado, ve a 'Editar' y selecciona las vulnerabilidades que aparecerán en el reporte.{END}")

# --- PASO 8: GENERACIÓN Y EXPORTACIÓN FINAL ---
print(f"{BOLD}{GREEN}\n--- PASO 8: Generación y Exportación Final ---{END}")
print(f"{BOLD}Acción:{END} Obtener el informe en un formato editable.")
print(f"{YELLOW}1. Pulsa el botón {BOLD}'overview report'{END} para generar la vista previa.{END}")
print(f"{YELLOW}2. Guarda la página que se genera como archivo {BOLD}'.mht'{END} (Web Archive).{END}")
print(f"{YELLOW}3. Abre el archivo {BOLD}.mht{END} con Word para realizar la edición y ajustes finales.{END}")


# --- CIERRE ---
print(f"{BOLD}{BLUE}\n¡GUÍA COMPLETA!{END}")
print(f"{YELLOW}Ya puedes empezar a gestionar auditorías y generar informes profesionales con BlackStone.{END}")