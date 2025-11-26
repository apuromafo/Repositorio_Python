# -*- coding: utf-8 -*-
# Script que guía los pasos recomendados para generar informes de Pentesting
# utilizando la plataforma SysReptor.

# Códigos ANSI para colores
BLUE = "\033[94m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
END = "\033[0m"
BOLD = "\033[1m"

print(f"{BOLD}{BLUE}\n*************************************************************{END}")
print(f"{BOLD}{BLUE}⚙️ GUÍA INFORMES DE PENTESTING CON SYSREPTOR ⚙️{END}")
print(f"{BOLD}{BLUE}*************************************************************{END}")
print(f"{YELLOW}SysReptor centraliza la gestión de hallazgos y automatiza el reporte final.{END}")

# --- ENFOQUE DE LA HERRAMIENTA ---
print(f"{BOLD}{RED}\n--- ENFOQUE Y VENTAJAS CLAVE ---{END}")
print(f"{BOLD}1. Base de Conocimiento Centralizada (Knowledge Base):{END}")
print(f"       {GREEN}✅ REUTILIZACIÓN RÁPIDA: Almacena hallazgos, descripciones y remedios para reutilizarlos en segundos.{END}")
print(f"{BOLD}2. Edición Eficiente con Markdown (MD):{END}")
print(f"       {YELLOW}🌐 CONSISTENCIA DE FORMATO: Permite una escritura ágil y estandarizada de los detalles de los hallazgos.{END}")
print(f"{BOLD}3. Exportación Profesional Automática:{END}")
print(f"       {GREEN}✅ FORMATOS FINALES: Genera informes listos para entregar en PDF/DOCX basados en plantillas definidas.{END}")


# --- PASO 1: CONFIGURACIÓN INICIAL Y PLANTILLAS ---
print(f"{BOLD}{BLUE}\n--- PASO 1: CONFIGURACIÓN INICIAL Y PLANTILLAS ---{END}")

print(f"{BOLD}1.1 -> Despliegue y Acceso a la Instancia.{END}")
print(f"       {YELLOW}Ya sea auto-alojado (*self-hosted*) o como servicio, asegura el acceso a la plataforma para el equipo.{END}")

print(f"{BOLD}\n1.2 -> Carga y Diseño de Plantillas.{END}")
print(f"       {YELLOW}Carga plantillas personalizadas (DOCX/LaTeX) para definir el logo, diseño y estructura final del informe.{END}")
print(f"       {BOLD}{GREEN}CONSEJO: Revisa los ejemplos de informes en la documentación oficial.{END}")


# --- PASO 2: GESTIÓN DE HALLAZGOS DEL PROYECTO ---
print(f"{BOLD}{BLUE}\n--- PASO 2: GESTIÓN DE HALLAZGOS Y EVIDENCIA ---{END}")

print(f"{BOLD}2.1 -> Creación de Proyectos y Asignación.{END}")
print(f"       {YELLOW}Crea el proyecto de pentesting y asigna roles y permisos a los *testers* para colaborar.{END}")

print(f"{BOLD}\n2.2 -> Inclusión de Hallazgos desde la KB.{END}")
print(f"       {YELLOW}Prioriza 'Añadir Hallazgo' desde la Base de Conocimiento y no re-escribir desde cero.{END}")
print(f"       {BOLD}{GREEN}ACCIÓN: Solo edita el Proof of Concept, el activo afectado (IP/Host) y los detalles específicos del caso.{END}")

print(f"{BOLD}\n2.3 -> Adjuntar Evidencia de Máquinas y Activos.{END}")
print(f"       {YELLOW}Sube capturas de pantalla, *logs* y define los activos afectados para que se integren automáticamente al reporte.{END}")
print(f"       {BOLD}{RED}❗ PRECAUCIÓN: Confirma que cada evidencia esté ligada al hallazgo correcto antes de la exportación.{END}")


# --- PASO 3: EXPORTACIÓN FINAL DEL INFORME ---
print(f"{BOLD}{BLUE}\n--- PASO 3: EXPORTACIÓN, QC Y CIERRE ---{END}")

print(f"{BOLD}3.1 -> Generación del Documento Final.{END}")
print(f"       {YELLOW}Elige la plantilla de destino ('Informe Técnico', 'Resumen Ejecutivo') y pulsa 'Generate Report' para obtener el PDF/DOCX.{END}")

print(f"{BOLD}\n3.2 -> Control de Calidad (QC) y Validación.{END}")
print(f"       {YELLOW}Realiza una revisión final del documento exportado. Verifica formatos, numeración, imágenes y datos del cliente.{END}")

print(f"{BOLD}{GREEN}\n📢 RECURSO ADICIONAL: Visualiza ejemplos de informes listos para entregar aquí:{END}")
print(f"{BOLD}{BLUE}        » https://docs.sysreptor.com/demo-reports/{END}")