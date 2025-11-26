# -*- coding: utf-8 -*-
# Script que guía los pasos recomendados para generar informes de Pentesting
# utilizando Microsoft Word, LibreOffice, o Google Docs.

# Códigos ANSI para colores
BLUE = "\033[94m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
END = "\033[0m"
BOLD = "\033[1m"

print(f"{BOLD}{BLUE}\n*************************************************************{END}")
print(f"{BOLD}{BLUE}📄 GUÍA INFORMES DE PENTESTING EN OFFICE/LIBREOFFICE 📄{END}")
print(f"{BOLD}{BLUE}*************************************************************{END}")
print(f"{YELLOW}El enfoque en estas herramientas es el uso consistente de plantillas y estilos.{END}")

# --- HERRAMIENTAS Y COSTOS ---
print(f"{BOLD}{RED}\n--- HERRAMIENTAS DISPONIBLES Y LICENCIAS ---{END}")
print(f"{BOLD}1. Word / Microsoft 365:{END}")
print(f"       {RED}❗ LICENCIA: Requiere pago por suscripción o licencia única.{END}")
print(f"{BOLD}2. LibreOffice Writer:{END}")
print(f"       {GREEN}✅ LICENCIA: Software libre y gratuito (Open Source).{END}")
print(f"{BOLD}3. Google Docs (Opcional):{END}")
print(f"       {YELLOW}🌐 LICENCIA: Gratuito con cuenta de Google (basado en la nube).{END}")


# --- PASO 1: Creación de la Plantilla Maestra ---
print(f"{BOLD}{BLUE}\n--- PASO 1: CREACIÓN DE LA PLANTILLA MAESTRA ---{END}")

print(f"{BOLD}1.1 -> Crear la Plantilla Base (.DOTX / .OTT).{END}")
print(f"       {YELLOW}Guarda el documento con la estructura base como una plantilla para evitar modificar el original.{END}")
print(f"       {BOLD}{GREEN}ACCIÓN: Diseñar Portada, Encabezados y Pie de Página.{END}")

print(f"{BOLD}\n1.2 -> Definir Estilos Clave.{END}")
print(f"       {YELLOW}Los estilos (Títulos, Subtítulos, Listas, Bloque de Código) son esenciales para la consistencia y la generación automática del Índice.{END}")
print(f"       {BOLD}{GREEN}ESTILOS CLAVE: Título 1, Título 2, Bloque de Código (fuente monoespaciada).{END}")

print(f"{BOLD}\n1.3 -> Configurar la Tabla de Contenido (Índice).{END}")
print(f"       {YELLOW}El índice debe generarse automáticamente a partir de los estilos de Título definidos en el paso anterior.{END}")
print(f"       {BOLD}{RED}❗ PRECAUCIÓN: No escribir el índice manualmente. Debe ser un campo automático.{END}")


# --- PASO 2: Inclusión de Contenido y Hallazgos ---
print(f"{BOLD}{BLUE}\n--- PASO 2: INCLUSIÓN DE CONTENIDO Y EVIDENCIA ---{END}")

print(f"{BOLD}2.1 -> Estructurar el Reporte de Hallazgos.{END}")
print(f"       {YELLOW}Aplica estilos consistentes a cada hallazgo (ID, Criticidad, Impacto, Remedio).{END}")
print(f"       {BOLD}{GREEN}CONSEJO: Usar 'Tablas' para los detalles de las vulnerabilidades para un diseño limpio.{END}")

print(f"{BOLD}\n2.2 -> Insertar Pruebas y Evidencia.{END}")
print(f"       {YELLOW}Añade capturas de pantalla y usa la función 'Insertar Título' (Caption) de Office para que se numeren automáticamente (Figura 1, Figura 2).{END}")

print(f"{BOLD}\n2.3 -> Integración de Datos (Macros/Combinación de Correspondencia Opcional).{END}")
print(f"       {YELLOW}Si manejas muchos datos, usa Macros (Word/LibreOffice) o la función Combinación de Correspondencia (Merge Field) para inyectar datos de un CSV.{END}")


# --- PASO 3: Revisión y Generación Final ---
print(f"{BOLD}{BLUE}\n--- PASO 3: REVISIÓN Y GENERACIÓN FINAL ---{END}")

print(f"{BOLD}3.1 -> Actualizar todos los Campos.{END}")
print(f"       {YELLOW}Antes de exportar, actualiza todos los campos (TDC, números de página, referencias) para asegurar la numeración final.{END}")
print(f"       {BOLD}{GREEN}ACCIÓN: Seleccionar todo el documento (Ctrl+A) y presionar F9 (o el atajo de actualización de campos).{END}")

print(f"{BOLD}\n3.2 -> Exportar al Formato de Entrega.{END}")
print(f"       {YELLOW}El informe debe entregarse en PDF para asegurar que el formato se mantenga intacto en todos los dispositivos.{END}")
print(f"       {BOLD}{GREEN}COMANDO (Word/Office): Archivo -> Exportar -> Crear documento PDF/XPS.{END}")

print(f"\n{BOLD}{GREEN}¡Informe listo usando tu procesador de texto preferido!{END}")