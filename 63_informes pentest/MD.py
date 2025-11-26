# -*- coding: utf-8 -*-
# Script que guía los pasos recomendados para generar informes de Pentesting
# utilizando Markdown (MD), recomendando Obsidian y la integración con GitHub.

# Códigos ANSI para colores
BLUE = "\033[94m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
END = "\033[0m"
BOLD = "\033[1m"

print(f"{BOLD}{BLUE}\n*************************************************************{END}")
print(f"{BOLD}{BLUE}⚛️ GUÍA INFORMES DE PENTESTING CON MARKDOWN (MD) ⚛️{END}")
print(f"{BOLD}{BLUE}*************************************************************{END}")
print(f"{YELLOW}Markdown ofrece velocidad y portabilidad, ideal para notas técnicas rápidas y estructuradas.{END}")

# --- HERRAMIENTAS RECOMENDADAS ---
print(f"{BOLD}{RED}\n--- HERRAMIENTAS CLAVE ---{END}")
print(f"{BOLD}1. Editor Principal (Recomendado):{END}")
print(f"       {GREEN}✅ OBSIDIAN:{END} Excelente para vincular notas de hallazgos (Knowledge Graph) y previsualizar Markdown.{END}")
print(f"{BOLD}2. Control de Versiones (Opcional, pero Recomendado):{END}")
print(f"       {GREEN}✅ GITHUB/GITLAB:{END} Permite versionar, colaborar y auditar cambios en el informe (archivos .md).{END}")
print(f"{BOLD}3. Conversión Final:{END}")
print(f"       {GREEN}✅ PANDOC:{END} Herramienta indispensable para convertir el archivo final .md a PDF, DOCX o HTML, manteniendo la estructura.{END}")


# --- PASO 1: ESTRUCTURA Y SINTAXIS ---
print(f"{BOLD}{BLUE}\n--- PASO 1: ESTRUCTURA Y SINTAXIS DE MARKDOWN ---{END}")

print(f"{BOLD}1.1 -> Definir la Estructura de Encabezados (Jerarquía).{END}")
print(f"       {YELLOW}Usa los encabezados MD (#, ##, ###) consistentemente, ya que serán la base para el Índice del informe final.{END}")
print(f"       {BOLD}{GREEN}SINTAXIS: #Título Principal, ##Sección, ###Hallazgo.{END}")

print(f"{BOLD}\n1.2 -> Manejar el Contenido Técnico.{END}")
print(f"       {YELLOW}Usa los bloques de código con resaltado de sintaxis para comandos, scripts o código vulnerable.{END}")
print(f"       {BOLD}{GREEN}SINTAXIS: ```lenguaje_usado\n...código...\n```{END}")

print(f"{BOLD}\n1.3 -> Insertar Imágenes (Evidencia).{END}")
print(f"       {YELLOW}Las imágenes deben guardarse en una subcarpeta (ej: /assets) y enlazarse desde el archivo MD.{END}")
print(f"       {BOLD}{GREEN}SINTAXIS: ![Pie de Imagen](./assets/captura.png){END}")


# --- PASO 2: GESTIÓN DE RIESGOS Y COLABORACIÓN ---
print(f"{BOLD}{BLUE}\n--- PASO 2: CUIDADO CON MARKDOWN Y GITHUB ---{END}")

print(f"{BOLD}2.1 -> Trabajar con Cuidado en el Formato.{END}")
print(f"       {RED}❗ PRECAUCIÓN: Markdown es sencillo pero estricto. Un salto de línea extra o un espacio de más puede romper la sintaxis al convertir a PDF.{END}")
print(f"       {BOLD}{GREEN}REVISIÓN: Siempre previsualiza el .md en Obsidian (o un visor) antes de la conversión final.{END}")

print(f"{BOLD}\n2.2 -> Integración con GitHub.{END}")
print(f"       {YELLOW}Almacenar el informe (.md y /assets) en un repositorio Git garantiza historial de cambios, backups y colaboración controlada.{END}")
print(f"       {BOLD}{GREEN}FLUJO DE TRABAJO: Crear rama para cambios, hacer commit de hallazgos, pull request para revisión.{END}")


# --- PASO 3: CONVERSIÓN Y ENTREGA FINAL ---
print(f"{BOLD}{BLUE}\n--- PASO 3: CONVERSIÓN FINAL CON PANDOC ---{END}")

print(f"{BOLD}3.1 -> Compilar a PDF o DOCX.{END}")
print(f"       {YELLOW}Pandoc toma tu archivo .md y lo convierte, aplicando una plantilla para darle un diseño profesional (como un informe LaTeX o DOCX).{END}")
print(f"       {BOLD}{GREEN}COMANDO PDF: pandoc mi_informe.md -o informe_final.pdf{END}")
print(f"       {BOLD}{GREEN}COMANDO DOCX: pandoc mi_informe.md -o informe_final.docx{END}")

print(f"\n{BOLD}{GREEN}¡Markdown y Obsidian te dan velocidad; GitHub y Pandoc te dan control y calidad final!{END}")