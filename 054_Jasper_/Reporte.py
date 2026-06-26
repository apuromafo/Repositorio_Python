#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# =============================================================================
# AVISO LEGAL / LEGAL NOTICE
# -----------------------------------------------------------------------------
# Esta herramienta es unicamente para fines educativos y de auditoria de
# seguridad autorizada. El uso no autorizado contra sistemas sin el
# consentimiento explicito del propietario es ilegal.
# El usuario asume toda responsabilidad por el uso indebido.
#
# This tool is for educational and authorized security auditing purposes only.
# Unauthorized use against systems without the owner's explicit consent is
# illegal. The user assumes all responsibility for misuse.
# =============================================================================

import json
import os
import argparse
import sys
from pathlib import Path
from datetime import datetime


# ==============================================================================
# CONFIGURACIÓN TÉCNICA (OWASP & RECOMENDACIONES)
# ==============================================================================
SEVERIDAD_MAP = {
    "SQL Injection": "Crítico", "Riesgo LFI": "Crítico", "RCE CRÍTICO": "Crítico",
    "Debilidad de Tipado": "Medio", "XSS": "Medio", "Exposición de Datos": "Medio",
    "Obsolescencia": "Informativo"
}

# Mapa de colores para el gráfico (formato Hexadecimal)
COLOR_MAP = {
    "Crítico": "#8B0000",   # Rojo Oscuro
    "Alto": "#FF0000",      # Rojo
    "Medio": "#FFA500",     # Naranjo
    "Bajo": "#008000",      # Verde
    "Informativo": "#87CEEB" # Celeste
}

RECOMENDACIONES_MAP = {
    "SQL Injection": "Reemplazar query dinámico por Sentencias Preparadas (Prepared Statements).",
    "Riesgo LFI": "Implementar whitelisting en la ruta de archivos y validar parámetros.",
    "RCE CRÍTICO": "Restringir la ejecución de comandos arbitrarios y sanear entradas.",
    "Debilidad de Tipado": "Forzar tipado estricto (ej. BigDecimal). Reemplazar tipo Object.",
    "XSS": "Sanitizar entradas de usuario antes de la renderización.",
    "Exposición de Datos": "Aplicar enmascaramiento de datos (PII) y cifrado en reposo.",
    "Obsolescencia": "Actualizar dependencias a versiones estables y eliminar código deprecado."
}


    
def generar_md_contenido(nombre_archivo, hallazgos):
    resumen = {"Crítico": 0, "Medio": 0, "Informativo": 0}
    for h in hallazgos:
        sev = SEVERIDAD_MAP.get(h.get('tipo'), "Informativo")
        resumen[sev] += 1

    # Filtramos solo las categorías que tienen al menos un hallazgo
    categorias_activas = [cat for cat, cant in resumen.items() if cant > 0]
    valores_activos = [cant for cat, cant in resumen.items() if cant > 0]

    content = f"# Informe de Auditoría: `{nombre_archivo}`\n"
    content += f"**Fecha de generación:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
    
# Bloque Mermaid corregido para máxima compatibilidad
    content += "## 📊 Distribución de Severidad\n"
    content += "```mermaid\n"
    content += "xychart-beta\n"
    content += '    title "Hallazgos por Severidad"\n'
    
    # Convertimos la lista de Python en una cadena de texto compatible con Mermaid: ["Cat1", "Cat2"]
    ejes_x = ', '.join([f'"{cat}"' for cat in categorias_activas])
    content += f'    x-axis [{ejes_x}]\n'
    
    content += '    y-axis "Cantidad" 0 --> 5\n'
    
    # Convertimos la lista de valores a cadena: [1, 2]
    valores_y = ', '.join([str(v) for v in valores_activos])
    content += f'    bar [{valores_y}]\n'
    content += "```\n\n"

    content += "## 🛠 Hallazgos Técnicos Identificados\n"
    content += "| Severidad | Tipo de Vulnerabilidad | Detalle Técnico | Recomendación |\n"
    content += "| :--- | :--- | :--- | :--- |\n"
    
    for h in hallazgos:
        tipo = h.get('tipo', 'N/A')
        detalle = h.get('detalle', 'Sin detalle')
        sev = SEVERIDAD_MAP.get(tipo, "Informativo")
        rec = RECOMENDACIONES_MAP.get(tipo, "Revisar estándar OWASP.")
        icon = "🔴" if sev == "Crítico" else "🟠" if sev == "Medio" else "🔵"
        content += f"| {icon} **{sev}** | {tipo} | {detalle} | {rec} |\n"
        
    return content
    
def procesar_reporte(ruta_input, modo):
    if not os.path.exists(ruta_input):
        print(f"[-] Error: Archivo '{ruta_input}' no encontrado.")
        sys.exit(1)

    with open(ruta_input, 'r', encoding='utf-8') as f:
        data = json.load(f)

    output_dir = Path("Reportes_Finales")
    output_dir.mkdir(exist_ok=True)

    if modo == '1':
        for archivo, hallazgos in data.items():
            nombre_base = Path(archivo).stem
            ruta_salida = output_dir / f"{nombre_base}_reporte.md"
            with open(ruta_salida, 'w', encoding='utf-8') as f:
                f.write(generar_md_contenido(archivo, hallazgos))
            print(f"[!] Guardado: {ruta_salida}")
    else:
        ruta_salida = output_dir / f"Consolidado_{datetime.now().strftime('%Y%m%d')}.md"
        with open(ruta_salida, 'w', encoding='utf-8') as f:
            f.write("# Informe Consolidado de Auditoría\n\n")
            for archivo, hallazgos in data.items():
                f.write(generar_md_contenido(archivo, hallazgos) + "\n---\n")
        print(f"[+] Consolidado generado: {ruta_salida}")


print("\n[!] AVISO LEGAL: Use solo con autorizacion. / LEGAL NOTICE: Authorized use only.\n")
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", help="Ruta del archivo JSON")
    args = parser.parse_args()

    ruta = args.input if args.input else input("Ingresa la ruta del archivo JSON: ").strip()
    ruta = ruta.replace('"', '').replace("'", "")
    
    print("\n[?] Modos: (1) Individual | (2) Consolidado")
    modo = input("Selección (1/2): ").strip()
    
    procesar_reporte(ruta, modo)