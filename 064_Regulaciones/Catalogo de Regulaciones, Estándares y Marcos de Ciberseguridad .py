#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
from operator import itemgetter

# --- Definiciones de Colores ANSI ---
# Estos códigos permiten colorear la salida en la terminal sin librerías externas.
ANSI_RESET = '\033[0m'
ANSI_BOLD = '\033[1m'
ANSI_GRAY = '\033[90m'

# Asignación de colores por Categoría
# R: Regulación (Rojo Brillante), E: Estándar (Verde Brillante), 
# A: Auditoría/Metodología (Amarillo Brillante), M: Marco de Gestión (Cyan Brillante)
COLOR_MAP = {
    "R": '\033[91m', # Bright Red
    "E": '\033[92m', # Bright Green
    "A": '\033[93m', # Bright Yellow
    "M": '\033[96m', # Bright Cyan
}

def obtener_datos_regulaciones_final():
    """Devuelve la lista completa de regulaciones, estándares y marcos (49 entradas)."""
    # Categorías: R (Regulación Legal/Contractual), E (Estándar Técnico/Seguridad), 
    # A (Auditoría/Evaluación/Metodología Pentest), M (Marco de Gestión/Gobierno)
    # 
    # Se han añadido nuevas entradas (46 a 49) para cubrir:
    # - FISMA (Regulación Federal de EE. UU.)
    # - RMF (Marco de Gestión de Riesgos de NIST)
    # - DORA (Regulación de Resiliencia Digital de la UE)
    # - CSA CCM (Marco de Controles de Seguridad en la Nube)
    return [
        {"Valor": 1, "Regulación": "Payment Card Industry Data Security Standard", "Acrónimo": "PCI DSS", "Alcance": "International", "Categoría": "R", "Descripción": "Estándar de seguridad de la información requerido por las principales marcas de tarjetas de pago (Visa, MasterCard, etc.) para todas las entidades que almacenan, procesan o transmiten datos de titulares de tarjetas.", "URL": "https://www.pcisecuritystandards.org/"},
        {"Valor": 2, "Regulación": "Health Insurance Portability and Accountability Act", "Acrónimo": "HIPAA", "Alcance": "United States", "Categoría": "R", "Descripción": "Protege la información de salud protegida (**PHI**). Establece estándares para las transacciones electrónicas de atención médica y requiere salvaguardas de seguridad y privacidad para la información de salud individual.", "URL": "https://www.hhs.gov/hipaa/index.html"},
        {"Valor": 3, "Regulación": "Family Educational Rights and Privacy Act", "Acrónimo": "FERPA", "Alcance": "United States", "Categoría": "R", "Descripción": "Otorga a los padres el derecho a acceder a los registros educativos de sus hijos y establece límites sobre la divulgación de información de esos registros. Se aplica a instituciones que reciben fondos del Departamento de Educación de EE. UU.", "URL": "https://www2.ed.gov/policy/gen/guid/fpco/ferpa/index.html"},
        {"Valor": 4, "Regulación": "Sarbanes–Oxley Act", "Acrónimo": "SOX", "Alcance": "United States", "Categoría": "R", "Descripción": "Ley federal que establece estándares nuevos o mejorados para todas las juntas directivas, la administración y las empresas de contabilidad pública de EE. UU., especialmente en lo referente a la precisión y revelación de informes financieros.", "URL": "https://www.sec.gov/news/press/2002-125.htm"},
        {"Valor": 5, "Regulación": "Gramm–Leach–Bliley Act", "Acrónimo": "GLBA", "Alcance": "United States", "Categoría": "R", "Descripción": "Requiere que las instituciones financieras expliquen sus prácticas de intercambio de información a sus clientes y salvaguarden la información personal confidencial.", "URL": "https://www.ftc.gov/business-guidance/privacy-security/gramm-leach-bliley-act"},
        {"Valor": 6, "Regulación": "Personal Information Protection and Electronic Documents Act", "Acrónimo": "PIPEDA", "Alcance": "Canada", "Categoría": "R", "Descripción": "Ley canadiense que rige cómo las organizaciones del sector privado recopilan, usan y divulgan información personal en el curso de actividades comerciales.", "URL": "https://laws.justice.gc.ca/eng/acts/P-8.6/"},
        {"Valor": 7, "Regulación": "Data Protection Act 1998", "Acrónimo": "DPA", "Alcance": "United Kingdom", "Categoría": "R", "Descripción": "Ley principal que regula el procesamiento de datos de personas vivas identificables en el Reino Unido.", "URL": "https://www.legislation.gov.uk/ukpga/1998/29/contents"},
        {"Valor": 8, "Regulación": "Children's Online Privacy Protection Act", "Acrónimo": "COPPA", "Alcance": "United States", "Categoría": "R", "Descripción": "Se aplica a la recopilación en línea de información personal de niños menores de 13 años. Requiere consentimiento parental verificable.", "URL": "https://www.ftc.gov/enforcement/rules/rulemaking-regulatory-reform-proceedings/childrens-online-privacy-protection-rule"},
        {"Valor": 9, "Regulación": "California Security Breach Information Act", "Acrónimo": "CA SB-1386", "Alcance": "US (California)", "Categoría": "R", "Descripción": "Ley estatal que requiere que las organizaciones notifiquen a los individuos si la seguridad de su información personal se ve comprometida (violación de datos).", "URL": "https://leginfo.legislature.ca.gov/faces/billTextClient.xhtml?bill_id=200120020SB1386"},
        {"Valor": 10, "Regulación": "California Online Privacy Protection Act", "Acrónimo": "OPPA", "Alcance": "US (California)", "Categoría": "R", "Descripción": "Requiere que los operadores de sitios web publiquen de manera visible y cumplan con una política de privacidad si recopilan información de residentes de California.", "URL": "https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?sectionNum=22575.&lawCode=BPC"},
        {"Valor": 11, "Regulación": "Data Protection Directive", "Acrónimo": "Directive 95/46/EC", "Alcance": "European Union", "Categoría": "A", "Descripción": "Directiva original de la UE que regulaba el procesamiento de datos personales. **Reemplazada por GDPR**.", "URL": "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:31995L0046"},
        {"Valor": 12, "Regulación": "Directive on Privacy and Electronic Communications", "Acrónimo": "Directive 2002/58/EC", "Alcance": "European Union", "Categoría": "R", "Descripción": "Conocida como Directiva e-Privacy, regula la protección de datos y la privacidad en el sector de las comunicaciones electrónicas.", "URL": "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32002L0058"},
        {"Valor": 13, "Regulación": "General Data Protection Regulation", "Acrónimo": "GDPR", "Alcance": "EU & Global", "Categoría": "R", "Descripción": "Marco estricto de privacidad y control de datos para ciudadanos de la UE/EEE.", "URL": "https://gdpr-info.eu/"},
        {"Valor": 14, "Regulación": "System and Organization Controls", "Acrónimo": "SOC2", "Alcance": "United States", "Categoría": "A", "Descripción": "Informes de auditoría del AICPA que evalúan los controles internos de una organización de servicios.", "URL": "https://us.aicpa.org/interestareas/frc/assuranceadvisoryservices/aicpasoc2report"},
        {"Valor": 15, "Regulación": "Information Security Standard 27001", "Acrónimo": "ISO 27001", "Alcance": "International", "Categoría": "E", "Descripción": "Norma internacional que especifica los requisitos para un **Sistema de Gestión de Seguridad de la Información (SGSI)**.", "URL": "https://www.iso.org/isoiec-27001-information-security.html"},
        {"Valor": 16, "Regulación": "CISA Secure Software Development Attestation", "Acrónimo": "CISA-SSDA", "Alcance": "United States", "Categoría": "R", "Descripción": "Formulario de atestación requerido a los productores de software utilizado por el Gobierno Federal de EE. UU.", "URL": "https://www.cisa.gov/secure-software-attestation-form"},
        {"Valor": 17, "Regulación": "Federal Risk and Authorization Management Program", "Acrónimo": "FEDRAMP", "Alcance": "US (Federal)", "Categoría": "R", "Descripción": "Programa que proporciona un enfoque estandarizado para la evaluación de seguridad y autorización de servicios en la nube federales.", "URL": "https://www.fedramp.gov/"},
        {"Valor": 18, "Regulación": "Supply Chain Levels for Software Artifacts", "Acrónimo": "SLSA", "Alcance": "International", "Categoría": "E", "Descripción": "Marco de seguridad para la cadena de suministro de software.", "URL": "https://slsa.dev/"},
        {"Valor": 19, "Regulación": "NIST Secure Software Development Framework", "Acrónimo": "SSDF", "Alcance": "United States", "Categoría": "E", "Descripción": "Marco NIST (SP 800-218) que recomienda prácticas para reducir las vulnerabilidades en el *software*.", "URL": "https://csrc.nist.gov/projects/ssdf"},
        {"Valor": 20, "Regulación": "CIS Controls & Benchmarks", "Acrónimo": "CIS Benchmark", "Alcance": "International", "Categoría": "E", "Descripción": "Un conjunto de 18 salvaguardas de seguridad priorizadas y guías de configuración segura (Benchmarks).", "URL": "https://www.cisecurity.org/"},
        {"Valor": 21, "Regulación": "NIST Cybersecurity Framework", "Acrónimo": "CSF", "Alcance": "United States", "Categoría": "E", "Descripción": "Guía voluntaria para gestionar y reducir el riesgo de ciberseguridad. Organizado en cinco funciones clave: Identificar, Proteger, Detectar, Responder y Recuperar.", "URL": "https://www.nist.gov/cyberframework"},
        {"Valor": 22, "Regulación": "OWASP Application Security Verification Standard", "Acrónimo": "ASVS", "Alcance": "International", "Categoría": "E", "Descripción": "**Estándar detallado de requisitos de seguridad para aplicaciones web.** Proporciona una base para probar cualquier control técnico y asegura la seguridad durante el SDLC.", "URL": "https://owasp.org/www-project-application-security-verification-standard/"},
        {"Valor": 23, "Regulación": "OWASP Top 10", "Acrónimo": "OWASP T10", "Alcance": "International", "Categoría": "E", "Descripción": "Documento de concienciación sobre los 10 riesgos de seguridad más críticos para las aplicaciones web.", "URL": "https://owasp.org/www-project-top-ten/"},
        {"Valor": 24, "Regulación": "OWASP API Security Top 10", "Acrónimo": "OWASP API T10", "Alcance": "International", "Categoría": "E", "Descripción": "Documento de concienciación centrado en los 10 riesgos de seguridad más críticos específicos para las Interfaces de Programación de Aplicaciones (**API**).", "URL": "https://owasp.org/www-project-api-security/"},
        {"Valor": 25, "Regulación": "California Consumer Privacy Act", "Acrónimo": "CCPA", "Alcance": "US (California)", "Categoría": "R", "Descripción": "Otorga a los consumidores derechos sobre sus datos personales.", "URL": "https://oag.ca.gov/privacy/ccpa"},
        {"Valor": 26, "Regulación": "California Privacy Rights Act", "Acrónimo": "CPRA", "Alcance": "US (California)", "Categoría": "R", "Descripción": "Expande y modifica la CCPA, estableciendo la Agencia de Protección de la Privacidad de California (CPPA).", "URL": "https://cppa.ca.gov/"},
        {"Valor": 27, "Regulación": "NIST Special Publication 800-53", "Acrónimo": "NIST 800-53", "Alcance": "US (Federal)", "Categoría": "E", "Descripción": "Catálogo de controles de seguridad y privacidad recomendados para sistemas de información federales. Su uso es **mandatario** bajo la ley FISMA.", "URL": "https://csrc.nist.gov/pubs/sp/800/53/r5/final"},
        {"Valor": 28, "Regulación": "Cybersecurity Maturity Model Certification", "Acrónimo": "CMMC", "Alcance": "US (DoD)", "Categoría": "R", "Descripción": "Marco de certificación de seguridad para contratistas del Departamento de Defensa de EE. UU. (DoD).", "URL": "https://dodcio.defense.gov/CMMC/"},
        {"Valor": 29, "Regulación": "Lei Geral de Proteção de Dados", "Acrónimo": "LGPD", "Alcance": "Brazil", "Categoría": "R", "Descripción": "Ley brasileña de protección de datos personales que regula el tratamiento de datos, similar al GDPR.", "URL": "http://www.planalto.gov.br/ccivil_03/_ato2015-2018/2018/lei/l13709.htm"},
        {"Valor": 30, "Regulación": "Australian Prudential Regulation Authority", "Acrónimo": "APRA", "Alcance": "Australia", "Categoría": "R", "Descripción": "Estándares y directrices que cubren la gestión de riesgos de seguridad de la información para entidades financieras y de seguros.", "URL": "https://www.apra.gov.au/cross-industry-supervision/cyber-resilience"},
        {"Valor": 31, "Regulación": "Payment Card Industry Data Security Standard v4.0", "Acrónimo": "PCI DSS v4.0", "Alcance": "International", "Categoría": "R", "Descripción": "La versión más reciente del estándar de seguridad para la industria de tarjetas de pago.", "URL": "https://www.pcisecuritystandards.org/documents/PCI-DSS-v4-0-Executive-Summary.pdf"},
        
        # --- Entradas de Auditoría (NIA/NOGAI) ---
        {"Valor": 32, "Regulación": "Normas Internacionales de Auditoría", "Acrónimo": "NIA", "Alcance": "International", "Categoría": "A", "Descripción": "Estándares utilizados para auditorías externas de estados financieros. Evalúan indirectamente los controles de TI. **No regula pentest.**", "URL": "https://www.ifac.org/knowledge-gateway/auditing-assurance/latest-news/international-standards-auditing-isa"},
        {"Valor": 33, "Regulación": "Normas de Auditoría General de Intervención", "Acrónimo": "NOGAI", "Alcance": "International", "Categoría": "A", "Descripción": "Directrices para la auditoría interna/gubernamental. Requieren un enfoque basado en riesgos, que a menudo incluye la evaluación de los riesgos de TI. **No regula pentest.**", "URL": "https://www.theiia.org/en/standards/global-internal-audit-standards/"},
        
        # --- Entradas de Marcos de Gestión (ITIL/COBIT/MAGERIT y nuevos ISO) ---
        {"Valor": 34, "Regulación": "Control Objectives for Information and Related Technologies", "Acrónimo": "COBIT", "Alcance": "International", "Categoría": "M", "Descripción": "Marco de **GOBIERNO** y gestión de TI (ISACA). Ayuda a las organizaciones a alinear la TI con los objetivos del negocio.", "URL": "https://www.isaca.org/resources/cobit"},
        {"Valor": 35, "Regulación": "Information Technology Infrastructure Library", "Acrónimo": "ITIL", "Alcance": "International", "Categoría": "M", "Descripción": "Conjunto de prácticas para la **Gestión de Servicios de TI (ITSM)**.", "URL": "https://www.axelos.com/itil"},
        {"Valor": 36, "Regulación": "Metodología de Análisis y Gestión de Riesgos de la Información", "Acrónimo": "MAGERIT", "Alcance": "Spain/EU", "Categoría": "M", "Descripción": "Metodología española de **ANÁLISIS y gestión de riesgos** en Sistemas de Información.", "URL": "https://administracionelectronica.gob.es/pae/magerit"},
        {"Valor": 37, "Regulación": "Information Security Controls 27002", "Acrónimo": "ISO 27002", "Alcance": "International", "Categoría": "E", "Descripción": "Guía de referencia para la implementación de los **controles de seguridad** de la información mencionados en ISO 27001.", "URL": "https://www.iso.org/standard/82875.html"},
        {"Valor": 38, "Regulación": "Privacy Information Management System (PIMS)", "Acrónimo": "ISO 27701", "Alcance": "International", "Categoría": "E", "Descripción": "Extensión de ISO 27001/27002 para la **gestión de la privacidad** de la información.", "URL": "https://www.iso.org/standard/70388.html"},
        {"Valor": 39, "Regulación": "Risk Management", "Acrónimo": "ISO 31000", "Alcance": "International", "Categoría": "M", "Descripción": "Principios y directrices genéricas para la **gestión del riesgo** de cualquier tipo.", "URL": "https://www.iso.org/standard/65552.html"},

        # --- Entradas de Pentesting/Seguridad Ofensiva (Enlaces Corregidos) ---
        {"Valor": 40, "Regulación": "Penetration Testing Execution Standard", "Acrónimo": "PTES", "Alcance": "International", "Categoría": "A", "Descripción": "Estándar que establece una metodología completa de prueba de penetración con 7 fases clave.", "URL": "http://www.pentest-standard.org/"},
        {"Valor": 41, "Regulación": "Open Source Security Testing Methodology Manual", "Acrónimo": "OSSTMM", "Alcance": "International", "Categoría": "A", "Descripción": "Metodología rigurosa para la evaluación de seguridad, con un fuerte enfoque en la medición de la seguridad (Security Metrics).", "URL": "https://www.isecom.org/"},
        {"Valor": 42, "Regulación": "Web Application Security Consortium Threat Classification", "Acrónimo": "WASC TC", "Alcance": "International", "Categoría": "E", "Descripción": "Clasificación de ataques y vulnerabilidades de aplicaciones web, que complementa a OWASP Top 10 con una taxonomía más detallada de las amenazas.", "URL": "https://projects.owasp.org/web-app-security-project/threat-classification.html"},
        {"Valor": 43, "Regulación": "Adversarial Tactics, Techniques, and Common Knowledge", "Acrónimo": "ATT&CK", "Alcance": "International", "Categoría": "E", "Descripción": "Marco de conocimiento global de MITRE que enumera y describe las tácticas y técnicas adversarias (Red Teaming y Detección).", "URL": "https://attack.mitre.org/"},
        {"Valor": 44, "Regulación": "Threat Intelligence-based Ethical Red Teaming", "Acrónimo": "TIBER-EU", "Alcance": "European Union", "Categoría": "A", "Descripción": "Marco Europeo que guía el Red Teaming basado en inteligencia de amenazas para las entidades financieras.", "URL": "https://www.ecb.europa.eu/paym/html/tiber-eu.en.html"},
        {"Valor": 45, "Regulación": "Mobile Application Security Verification Standard", "Acrónimo": "MASVS", "Alcance": "International", "Categoría": "E", "Descripción": "Estándar de requisitos de seguridad para aplicaciones móviles (iOS y Android). Proporciona una base para pruebas de penetración móvil.", "URL": "https://owasp.org/www-project-mobile-application-security-verification-standard/"},
        
        # --- Nuevas Entradas Adicionales (46 a 49) ---
        {"Valor": 46, "Regulación": "Federal Information Security Modernization Act", "Acrónimo": "FISMA", "Alcance": "US (Federal)", "Categoría": "R", "Descripción": "Ley federal de EE. UU. que requiere que las agencias federales y sus contratistas implementen programas de seguridad de la información. **Manda el uso de estándares NIST** como el SP 800-53.", "URL": "https://www.cisa.gov/fisma"},
        {"Valor": 47, "Regulación": "NIST Special Publication 800-37 (Risk Management Framework)", "Acrónimo": "RMF", "Alcance": "US (Federal)", "Categoría": "M", "Descripción": "Define el enfoque sistemático (6 pasos: Preparar, Categorizar, Seleccionar, Implementar, Evaluar, Autorizar y Monitorear) para integrar la gestión de riesgos de seguridad y privacidad en el ciclo de vida de los sistemas de información federales. [Image of NIST Risk Management Framework]", "URL": "https://csrc.nist.gov/pubs/sp/800/37/r2/final"},
        {"Valor": 48, "Regulación": "Digital Operational Resilience Act", "Acrónimo": "DORA", "Alcance": "European Union", "Categoría": "R", "Descripción": "Regulación de la UE que establece requisitos uniformes de **resiliencia operativa digital** para el sector financiero, incluyendo la gestión de riesgos de las TIC de terceros (proveedores cloud).", "URL": "https://finance.ec.europa.eu/digital-finance/digital-operational-resilience-act-dora_en"},
        {"Valor": 49, "Regulación": "Cloud Security Alliance Cloud Controls Matrix", "Acrónimo": "CSA CCM", "Alcance": "International", "Categoría": "E", "Descripción": "Marco de controles de ciberseguridad específico para la computación en la nube. Proporciona una matriz de 197 controles y mapeos a múltiples regulaciones y estándares (ISO 27001, COBIT, HIPAA, etc.).", "URL": "https://cloudsecurityalliance.org/research/cloud-controls-matrix/"},
    ]

def obtener_nombre_categoria(acronimo_cat):
    """Devuelve el nombre completo de la categoría."""
    mapping = {
        "R": "Regulación Legal/Contractual",
        "E": "Estándar Técnico/Seguridad",
        "A": "Auditoría/Evaluación/Metodología Pentest",
        "M": "Marco de Gestión/Gobierno de TI"
    }
    return mapping.get(acronimo_cat, "Desconocido")

def imprimir_tabla(datos):
    """
    Imprime los datos ordenados y con colores usando códigos ANSI.
    """
    if not datos:
        print("No hay datos para mostrar.")
        return

    # 1. Ordenar los datos: Primero por Categoría, luego alfabéticamente por Acrónimo
    # Utilizar 'Categoría' como clave de orden principal y 'Acrónimo' como clave secundaria.
    datos_ordenados = sorted(datos, key=itemgetter('Categoría', 'Acrónimo'))

    # Título principal
    print(ANSI_BOLD + "\n--- Catálogo de Regulaciones, Estándares y Marcos de Ciberseguridad ---" + ANSI_RESET)
    
    # Leyenda de Colores
    print("\n" + ANSI_BOLD + "Leyenda de Categorías:" + ANSI_RESET)
    leyenda_parts = []
    for acr, color in COLOR_MAP.items():
        nombre = obtener_nombre_categoria(acr)
        leyenda_parts.append(f"{color}{ANSI_BOLD}{acr}{ANSI_RESET} ({nombre})")
    print(" | ".join(leyenda_parts))
    print("-" * 100)

    # Variables para control de agrupamiento por categoría
    categoria_actual = None
    # Contador para la numeración secuencial de las entradas impresas
    entry_number = 0
    
    for item in datos_ordenados:
        categoria = item["Categoría"]
        acronimo = item["Acrónimo"]
        regulacion = item["Regulación"]
        alcance = item["Alcance"]
        descripcion = item["Descripción"]
        url = item["URL"]
        color = COLOR_MAP.get(categoria, ANSI_RESET) # Obtiene el color de la categoría

        # Imprime el encabezado de la categoría si cambia
        if categoria != categoria_actual:
            nombre_cat = obtener_nombre_categoria(categoria)
            # Reutilizo el cálculo de la longitud de la lista para el título de la categoría
            categoria_count = len([d for d in datos if d['Categoría'] == categoria])
            print(f"\n{ANSI_BOLD}{color}>>> {categoria} - {nombre_cat} ({categoria_count} Entradas){ANSI_RESET}\n" + "=" * 100)
            categoria_actual = categoria

        # Formato de la entrada
        # 2. Agregar el número secuencial (ej. 01., 02., etc.)
        entry_number += 1
        # Línea de Acrónimo y Regulación (destacada)
        print(f"{ANSI_BOLD}{entry_number:02d}.{ANSI_RESET} {color}{ANSI_BOLD}[{acronimo}]{ANSI_RESET} {regulacion}")
        
        # Línea de Alcance y Categoría (en gris)
        print(f"{ANSI_GRAY}  Alcance: {alcance} | Categoría: {categoria}{ANSI_RESET}")
        
        # Línea de Descripción
        print(f"  Descripción: {descripcion}")
        
        # Línea de URL
        print(f"  URL: {url}\n")
        
        # Separador ligero entre entradas
        print("-" * 50)


if __name__ == "__main__":
    try:
        data = obtener_datos_regulaciones_final()
        imprimir_tabla(data)
    except Exception as e:
        print(f"Ocurrió un error: {e}", file=sys.stderr)