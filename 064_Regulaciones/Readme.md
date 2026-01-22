# Catálogo de Regulaciones, Estándares y Marcos de Ciberseguridad

Este proyecto es una herramienta de terminal escrita en Python que proporciona un catálogo organizado y categorizado de **49 normativas clave** en el mundo de la ciberseguridad, la privacidad de datos y la auditoría de TI.

El script clasifica cada entrada por su naturaleza (Legal, Técnica, Gestión o Auditoría) y facilita la consulta de descripciones rápidas y enlaces oficiales.

## 🚀 Características

* **Clasificación por Colores:** Interfaz de línea de comandos (CLI) que utiliza códigos ANSI para diferenciar visualmente las categorías.
* **Organización Inteligente:** Los datos se presentan ordenados alfabéticamente dentro de cada categoría.
* **Información Detallada:** Incluye acrónimo, nombre completo, alcance geográfico/sectorial, descripción técnica y URL de referencia.
* **Amplia Cobertura:** Desde normativas clásicas como **PCI DSS** y **GDPR** hasta marcos modernos como **DORA**, **SLSA** y **TIBER-EU**.

## 📊 Categorías Incluidas

El catálogo divide las normativas en cuatro pilares fundamentales:

| Código | Categoría | Ejemplo |
| --- | --- | --- |
| **R** | Regulación Legal/Contractual | GDPR, HIPAA, DORA |
| **E** | Estándar Técnico/Seguridad | ISO 27001, OWASP ASVS, NIST 800-53 |
| **A** | Auditoría y Metodología Pentest | PTES, OSSTMM, SOC2 |
| **M** | Marco de Gestión y Gobierno | COBIT, ITIL, NIST RMF |

## 🛠️ Requisitos e Instalación

1. **Requisitos:** Tener instalado Python 3.x.
2  **Ejecución:** No requiere librerías externas. Solo ejecuta:
```bash
python "Catalogo de Regulaciones, Estándares y Marcos de Ciberseguridad .py"

```



## 📝 Ejemplo de Salida

```text
>>> R - Regulación Legal/Contractual (20 Entradas)
====================================================================================================
01. [CCPA] California Consumer Privacy Act
  Alcance: US (California) | Categoría: R
  Descripción: Otorga a los consumidores derechos sobre sus datos personales.
  URL: https://oag.ca.gov/privacy/ccpa
--------------------------------------------------

```

## 📄 Contenido del Catálogo

El script incluye información sobre:

* **Privacidad:** GDPR, LGPD, CCPA, PIPEDA.
* **Finanzas:** PCI DSS v4.0, DORA, GLBA.
* **Ciberseguridad Ofensiva:** PTES, MITRE ATT&CK, TIBER-EU.
* **Desarrollo Seguro:** NIST SSDF, SLSA, OWASP Top 10.
* **Gestión de Riesgos:** NIST RMF (SP 800-37), MAGERIT, ISO 31000.

---

 