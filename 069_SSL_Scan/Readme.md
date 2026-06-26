
# 🔐 SCAN SSL — Auditor de Seguridad SSL/TLS

**Versión:** v34.1  
**Estado:** Estable / Producción  
**Licencia:** MIT  
**Repositorio:** [apuromafo/Repositorio_Python](https://github.com/apuromafo/Repositorio_Python)

---

## ¿Qué hace esta herramienta?

**SCAN SSL** es un auditor automatizado de seguridad SSL/TLS que analiza servidores web en busca de:

- **Protocolos inseguros** — SSLv2, SSLv3, TLSv1.0, TLSv1.1
- **Cifrados débiles** y falta de PFS (Perfect Forward Secrecy)
- **Vulnerabilidades** — Heartbleed (CVE-2014-0160), renegociación insegura (CVE-2009-3555)
- **Cumplimiento normativo:**
  - **PCI DSS 4.0.1** — Requisitos de confianza, renegociación y cifrados
  - **NIST SP 800-52 Rev.2** — Control de vigencia, CA y TLS 1.3
  - **FIPS 203 (ML-KEM)** — Preparación post-cuántica en intercambio de claves
  - **FIPS 204 (ML-DSA)** — Preparación post-cuántica en firmas digitales
- **Puntuación CVSS 4.0 y 3.1** — Asignación de vectores de severidad según FIRST.org

### ¿Qué permite?

| Modo | Descripción |
|------|-------------|
| `-t <dominio>` | Escaneo en vivo de un servidor SSL/TLS |
| `-f <carpeta>` | Revisión offline de evidencia guardada |
| `-c` | Generar comandos curl/openssl/nmap para verificación manual |
| `-V` | Mostrar versión |
| `-h` | Ayuda detallada |

---

## Requisitos

- **Python 3.8+**
- **Conexión a internet** (solo primera ejecución para descargar `sslscan`)
- **Dependencia:** `colorama`

```bash
pip install colorama
```

---

## Instalación

```bash
git clone https://github.com/apuromafo/Repositorio_Python.git
cd Repositorio_Python/069_SSL_Scan
pip install -r requirements.txt
```

---

## Uso

### Escaneo en vivo

```bash
python Scan_ssl_v3.py -t example.com
```

### Revisión offline (desde escaneo previo)

```bash
python Scan_ssl_v3.py -f ./Resultados_SSL/example_com_20260625_120000
```

### Escaneo con comandos curl

```bash
python Scan_ssl_v3.py -t example.com -c
```

### Ver versión

```bash
python Scan_ssl_v3.py -V
```

---

## Estructura de salida

```
Resultados_SSL/
└── <target>_<fecha>_<hora>/
    ├── EVIDENCIA_SSLSCAN.log    # Salida cruda de sslscan
    ├── FINDINGS_SSL.json        # Hallazgos estructurados con CVSS
    └── CURLS_SSL.json           # (opcional) Comandos de verificación manual
```

---

## Ejemplo de reporte

```
>>> Prueba de Preparación Post-Cuántica (PQC) FIPS 203/204
Intercambio de Claves Híbrido ML-KEM          | Vanguardia
    Referencia: FIPS 203
    └─ Evidencia: X25519MLKEM768
Firma Digital PQC (ML-DSA)                    | No cumple con NIST
    └─ ACCIÓN REQUERIDA: Migrar a ML-DSA

>>> Prueba de Cumplimiento PCI DSS 4.0.1
Certificados Confiables                       | Confiable
    Referencia: PCI DSS 4.2
Vulnerabilidad: HEARTBLEED                    | No vulnerable
Renegociación Segura                          | Buena configuración

>>> Resumen Ejecutivo de Riesgo (CVSS 4.0 / 3.1)
  [HIGH] TLSv1.0
    CVSS 4.0: 7.4 | CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L
    CVSS 3.1: 7.5 | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N

  Score de Riesgo Acumulado:    2.0/10 (BAJO)
  Hallazgos Críticos:           0
  Hallazgos Altos:              2
  Hallazgos Medios:             1
```

---

## CVSS — Referencias y metodología

Los vectores CVSS 4.0 y 3.1 siguen la especificación oficial de **FIRST.org**:

- [CVSS 4.0 Specification](https://www.first.org/cvss/v4-0/cvss-v40-specification_v1.0.pdf)
- [CVSS 3.1 Specification](https://www.first.org/cvss/v3-1/cvss-v31-specification_v1.1.pdf)
- [Calculadora CVSS 4.0](https://www.first.org/cvss/calculator/4.0)
- [Calculadora CVSS 3.1](https://www.first.org/cvss/calculator/3.1)

| Hallazgo | CVSS 4.0 | CVSS 3.1 | Referencias |
|----------|----------|----------|-------------|
| SSLv2/3 habilitado | 9.8 CRITICAL | 9.8 CRITICAL | CVE-2014-3566, CVE-2016-0800 |
| TLSv1.0/1 habilitado | 7.4 HIGH | 7.5 HIGH | CVE-2011-3389, RFC 8996 |
| TLSv1.3 no habilitado | 5.9 MEDIUM | 5.9 MEDIUM | NIST SP 800-52 Rev.2 |
| Heartbleed | 7.5 HIGH | 7.5 HIGH | CVE-2014-0160, CAPEC-497 |
| Renegociación insegura | 6.8 MEDIUM | 6.8 MEDIUM | CVE-2009-3555, RFC 5746 |
| Sin KEX Post-Cuántico | 4.8 MEDIUM | 4.8 MEDIUM | FIPS 203, NIST IR 8545 |
| Sin firma Post-Cuántica | 5.3 MEDIUM | 5.3 MEDIUM | FIPS 204, NIST IR 8413 |

---

## Motor de escaneo

La herramienta utiliza [**sslscan**](https://github.com/rbsec/sslscan) v2.2.2, un escáner SSL/TLS de código abierto que detecta:

- Protocolos y cifrados soportados
- Grupos de intercambio de claves
- Renegociación y compresión TLS
- Vulnerabilidad Heartbleed
- Detalles del certificado SSL

El binario se descarga automáticamente en la primera ejecución desde GitHub releases.

---

## Pruebas

```bash
# Ejecutar todas las pruebas
python -m pytest tests/ -v

# Cobertura (si pytest-cov está instalado)
python -m pytest tests/ --cov=Scan_ssl_v3.py -v
```

Las pruebas cubren:
- Motor de coloreado (`render_log_line`)
- Motor de auditoría y cumplimiento (`ejecutar_auditoria_v34`)
- Provisión del binario (`provisionar_binario`)
- CLI completo (argumentos, flags, modos offline/live)
- Generación de curls y exportación JSON

---

## Changelog

| Versión | Cambios |
|---------|---------|
| v34.1   | ✨ CVSS 4.0/3.1 con vectores documentados · `--version` · `--curl` · Findings JSON · Tests unitarios (39) · README completo · Todo en español |
| v34.0   | 🚀 PCI DSS 4.0.1 · NIST SP 800-52 · FIPS 203/204 (PQC) · Coloreado profesional |
| v2.x    | Escaneo básico con sslscan · Salida coloreada |

---

## Autor

**Apuromafo Security Team**  
[GitHub](https://github.com/apuromafo)


## ⚠️ Aviso Legal / Legal Notice

Esta herramienta es unicamente para fines educativos y de auditoria de seguridad autorizada. El uso no autorizado contra sistemas sin el consentimiento explicito del propietario es ilegal. El usuario asume toda responsabilidad por el uso indebido.

This tool is for educational and authorized security auditing purposes only. Unauthorized use against systems without the owner's explicit consent is illegal. The user assumes all responsibility for misuse.
