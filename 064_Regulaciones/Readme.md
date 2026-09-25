# Catálogo de Ciberseguridad — Red, Blue y Purple Team

Herramienta de terminal en Python (sin dependencias externas) con **104 referencias** de ciberseguridad, privacidad y regulación financiera, con corte documental al **25-09-2026**. Cubre Chile, América Latina, banca y seguros, y referencias globales.

Los datos viven en `datos_catalogo.json` (editable). La entrada principal es `catalogo_ciberseguridad.py`. El archivo con el nombre anterior se conserva como wrapper compatible y ya no imprime al importarse.

## Cobertura

- **Chile (15):** Ley 21.719 (vigencia 01-12-2026), Ley 19.628 en transición, Ley 21.459 vigente, Ley 19.223 derogada, Ley 21.663, reglamento de incidentes, Ley 20.285, Estrategia Nacional y normativa CMF (RAN 20-10, 20-9, 20-8, 20-7, 1-7, NCG 454 y FAQ).
- **América Latina (29):** Argentina, Brasil, Colombia, Costa Rica, Ecuador, México, Perú y Uruguay (privacidad, ciberdelito y banca).
- **Banca y seguros (19):** CMF, BCRA, BCB/CMN, Superfinanciera, CNBV, SBS, DORA, GLBA, SOX, APRA CPS 234 y TIBER-EU, distinguiendo obligación de guía.
- **Global:** GDPR, NIS2, DORA, CRA, CCPA/CPRA, HIPAA, FISMA, FedRAMP, CMMC, PIPEDA, APRA, APPI, PDPA, DPDP Act, PCI DSS v4.0.1, familia ISO 27000, NIST (CSF 2.0, SP 800-53 Rev. 5.2.0, SP 800-61 Rev. 3, RMF, 800-115, ZTA, SSDF), MITRE ATT&CK/D3FEND, OWASP (Top 10, API, ASVS 5.0.0, WSTG, MASVS, SAMM), CIS Controls v8.1, PTES, OSSTMM 3, FIRST, SLSA, CSA CCM, SOC 2, COBIT 2019, ITIL 4 y MAGERIT v3.

## Uso

```bash
python catalogo_ciberseguridad.py resumen
python catalogo_ciberseguridad.py banca --rol blue-team
python catalogo_ciberseguridad.py buscar incidentes --region "América Latina"
python catalogo_ciberseguridad.py ver CL-PRV-001
python catalogo_ciberseguridad.py mapa
python catalogo_ciberseguridad.py paises
python catalogo_ciberseguridad.py roles
python catalogo_ciberseguridad.py exportar --formato csv --salida reporte.csv --forzar
python -m unittest
```

Filtros combinables: `--pais`, `--region`, `--categoria`, `--sector`, `--rol`, `--estado`, `--obligatoriedad`. Los históricos (derogadas/retiradas) se excluyen por defecto; se muestran con `--incluir-historicos` o `--estado`.

## Criterio legal

- Se distingue **ley/regulación** (obligatoria) de **estándar, marco, metodología, guía, evaluación y base de conocimiento** (voluntarios, contractuales o de referencia).
- ISO, NIST, OWASP y MITRE **no** se presentan como obligaciones legales globales.
- Las fechas no verificadas en fuente oficial se omiten ("No consignada") en lugar de inventarse.
- Corte documental 25-09-2026: guía técnica, **no asesoramiento legal**. Verifique vigencia, alcance territorial y texto oficial antes de decidir.

## Pruebas autorizadas

Solo para fines educativos y auditoría de seguridad **autorizada**. El uso no autorizado contra sistemas sin consentimiento explícito del propietario es ilegal.
