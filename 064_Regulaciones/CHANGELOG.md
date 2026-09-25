# Changelog — Catálogo de Ciberseguridad

## [3.0.0] — 2026-09-25

Corte documental: 25-09-2026. Sin dependencias externas.

### Agregado

- `datos_catalogo.json`: 104 entradas con fuente oficial o de su editor (Chile 15, América Latina 29, banca y seguros 19, resto global).
- Cobertura Chile: Ley 21.719 (vigencia 01-12-2026), Ley 19.628 en transición, Ley 21.459 vigente, Ley 19.223 derogada, Ley 21.663, reglamento de incidentes, Ley 20.285, Estrategia Nacional y normativa CMF.
- Cobertura LATAM: Argentina, Brasil, Colombia, Costa Rica, Ecuador, México, Perú y Uruguay.
- Referencias Red/Blue/Purple: CSF 2.0, NIST SP 800-53 Rev. 5.2.0, SP 800-61 Rev. 3, MITRE ATT&CK/D3FEND, OWASP ASVS 5.0.0, CIS Controls v8.1, PCI DSS v4.0.1, PTES, OSSTMM 3, TIBER-EU, FIRST.
- CLI (`catalogo_ciberseguridad.py`): `listar`, `buscar`, `banca`, `ver`, `resumen`, `paises`, `roles`, `mapa`, `exportar` (JSON/CSV), filtros combinables y exclusión de históricos por defecto.
- `test_catalogo_ciberseguridad.py`: 14 pruebas (cobertura, transición chilena, versiones, filtros, CLI, exportación).
- Este CHANGELOG.

### Cambiado

- Datos separados a JSON editable; el script anterior queda como wrapper compatible que ya no imprime al importarse.
- `Readme.md` reescrito con alcance, comandos y criterio legal.
- Excepción en `.gitignore` para versionar `064_Regulaciones/datos_catalogo.json`.
- Filtros de rol/país insensibles a guiones, espacios y acentos.

### Criterio

- Se distingue ley/regulación obligatoria de estándar, marco, metodología, guía, evaluación y base de conocimiento.
- Fechas no verificadas se omiten ("No consignada") en lugar de inventarse.
- Guía técnica, no asesoramiento legal.

## [2.1.0] — anterior

- Catálogo de 49 entradas con datos embebidos en un solo script.
