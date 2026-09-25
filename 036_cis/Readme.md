## README General - Scripts de Revisión CIS (v8.1.2)

**Descripción:**

Este directorio contiene herramientas para revisar el cumplimiento básico con los
controles de seguridad del CIS (Center for Internet Security), versión **8.1.2
(marzo 2025)**: **18 controles y 153 salvaguardas**, en español e inglés.

```
036_cis/
├── Readme.md              Este archivo
├── Json/
│   ├── Leer.py                  Lector interactivo de controles (menú ES/EN)
│   ├── all_cis_controls_es.json 18 controles + 153 salvaguardas en español
│   ├── all_cis_controls_en.json 18 controles + 153 salvaguardas en inglés
│   ├── Readme.md
│   └── documentos/              CSV/XLSX/PDF oficiales CIS v8.1.2
├── Windows/
│   ├── win.py     Auditoría básica Windows (Defender, cuentas, red, logs)
│   └── Readme.md
└── Linux/
    ├── linux.py   Evaluación básica Linux (firewall, logs, updates, inventario)
    └── Readme.md
```

**Uso rápido:**

```bash
# Leer los controles (menú interactivo)
cd 036_cis/Json && python Leer.py

# Auditoría Windows (como administrador)
cd 036_cis/Windows && python win.py

# Evaluación Linux
cd 036_cis/Linux && python linux.py
```

## Notas Importantes:

## Buenas prácticas antes de ejecutar (los scripts también lo muestran)

1. Ejecute SOLO en sistemas propios o con autorización escrita.
2. Privilegios mínimos necesarios (admin/root solo si el chequeo lo requiere).
3. Pruebe primero en entorno no productivo (VM/Vagrant).
4. Herramientas de SOLO LECTURA: revise cada recomendación antes de aplicar cambios.

Autores: apuromafo ([github.com/apuromafo](https://github.com/apuromafo)) —
sugerencias y reportes en [issues](https://github.com/apuromafo/Repositorio_Python/issues).

*   Estos scripts son una herramienta de revisión básica y no sustituyen a un análisis de seguridad exhaustivo.
*   Asegúrese de comprender completamente los controles CIS antes de ejecutar estos scripts.
*   Adapte las configuraciones del script según sus necesidades específicas.
*   La salida del script puede variar dependiendo de la versión del sistema operativo y la configuración de seguridad.

**Consideraciones:**

*   Este README proporciona una visión general. Para información más detallada, consulte los archivos `Readme.md` dentro de cada directorio (`Json`, `Linux` y `Windows`).
*   Los scripts están diseñados para ser fáciles de usar, pero requieren un conocimiento básico de la línea de comandos y de Python.



# Material de Apoyo CIS Security

Este documento proporciona enlaces a recursos clave relacionados con la seguridad CIS, incluyendo documentación y descargas.

## 8.0 [https://learn.cisecurity.org/control-download](https://learn.cisecurity.org/)

*   **Descripción:**  Esta es la página principal para descargar los controles CIS.
*   **Idiomas Disponibles:** Inglés, Español y otros.
*   **Enlace Directo:** [https://learn.cisecurity.org/control-download](https://learn.cisecurity.org/control-download)

## 8.1 [https://learn.cisecurity.org/control-download-v8.1](https://learn.cisecurity.org/control-download-v8.1)

*   **Descripción:**  Versión específica (V8.1) de la descarga de los controles CIS.
*   **Idiomas Disponibles:** Inglés + Francés.
*   **Enlace Directo:** [https://learn.cisecurity.org/control-download-v8.1](https://learn.cisecurity.org/control-download-v8.1)

## Fuentes y herramientas de referencia

Sincronizar (contenido oficial) → informar (auditar) → sugerir (remediar):

*   **CIS Controls v8.1.2 (oficial):** [control-download](https://learn.cisecurity.org/control-download)
    — los JSON de `Json/` se validan contra el CSV de `documentos/`.
*   **HardeningKitty** ([scipag/HardeningKitty](https://github.com/scipag/HardeningKitty)):
    auditoría Windows por finding lists con severidad, score y reporte CSV.
    Cubre CIS *Benchmarks* (complementa, no reemplaza, los CIS *Controls*).
*   **Harden-Windows-Security** ([HotCakeX](https://github.com/HotCakeX/Harden-Windows-Security)):
    endurecimiento con métodos oficiales Microsoft; referencia de remediación.
*   **Lynis** ([cisofy.com/lynis](https://cisofy.com/lynis)): auditoría profunda
    Linux/Unix con hardening index; ideas de severidad y sugerencias.
*   **OpenSCAP + ComplianceAsCode** ([github.com/ComplianceAsCode/content](https://github.com/ComplianceAsCode/content)):
    contenido SSG versionado; evaluación formal con
    `oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_cis`
    y remediación vía Ansible/Bash generados. Ver sección OpenSCAP en `Linux/Readme.md`.
*   **Ansible CIS** (roles tipo ansible-lockdown): remediación como código tras auditar.
*   **Vagrant** ([vagrantup.com](https://www.vagrantup.com/downloads.html)):
    laboratorio para probar los scripts en varias distros sin riesgo.



## ⚠️ Aviso Legal / Legal Notice

Esta herramienta es unicamente para fines educativos y de auditoria de seguridad autorizada. El uso no autorizado contra sistemas sin el consentimiento explicito del propietario es ilegal. El usuario asume toda responsabilidad por el uso indebido.

This tool is for educational and authorized security auditing purposes only. Unauthorized use against systems without the owner's explicit consent is illegal. The user assumes all responsibility for misuse.
