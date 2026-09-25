# Changelog — 036_cis

## 2026-09-25 — Controles v8.1.2 sincronizados + READMEs
- Verificación contra CSV oficial (`documentos/CIS_Controls_Version_8.1.2___March_2025.csv`):
  18 controles y 153 salvaguardas con IDs coincidentes en ES y EN.
- EN: agregada `title` a las 153 salvaguardas (calza 100% con el CSV).
- ES: reparado mojibake (`Documentaci├│n` → `Documentación`, 0 restos),
  agregadas 153 `title` traducidas y traducidos 7 títulos de control (3, 4, 5, 6, 9, 13, 18).
- `Leer.py`: muestra el título de cada salvaguarda.
- READMEs (raíz, Json, Windows, Linux): comandos reales, estructura,
  versión v8.1.2 y conteos 18/153.

## 2026-09-25 — Endurecimiento de auditorías Win/Linux
- `Windows/win.py`:
  - `wmi`/`psutil` opcionales con degradación avisada (antes `import wmi`
    tumbaba todo el script); aliases seguros para `except wmi.*`.
  - Flags `--no-pause` (no interactivo), `--no-color`, `--json RUTA`
    (exporta fecha/equipo/usuario/recomendaciones).
  - Timeout 60 s en comandos externos; helper `_run_text()` que decodifica
    OEM (cp850) para `net accounts`/`auditpol`/PowerShell.
  - Nueva sección Línea Base Segura: UAC, LSA (RunAsPPL), RDP+NLA,
    auto-logon/DefaultPassword, firma SMB, Autorun, LLMNR, último parche,
    política `net accounts`, resumen `auditpol`. Verificado en vivo.
  - Recomendaciones sin duplicados.
- `Linux/linux.py`:
  - Timeout 30 s en `run_command()`; `shlex.quote()` en interpolaciones shell.
  - Flag `--json RUTA` (vuelca `SECURITY_FINDINGS`).
  - Nuevos chequeos (estilo reglas SCAP): SSH (`sshd_config`), sysctl
    (ASLR, kptr, dmesg, ptrace, ip_forward, rp_filter), SUID/SGID inesperados,
    `login.defs`, NOPASSWD en sudoers, pwquality/faillock, updates
    desatendidas, core dumps. 24 claves nuevas en `RECOMMENDATIONS_MAP`
    con comando de remediación.
- Ambos scripts: preámbulo de buenas prácticas + disclaimer + autores antes
  de auditar (solo lectura, privilegios mínimos, probar en VM primero).
