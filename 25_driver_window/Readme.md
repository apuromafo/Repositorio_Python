 

# Driver Blocklist Checker

![Python Version](https://img.shields.io/badge/python-3.7%20%7C%203.8%20%7C%203.9%20%7C%203.10-blue)
![License](https://img.shields.io/badge/license-MIT-green)

## Autor

- **Nombre:** Apuromafo
- **Versión:** 0.0.1
- **Fecha:** 22.01.2025

## Descripción

**Driver Blocklist Checker** es una herramienta diseñada para validar drivers vulnerables en sistemas Windows. Compara la lista de drivers bloqueados por Microsoft con la lista de drivers conocidos como vulnerables en [LOLDrivers](https://www.loldrivers.io/).

Esta herramienta permite identificar qué drivers vulnerables no están siendo bloqueados por Microsoft y cuáles ya están incluidos en su lista de bloqueo.

### Características principales:
- **Comparación de listas:** Compara la lista de drivers vulnerables de LOLDrivers con la lista oficial de Microsoft.
- **Modo verbose:** Proporciona detalles adicionales sobre los drivers que están o no bloqueados.
- **Soporte para diferentes políticas:** Permite seleccionar entre las políticas `Enforced` y `Audit`.

## Requisitos

Antes de ejecutar este script, asegúrate de tener instaladas las siguientes dependencias:

- Python 3.7+
- Las siguientes bibliotecas de Python:
  - `requests`
  - `xmltodict`
  - `beautifulsoup4`

Puedes instalar las dependencias necesarias ejecutando el siguiente comando:

```bash
pip install requests xmltodict beautifulsoup4
```

## Uso

### Ejecución básica

Para ejecutar el script con la configuración predeterminada (política `Enforced`):

```bash
python driver_blocklist_checker.py
```

### Modo verbose

Si deseas ver más detalles sobre los drivers que están o no bloqueados, puedes usar la opción `-v` o `--verbose`:

```bash
python driver_blocklist_checker.py -v
```

### Seleccionar política

Puedes elegir entre las políticas `Enforced` (predeterminada) o `Audit` usando la opción `-t` o `--target`:

```bash
python driver_blocklist_checker.py -t Audit
```

### Salida esperada

El script mostrará:
- Cuántos drivers vulnerables no están bloqueados por Microsoft.
- Cuántos drivers vulnerables ya están bloqueados por Microsoft.
- En modo verbose, también mostrará detalles sobre cada driver.

## Licencia

Este proyecto está bajo la **Licencia MIT**. Consulta el archivo [LICENSE](LICENSE) para más detalles.

--- 

---
 