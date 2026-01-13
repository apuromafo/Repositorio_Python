-----

# 💻 Proyecto Validador de Sitios Vulnerables (OWASP VWAD)

## Descripción General

Este proyecto es una herramienta de **línea de comandos** diseñada para automatizar la validación de la lista de sitios web vulnerables de la colección **OWASP VWAD** (Vulnerable Web Application Database). Su principal función es descargar la lista oficial, verificar el estado de cada URL e identificar cuáles están en línea y cuáles están caídas. Esto te permite tener una base de datos actualizada para tus laboratorios de pruebas de penetración o de seguridad.

-----

## Características Principales

  * **Descarga Automática**: Obtiene automáticamente el archivo JSON de la colección OWASP VWAD desde su repositorio oficial en GitHub.
  * **Gestión de URLs Únicas**: El script detecta y elimina las URLs duplicadas antes de la validación para evitar peticiones redundantes.
  * **Reporte de Duplicados**: Genera un informe detallado que lista las URLs que se encontraron repetidas en la colección original.
  * **Validación Concurrente y Secuencial**: Ofrece dos modos de validación:
      * **Multihilo (por defecto)**: Utiliza múltiples hilos para validar las URLs de manera rápida y eficiente.
      * **Secuencial**: Procesa las URLs una por una, ideal para entornos sensibles o para un análisis más lento y controlado.
  * **Informe de Resultados**: Presenta los resultados en una tabla clara y organizada, separando las URLs que están "En línea" de las que están "Fuera de línea", y guarda la información completa en un archivo JSON.

-----

## Requisitos

  * **Python 3.x**
  * Biblioteca `requests`

Para instalar la biblioteca, ejecuta el siguiente comando:

```bash
pip install requests
```

-----

## Uso

Para ejecutar el script, navega hasta el directorio del proyecto y usa el comando `python Validador.py`.

### Modo por defecto (Multihilo)

La ejecución por defecto utiliza el modo multihilo, que es el más rápido.

```bash
python Validador.py
```

### Modo Secuencial

Si prefieres una validación más lenta y controlada, utiliza la opción `--single-thread` o su abreviatura `-s`.

```bash
python Validador.py -s
```

### Opciones Adicionales

  * **URL de entrada**: Puedes especificar una URL de archivo JSON diferente si deseas validar otra lista de sitios.
  * **Archivo de salida**: Puedes cambiar el nombre del archivo donde se guardarán los resultados.

<!-- end list -->

```bash
# Ejemplo con opciones personalizadas
python Validador.py https://mi-otra-lista.com/lista.json -o mi_validacion.json
```

-----
 