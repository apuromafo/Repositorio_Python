# Validador de Strings

## Descripción

Esta herramienta está diseñada para validar y extraer cadenas legibles de texto de archivos o directorios. Busca secuencias de caracteres que cumplan con un cierto largo mínimo (por defecto, 6 caracteres) y las guarda en un archivo de log con la fecha y hora actual.

### Características principales:
- **Validación de cadenas**: Extrae cadenas legibles de texto que contienen caracteres alfanuméricos y símbolos comunes.
- **Compatibilidad con archivos y directorios**: Puede procesar un archivo individual o todos los archivos dentro de un directorio y sus subdirectorios.
- **Registro detallado**: Los resultados se guardan en un archivo de log con un nombre único basado en la fecha y hora de ejecución.

---

## Autoría

- **Autor**: Apuromafo  
- **Versión**: 0.0.1  
- **Fecha de creación**: 23.01.2025  

---

## Requisitos

Para ejecutar este script, necesitarás lo siguiente:

- **Python 3.x**: El script está escrito en Python y requiere una versión compatible de Python 3.
- **Permisos de lectura**: Asegúrate de tener permisos de lectura para los archivos o directorios que deseas procesar.

---

## Uso

### Sintaxis

```bash
python3 validador_strings.py <archivo_o_directorio>
```

### Ejemplos

1. **Procesar un archivo específico**:
   ```bash
   python3 validador_strings.py ejemplo.txt
   ```
   Esto procesará el archivo `ejemplo.txt` y generará un archivo de log con las cadenas encontradas.

2. **Procesar un directorio completo**:
   ```bash
   python3 validador_strings.py /ruta/al/directorio
   ```
   Esto buscará y procesará todos los archivos dentro del directorio especificado y sus subdirectorios.

### Salida

El script genera un archivo de log con un nombre único en el formato `log__MM_DD_YYYY, HH_MM_SS.txt`. Este archivo contendrá:
- Las cadenas legibles encontradas en cada archivo procesado.
- Mensajes de error si ocurre algún problema durante el procesamiento.

---

## Funcionamiento interno

### Lógica principal
1. **Extracción de cadenas**:
   - El script lee archivos en modo binario y decodifica su contenido como UTF-8.
   - Identifica secuencias de caracteres legibles que cumplan con el largo mínimo especificado (por defecto, 6 caracteres).

2. **Procesamiento de archivos y directorios**:
   - Si se proporciona un archivo, se procesa directamente.
   - Si se proporciona un directorio, se recorre recursivamente para procesar todos los archivos contenidos.

3. **Registro de resultados**:
   - Los resultados se escriben en un archivo de log con un nombre único basado en la fecha y hora de ejecución.

---

## Personalización

Puedes modificar el comportamiento del script ajustando los siguientes parámetros en el código:

- **Largo mínimo de las cadenas**:
  Cambia el valor de la variable `largo` para definir el largo mínimo de las cadenas a extraer. Por defecto, está configurado en `6`.

  ```python
  largo = 6
  ```

- **Caracteres permitidos**:
  Modifica la lista de caracteres en la función `strings_util` si deseas incluir o excluir ciertos símbolos.

---

## Contribuciones

Si deseas contribuir a este proyecto, ¡eres bienvenido! Puedes hacerlo de las siguientes maneras:
- Reportar problemas o errores abriendo un issue.
- Proponer mejoras o nuevas características mediante pull requests.

---

## Licencia

Este proyecto está bajo la licencia [MIT](LICENSE). Consulta el archivo `LICENSE` para más detalles.

---
 