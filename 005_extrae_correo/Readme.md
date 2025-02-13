 

# Extractor de Correos Electrónicos

Este script en Python 3 permite extraer correos electrónicos de un archivo de texto. El programa busca los correos electrónicos en el archivo, extrayendo la parte antes del símbolo ":" en cada línea. Además, valida que los correos sean válidos y ofrece opciones para eliminar duplicados y manejar archivos grandes de manera eficiente.

Los correos extraídos se guardan en un archivo de salida (por defecto, `Resultado.txt`), ordenados alfabéticamente.

## Características principales

- **Validación de correos electrónicos**: Solo se extraen correos con formato válido.
- **Eliminación de duplicados**: Puedes optar por eliminar correos duplicados del resultado final.
- **Manejo de archivos grandes**: El script procesa archivos línea por línea, lo que lo hace adecuado para archivos de gran tamaño.
- **Mensajes informativos**: Se informa sobre el número de correos válidos extraídos y cuántos fueron ignorados debido a errores de formato.
- **Compatibilidad multiplataforma**: Funciona en cualquier sistema con Python 3 instalado.

## Requisitos

- Python 3.x instalado en tu computadora.
- Un archivo de texto que contenga los correos electrónicos en el formato `email: valor`.

## Uso

1. **Instalación**:
   - Asegúrate de tener Python 3 instalado. Puedes verificarlo ejecutando el siguiente comando en tu terminal:
     ```bash
     python3 --version
     ```
   - Descarga el archivo `extract_emails.py` desde este repositorio.

2. **Preparación**:
   - Coloca el archivo que contiene los correos electrónicos en el mismo directorio que `extract_emails.py`.
   - Asegúrate de que los correos estén en el formato `email: valor` (por ejemplo, `usuario@example.com:12345`).

3. **Ejecución**:
   - Abre una terminal o línea de comandos y navega hasta el directorio donde se encuentra el archivo `extract_emails.py`.
   - Ejecuta el script con el siguiente comando:
     ```bash
     python3 extract_emails.py <ruta_del_archivo> [-o <archivo_salida>] [-d]
     ```
     - `<ruta_del_archivo>`: Ruta del archivo que contiene los correos electrónicos.
     - `-o <archivo_salida>` (opcional): Especifica el nombre del archivo de salida (por defecto es `Resultado.txt`).
     - `-d` (opcional): Activa la eliminación de correos duplicados.

4. **Ejemplo de uso**:
   - Para extraer correos sin eliminar duplicados:
     ```bash
     python3 extract_emails.py emails.txt
     ```
   - Para extraer correos y eliminar duplicados:
     ```bash
     python3 extract_emails.py emails.txt -d
     ```
   - Para especificar un archivo de salida personalizado:
     ```bash
     python3 extract_emails.py emails.txt -o correos_extraidos.txt -d
     ```

5. **Resultados**:
   - Después de que el programa termine de procesar el archivo, encontrarás un archivo de salida (por defecto, `Resultado.txt`) en el mismo directorio.
   - El archivo contendrá los correos electrónicos extraídos, ordenados alfabéticamente.
   - En la terminal, se mostrará información sobre el proceso, incluyendo:
     - Número de correos válidos extraídos.
     - Número de correos inválidos ignorados.

## Ejemplo de archivo de entrada

Supongamos que tienes un archivo llamado `emails.txt` con el siguiente contenido:

```
john.doe@example.com:12345
jane.doe@example.com:67890
invalid-email:password
john.doe@example.com:another_password
```

Al ejecutar el script con la opción `-d` para eliminar duplicados:

```bash
python3 extract_emails.py emails.txt -d
```

El archivo de salida (`Resultado.txt`) contendrá:

```
jane.doe@example.com
john.doe@example.com
```

En la terminal verás:

```
Procesando el archivo...
Estado: OK, proceso listo. Revisa Resultado.txt
Correos válidos extraídos: 2
Correos inválidos ignorados: 1
```

## Notas importantes

- Si el archivo de entrada no existe o no se puede leer, el programa mostrará un mensaje de error.
- Si el archivo de salida ya existe, será sobrescrito.
- Los correos inválidos (por ejemplo, aquellos que no cumplen con el formato estándar de correo electrónico) serán ignorados.
 
---

¡Disfruta extrayendo correos electrónicos de forma sencilla y eficiente con este script en Python 3! 🚀
