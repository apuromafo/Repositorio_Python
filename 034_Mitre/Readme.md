# Herramienta CLI para la Matriz MITRE ATT&CK

Esta herramienta proporciona una interfaz de línea de comandos (CLI) para navegar y buscar información dentro de la matriz MITRE ATT&CK.  Permite listar grupos APT, buscar técnicas por ID o nombre, y mostrar detalles sobre tácticas.

## Instalación

[Instrucciones de instalación específicas aquí -  Por ejemplo, cómo instalar dependencias, etc.]

## Uso

La herramienta se ejecuta desde la línea de comandos utilizando el siguiente formato:

```bash
nombre_del_script.py [opciones]
```

**Subcomandos:**

*   `apt-list`: Listar todos los grupos APT.
    ```bash
    nombre_del_script.py apt-list
    ```

*   `apt`: Mostrar información de un grupo APT específico.
    ```bash
    nombre_del_script.py apt --nombre "Nombre del Grupo APT"
    ```

*   `tid`: Buscar una técnica por su ID (ej., T1055).
    ```bash
    nombre_del_script.py tid --id "T1055"
    ```

*   `tn`: Buscar una técnica por su nombre.
    ```bash
    nombre_del_script.py tn --nombre "Nombre de la Técnica"
    ```

*   `tactic`: Mostrar información sobre una táctica específica.
    ```bash
    nombre_del_script.py tactic --nombre "Nombre de la Táctica"
    ```

**Opciones:**

*   `--update`:  Forzar la descarga del archivo JSON de MITRE ATT&CK. Esto es útil si tienes una versión desactualizada y quieres obtener la última.

## Argumentos

| Argumento        | Descripción                               | Ejemplo             |
|------------------|-------------------------------------------|---------------------|
| `nombre`         | Nombre o alias del grupo APT (para comandos `apt`) | "Grupo-1"          |
| `id`             | ID de la técnica (para comando `tid`)       | "T1055"             |
| `nombre`        | Nombre de la técnica (para comando `tn`)      | "Evaluar Vulnerabilidades" |
| `nombre`         | Nombre de la táctica (para comando `tactic`)  | "Initial Access"    |

## Dependencias

*   [Lista de dependencias y versiones requeridas aquí - por ejemplo, Python 3.x, argparse, etc.]

## Autor

Mitre (desarrollo el json)
  

## Licencia

[Especifica la licencia bajo la cual se distribuye la herramienta (ej., MIT License)]
 