
# 🐍 Script para Resolver Enlaces de Cursoteca Plus

Este script en Python está diseñado para extraer y resolver los enlaces de cursos de Udemy que se encuentran en el sitio web de Cursoteca Plus. La herramienta puede funcionar de varias maneras: a través de un feed RSS, un rango de páginas, un archivo de texto o procesando una URL individual.

## 🚀 Uso

Puedes ejecutar el script en modo interactivo sin argumentos o pasarle opciones por la línea de comandos.

### Modo Interactivo

Simplemente ejecuta el script sin ningún argumento:

```
python cursoteca.py

```

Esto te presentará un menú interactivo con las siguientes opciones:

1. Procesar el feed RSS principal.
    
2. Procesar un rango de páginas numeradas.
    
3. Procesar una lista de enlaces desde un archivo de texto.
    
4. Procesar una URL individual.
    
5. Salir del programa.
    

### Modo de Línea de Comandos

El script también acepta argumentos para realizar tareas específicas directamente.

- **Procesar una URL única:**
    
    ```
    python cursoteca.py -u "https://cupones.cursotecaplus.com/curso/nombre-del-curso/"
    
    ```
    
- **Procesar enlaces desde un archivo:**
    
    ```
    python cursoteca.py -f mis_enlaces.txt
    
    ```
    
- **Procesar el feed principal:**
    
    ```
    python cursoteca.py -a
    
    ```
    
- **Procesar un rango de páginas:**
    
    ```
    python cursoteca.py -p 1 10
    
    ```
    
    (Esto procesará desde la página 1 hasta la 10)
    

## ⚙️ Dependencias

El script requiere las siguientes librerías de Python. Puedes instalarlas con pip:

```
pip install requests beautifulsoup4

```

## 📝 Salida

El script guardará los enlaces de Udemy resueltos y limpios en un archivo de texto con un nombre que incluye la fecha y hora, por ejemplo: `links_udemy_limpios_feed_2025-08-11_10-30-00.txt`.

## ⚠️ Aviso Legal / Legal Notice

Esta herramienta es unicamente para fines educativos y de auditoria de seguridad autorizada. El uso no autorizado contra sistemas sin el consentimiento explicito del propietario es ilegal. El usuario asume toda responsabilidad por el uso indebido.

This tool is for educational and authorized security auditing purposes only. Unauthorized use against systems without the owner's explicit consent is illegal. The user assumes all responsibility for misuse.
