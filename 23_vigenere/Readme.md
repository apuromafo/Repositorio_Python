 
# Vigenère Cipher Tool

[![Python Version](https://img.shields.io/badge/python-3.x-blue)](https://www.python.org/)

Una herramienta en Python para cifrar, descifrar y realizar ataques de fuerza bruta sobre texto utilizando el cifrado Vigenère.

## Descripción

Este script permite cifrar y descifrar texto utilizando el cifrado Vigenère. Además, incluye una función de fuerza bruta que utiliza un diccionario de posibles claves para intentar descifrar un texto cifrado.

### Autor
- **Apuromafo**
- Versión: 0.0.5
- Fecha: 17.12.2024

## Instalación

1. Clona este repositorio:
   ```bash
   git clone https://github.com/tu_usuario/tu_repositorio.git
   ```
2. Navega al directorio del proyecto:
   ```bash
   cd tu_repositorio
   ```
3. Asegúrate de tener Python instalado (versión 3.x):
   ```bash
   python --version
   ```

## Uso

### Cifrar texto
Para cifrar un texto, utiliza el siguiente comando:
```bash
python tu_script.py -s "texto a cifrar" -k "clave"
```

### Descifrar texto
Para descifrar un texto, utiliza el siguiente comando:
```bash
python tu_script.py -s "texto a descifrar" -k "clave" -d
```

### Fuerza bruta sobre la clave
Para realizar un ataque de fuerza bruta utilizando un diccionario de claves, utiliza el siguiente comando:
```bash
python tu_script.py -s "texto a descifrar" -f -dic diccionario.txt
```

> **Nota:** Asegúrate de proporcionar un archivo de diccionario válido (`diccionario.txt`) con una lista de posibles claves.

## Ejemplos

### Ejemplo 1: Cifrar un texto
```bash
python tu_script.py -s "hola mundo" -k "secreto"
```
**Salida:**
```
Texto ingresado: hola mundo
Clave ingresada: secreto
Texto cifrado: zszg qynto
```

### Ejemplo 2: Descifrar un texto
```bash
python tu_script.py -s "zszg qynto" -k "secreto" -d
```
**Salida:**
```
Texto ingresado: zszg qynto
Clave ingresada: secreto
Texto decodificado: hola mundo
```

### Ejemplo 3: Fuerza bruta
Supongamos que tienes un archivo `diccionario.txt` con las siguientes claves:
```
clave1
clave2
secreto
clave3
```

Ejecuta el siguiente comando:
```bash
python tu_script.py -s "zszg qynto" -f -dic diccionario.txt
```
**Salida:**
```
Probando clave: clave1 -> Texto decodificado: ...
Probando clave: clave2 -> Texto decodificado: ...
Probando clave: secreto -> Texto decodificado: hola mundo
...
```

## Otras herramientas útiles

- [Identificar cifrados](https://www.dcode.fr/cipher-identifier): Herramienta para identificar cifrados.
- [Decodificar cifrados](https://www.boxentriq.com/code-breaking/vigenere-cipher): Decodificador de cifrados Vigenère.
- [CyberChef](https://cyberchef.io/): Herramienta versátil para manipular datos.
- [Cryptii](https://cryptii.com/pipes/vigenere-cipher): Conversor y cifrador en línea.

## Contribuciones

Si deseas contribuir a este proyecto, por favor abre un issue o envía un pull request. ¡Todas las contribuciones son bienvenidas!

## Licencia

Este proyecto está bajo la licencia [MIT License](LICENSE).

---
 