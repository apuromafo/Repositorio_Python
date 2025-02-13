# Crack y Generación de Hashes SHA-256

Este repositorio contiene herramientas en Python para **generar hashes SHA-256** y realizar **ataques de fuerza bruta** (crack) sobre hashes SHA-256. Los scripts son útiles para fines educativos y de aprendizaje sobre criptografía básica.

## Contenido del Repositorio

1. **Generador de SHA-256**:
   - Genera hashes SHA-256 a partir de texto proporcionado por el usuario.
   - Permite guardar los resultados en un archivo.

2. **Crack de SHA-256 Numérico**:
   - Realiza un ataque de fuerza bruta sobre hashes SHA-256 generados a partir de números de 4 dígitos.
   - Guarda los resultados en un archivo si se desea.

3. **Crack de SHA-256 con Diccionario**:
   - Utiliza un archivo de diccionario para intentar encontrar la cadena original que genera un hash SHA-256 específico.
   - Compatible con caracteres especiales como tildes y eñes.

---

## Requisitos

- Python 3.x instalado en tu sistema.
- Bibliotecas estándar de Python (`hashlib`, `argparse`, etc.).

---

## Scripts Disponibles

### 1. Generador de SHA-256

#### Descripción
Este script genera hashes SHA-256 a partir de texto proporcionado por el usuario. Ofrece opciones para guardar los resultados en un archivo.

#### Uso
```bash
python generador_sha256.py -t "texto_a_hashear" -f resultados.txt
```

- `-t` o `--texto`: Texto para generar el hash.
- `-f` o `--file`: (Opcional) Nombre del archivo donde guardar los resultados.

#### Ejemplo
```bash
python generador_sha256.py -t "Hola Mundo" -f hash_resultados.txt
```

---

### 2. Crack de SHA-256 Numérico

#### Descripción
Este script realiza un ataque de fuerza bruta sobre hashes SHA-256 generados a partir de números de 4 dígitos (0000-9999).

#### Uso
```bash
python brute256_num.py -hsh "hash_objetivo" -f resultados.txt
```

- `-hsh` o `--hash`: Hash SHA-256 objetivo.
- `-f` o `--file`: (Opcional) Nombre del archivo donde guardar los resultados.

#### Ejemplo
```bash
python brute256_num.py -hsh "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" -f resultados.txt
```

---

### 3. Crack de SHA-256 con Diccionario

#### Descripción
Este script utiliza un archivo de diccionario para intentar encontrar la cadena original que genera un hash SHA-256 específico. Es compatible con caracteres especiales como tildes y eñes.

#### Uso
```bash
python brute256_diccionario.py -hsh "hash_objetivo" -dic diccionario.txt -f resultados.txt
```

- `-hsh` o `--hash`: Hash SHA-256 objetivo.
- `-dic` o `--diccionario`: Ruta al archivo de diccionario.
- `-f` o `--file`: (Opcional) Nombre del archivo donde guardar los resultados.

#### Ejemplo
```bash
python brute256_diccionario.py -hsh "b221d9dbb083a7f33428d7c2a3c3198ae925614d70210e28716ccaa7cd4ddb79" -dic diccionario.txt -f resultados.txt
```

---

## Cómo Crear un Archivo de Diccionario

Puedes crear un archivo de diccionario personalizado con palabras separadas por líneas. Aquí hay un ejemplo básico:

```txt
hola
mundo
python
programacion
clave
secreto
contraseña
cifrado
árbol
camión
niño
café
mañana
españa
pequeño
grande
rápido
lento
fácil
difícil
123456
abcdef
abc123
admin
password
```

Guarda este contenido en un archivo llamado `diccionario.txt` y úsalo con el script de crack de diccionario.

---

## Notas Importantes

- Estos scripts están diseñados para **fines educativos**. No los uses para actividades malintencionadas o no autorizadas.
- El rendimiento del crack de diccionario depende del tamaño del archivo de diccionario. Archivos más grandes pueden requerir más tiempo de procesamiento.

---

## Autor

- **Autor**: Apuromafo  
- **Versión**: 0.0.2  
- **Fecha**: 08.12.2024  
 