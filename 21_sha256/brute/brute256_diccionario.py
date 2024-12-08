import hashlib
import argparse
import time

def fuerza_bruta_diccionario(hash_objetivo, archivo_diccionario):
    """Realiza un ataque usando un diccionario para encontrar la cadena que genera un hash SHA-256 específico.

    Args:
        hash_objetivo: El hash a encontrar.
        archivo_diccionario: Ruta al archivo que contiene las palabras.

    Returns:
        La cadena encontrada si existe, o None si no se encuentra.
    """
    
    inicio = time.time()  # Registramos el tiempo inicial

    # Cargar el diccionario
    with open(archivo_diccionario, 'r', encoding='utf-8') as f:
        for linea in f:
            cadena = linea.strip()  # Eliminamos espacios en blanco
            hash_calculado = hashlib.sha256(cadena.encode('utf-8')).hexdigest()
            if hash_calculado.lower() == hash_objetivo.lower():
                fin = time.time()  # Registramos el tiempo final
                tiempo_total = fin - inicio
                print(f"La cadena encontrada es: {cadena}")
                print(f"Tiempo de ejecución: {tiempo_total:.2f} segundos")
                return cadena
    return None

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Realiza un ataque usando un diccionario sobre hashes SHA-256')
    parser.add_argument('hash', help='El hash SHA-256 a buscar')
    parser.add_argument('diccionario', help='Ruta al archivo de diccionario')
    args = parser.parse_args()

    resultado = fuerza_bruta_diccionario(args.hash, args.diccionario)

    if resultado is None:
        print("No se encontró ninguna cadena que coincida con el hash.")