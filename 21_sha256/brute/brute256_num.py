import hashlib
import argparse
import time

def fuerza_bruta_sha256(hash_objetivo):
    """Realiza un ataque de fuerza bruta para encontrar la cadena que genera un hash SHA-256 específico.

    Args:
        hash_objetivo: El hash a encontrar.

    Returns:
        La cadena encontrada si existe, o None si no se encuentra.
    """

    inicio = time.time()  # Registramos el tiempo inicial
    for i in range(10000):
        cadena = str(i).zfill(4)
        hash_calculado = hashlib.sha256(cadena.encode('utf-8')).hexdigest()
        if hash_calculado.lower() == hash_objetivo.lower():
            fin = time.time()  # Registramos el tiempo final
            tiempo_total = fin - inicio
            print(f"La cadena encontrada es: {cadena}")
            print(f"Tiempo de ejecución: {tiempo_total:.2f} segundos")
            return cadena
    return None

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Realiza un ataque de fuerza bruta sobre hashes SHA-256 de 4 dígitos')
    parser.add_argument('hash', help='El hash SHA-256 a buscar')
    args = parser.parse_args()

    resultado = fuerza_bruta_sha256(args.hash)

    if resultado is None:
        print("No se encontró ninguna cadena que coincida con el hash.")