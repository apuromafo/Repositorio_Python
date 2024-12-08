import hashlib
import argparse

def calcular_sha256(texto):
  """Calcula el hash SHA-256 de un texto dado.

  Args:
    texto: El texto a convertir en hash.

  Returns:
    Una cadena de texto que representa el hash SHA-256.
  """

  # Codificamos el texto a bytes (necesario para el cálculo del hash)
  texto_bytes = texto.encode('utf-8')

  # Creamos un objeto SHA-256 y actualizamos con los bytes
  sha256 = hashlib.sha256()
  sha256.update(texto_bytes)

  # Obtenemos el hash en formato hexadecimal
  hash_hex = sha256.hexdigest()

  return hash_hex

if __name__ == "__main__":
  parser = argparse.ArgumentParser(description='Calcula el hash SHA-256 de un texto.')
  parser.add_argument('texto', help='El texto a convertir en hash.')
  args = parser.parse_args()

  hash_resultante = calcular_sha256(args.texto)
  print(hash_resultante)