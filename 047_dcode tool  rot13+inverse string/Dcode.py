#!/usr/bin/env python3
# Dcode.py - Decodificación con fuerza bruta de secuencias
#ejemplo  python .\Dcode.py -a .\demo.txt -fb
import argparse
import base64
import codecs
import os
import re
import math
from collections import Counter
from itertools import permutations

# Mapeo de números a nombres de algoritmos
ALGORITHM_NAMES = {
    '1': 'Invertir',
    '2': 'ROT13',
    '3': 'Base64'
}

def shannon_entropy(s):
    """Calcula la entropía de Shannon de una cadena."""
    if not s:
        return 0.0
    counts = Counter(s)
    probs = [n / len(s) for n in counts.values()]
    return -sum(p * math.log2(p) for p in probs if p > 0)
    
def reverse_string(s):
    """Invierte la cadena."""
    return s[::-1]

def rot13_transform(s):
    """Aplica ROT13."""
    return codecs.encode(s, 'rot13')

def base64_encode(s):
    """Codifica en Base64."""
    return base64.b64encode(s.encode('utf-8')).decode('utf-8')

def base64_decode(s):
    """Decodifica Base64 con padding automático."""
    try:
        padding_needed = len(s) % 4
        if padding_needed:
            s += '=' * (4 - padding_needed)
        return base64.b64decode(s).decode('utf-8')
    except (base64.binascii.Error, UnicodeDecodeError):
        return None  # Decodificación fallida

def apply_algorithm_sequence(text, algorithm_sequence, encode_mode=False):
    """
    Aplica secuencia de algoritmos: 1=Invertir, 2=ROT13, 3=Base64
    En decodificación, se aplica en orden inverso: secuencia[::-1]
    """
    algorithms = {
        '1': reverse_string,
        '2': rot13_transform,
        '3': base64_encode if encode_mode else base64_decode
    }

    sequence = algorithm_sequence if encode_mode else algorithm_sequence[::-1]
    processed_text = text

    for algo in sequence:
        if algo not in algorithms:
            return None
        func = algorithms[algo]
        try:
            result = func(processed_text)
            if result is None:
                return None
            processed_text = result
        except Exception:
            return None
    return processed_text

def is_encoded_string(s):
    """Detecta si parece Base64."""
    if len(s) < 10:
        return False
    if not re.fullmatch(r'[A-Za-z0-9+/=]+', s):
        return False
    padded_len = len(s) + (4 - len(s) % 4) if len(s) % 4 != 0 else len(s)
    return 12 <= padded_len <= 1000

def generate_all_sequences():
    """Genera todas las combinaciones únicas de 1,2,3 de longitud 1 a 3."""
    algorithms = ['1', '2', '3']
    sequences = []
    for r in range(1, 4):
        for perm in permutations(algorithms, r):
            sequences.append(''.join(perm))
    return sequences

def get_sequence_description(sequence):
    """
    Convierte una secuencia de algoritmos (p. ej., '321') en una descripción clara con números.
    """
    parts = []
    for algo_num in sequence:
        name = ALGORITHM_NAMES.get(algo_num, 'Desconocido')
        parts.append(f"{name} ({algo_num})")
    return ' → '.join(parts)

def is_plausible_text(s):
    """
    Heurística mejorada: combina palabras clave, legibilidad y entropía de Shannon.
    """
    # 1. ¿Es imprimible?
    if not s.isprintable():
        return False
    if re.search(r'[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f-\x9f]', s):
        return False

    # 2. Densidad de letras
    letters = sum(c.isalpha() for c in s)
    if len(s) > 10 and letters < len(s) * 0.3:
        return False

    # 3. Entropía de Shannon
    entropy = shannon_entropy(s)
    if entropy > 4.7:  # Umbral: demasiado aleatorio → basura
        return False

    # 4. Palabras clave (español, inglés, CTF, redes, emojis)
    keywords = [
        # === Flags y formatos ===
        'flag', 'ctf', 'secret', 'key', 'token', 'pass', 'password', 'passwd',
        'clave', 'contraseña', 'pista', 'solution', 'solve', 'found', 'crack',
        'decoded', 'encoded', 'crypt', 'cipher', 'hash', 'b64', 'base64',
        'rot', 'rot13', 'aes', 'rsa', 'md5', 'sha', 'xor', 'otp',

        # === Formatos de flag ===
        'flag{', 'ctf{', 'flag_', 'ctf_', 'key{', 'token{', '{', '}', '()',

        # === Mensajes comunes ===
        'si', 'yes', 'ok', 'correcto', 'valido', 'verdadero', 'exito', 'éxito',
        'bien', 'genial', 'perfecto', 'excelente', 'mejor', 'like', 'follow',
        'comparte', 'gracias', 'saludo', 'saludos', 'hola', 'hello', 'hi',
        'congratulations', 'congrats', 'winner', 'ganaste', 'desafío', 'challenge',
        'resuelto', 'resuelva', 'resolver', 'intento', 'intentos', 'final',
        'completo', 'completado', 'terminado', 'acabado', 'listo', 'done',

        # === Firmas y nombres ===
        'lockdown', 'lockdown0x0', 'apuromafo', 'pucv', 'ux', 'iot', 'ot',
        'cybersecurity', 'infosec', 'hacking', 'crack', 'cracker', 'hacker',

        # === Emojis comunes ===
        '💬', '🎉', '🔥', '✅', '🎯', '🚀', '🏆',
    ]

    lower_s = s.lower()
    has_keyword = any(kw.lower() in lower_s for kw in keywords)

    # 5. Decisión final: baja entropía + palabras clave o suficientes letras
    return has_keyword or (entropy < 4.5 and letters > 5)

def main():
    parser = argparse.ArgumentParser(
        description="Dcode.py - Fuerza bruta de secuencias de decodificación.",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # Permitimos -s, -a y -fb en cualquier combinación (validaremos después)
    parser.add_argument("-s", "--string", help="Procesa una cadena directamente.")
    parser.add_argument("-a", "--archivo", help="Procesa cada línea de un archivo.")
    parser.add_argument("-fb", "--fuerzabruta", action="store_true",
                       help="Modo fuerza bruta: prueba todas las secuencias posibles.")

    parser.add_argument("-e", "--encode", action="store_true", help="Modo codificación.")
    parser.add_argument("-alg", "--algoritmos", default="321", metavar="SEQ",
                        help="Secuencia: 1=Invertir, 2=ROT13, 3=Base64. Por defecto: 321")

    args = parser.parse_args()

    # Validación lógica
    if args.encode and args.fuerzabruta:
        print("Error: -fb solo funciona en modo decodificación.")
        return
    if not args.fuerzabruta and not args.string and not args.archivo:
        print("Error: Debes usar -s, -a, o -fb con -s/-a.")
        return

    all_sequences = generate_all_sequences()

    # === Modo: Fuerza bruta sobre cadena única ===
    if args.fuerzabruta and args.string:
        print(f"\n🔍 [Fuerza Bruta] Cadena: {args.string}")
        found = False
        for seq in all_sequences:
            result = apply_algorithm_sequence(args.string, seq, encode_mode=False)
            if result is not None and is_plausible_text(result):
                entropy = shannon_entropy(result)
                description = get_sequence_description(seq)
                print(f"    ✅ [{description}] → Entropía: {entropy:.3f} | {repr(result)}")
                found = True
        if not found:
            print(f"    ❌ Ninguna secuencia produjo un resultado válido.")
        
        print("\n---")
        print("💡 Nota sobre el modo de Fuerza Bruta:")
        print("La secuencia de algoritmos de los resultados válidos (ej. 'Invertir (1) → ROT13 (2) → Base64 (3)')")
        print("muestra el orden de decodificación. Puedes usar esta secuencia numérica (ej. '123')")
        print("directamente con el parámetro '-alg' para decodificar otras cadenas de manera rápida.")
        print("Ejemplo: python Dcode.py -s 'cadena_codificada' -alg 123")
        print("---\n")
        return

    # === Modo: Fuerza bruta sobre archivo ===
    if args.fuerzabruta and args.archivo:
        if not os.path.exists(args.archivo):
            print(f"Error: Archivo '{args.archivo}' no encontrado.")
            return

        with open(args.archivo, 'r', encoding='utf-8-sig') as file:
            for line_num, line in enumerate(file, 1):
                stripped = line.strip()
                if not stripped:
                    continue
                if stripped.startswith('#'):
                    print(f"Línea {line_num} (comentario): {stripped}")
                    continue
                if not is_encoded_string(stripped):
                    continue

                print(f"\n🔍 [Fuerza Bruta] Línea {line_num}: {stripped}")
                found = False
                for seq in all_sequences:
                    result = apply_algorithm_sequence(stripped, seq, encode_mode=False)
                    if result is not None and is_plausible_text(result):
                        entropy = shannon_entropy(result)
                        description = get_sequence_description(seq)
                        print(f"    ✅ [{description}] → Entropía: {entropy:.3f} | {repr(result)}")
                        found = True
                if not found:
                    print(f"    ❌ Ninguna secuencia produjo un resultado válido.")
        
        print("\n---")
        print("💡 Nota sobre el modo de Fuerza Bruta:")
        print("La secuencia de algoritmos de los resultados válidos (ej. 'Invertir (1) → ROT13 (2) → Base64 (3)')")
        print("muestra el orden de decodificación. Puedes usar esta secuencia numérica (ej. '123')")
        print("directamente con el parámetro '-alg' para decodificar otras cadenas de manera rápida.")
        print("Ejemplo: python Dcode.py -a 'archivo.txt' -alg 123")
        print("---\n")
        return

    # === Modo: cadena única normal ===
    if args.string:
        try:
            description = get_sequence_description(args.algoritmos)
            print(f"Aplicando secuencia: {description}")
            result = apply_algorithm_sequence(args.string, args.algoritmos, args.encode)
            if result is not None:
                print(f"Resultado: {result}")
            else:
                print("Error: No se pudo procesar la cadena.")
        except Exception as e:
            print(f"Error: {e}")
        
        print("\n---")
        print("💡 Nota sobre el modo de Algoritmo Directo:")
        print("Si no conoces la secuencia de decodificación, puedes usar la opción de fuerza bruta (-fb)")
        print("para encontrarla automáticamente. Luego, puedes usar la secuencia numérica (ej. '123')")
        print("con el parámetro '-alg' para un uso más rápido.")
        print("---\n")
        return

    # === Modo: archivo normal ===
    if args.archivo:
        if not os.path.exists(args.archivo):
            print(f"Error: Archivo '{args.archivo}' no encontrado.")
            return

        description = get_sequence_description(args.algoritmos)
        print(f"Aplicando la secuencia de decodificación: {description}")

        with open(args.archivo, 'r', encoding='utf-8-sig') as file:
            for line_num, line in enumerate(file, 1):
                stripped = line.strip()
                if not stripped:
                    continue
                if stripped.startswith('#'):
                    print(f"Línea {line_num}: {stripped}")
                    continue

                if args.encode:
                    try:
                        encoded = apply_algorithm_sequence(stripped, args.algoritmos, True)
                        if encoded is not None:
                            print(f"Línea {line_num} (Codificado): {encoded}")
                        else:
                            print(f"Línea {line_num}: Error al codificar.")
                    except Exception as e:
                        print(f"Línea {line_num}: Error: {e}")
                else:
                    if is_encoded_string(stripped):
                        result = apply_algorithm_sequence(stripped, args.algoritmos, False)
                        if result is not None:
                            print(f"Línea {line_num} (Decodificado): {result}")
                        else:
                            print(f"Línea {line_num}: Error al decodificar.")
                    else:
                        print(f"Línea {line_num}: {stripped}")
        
        print("\n---")
        print("💡 Nota sobre el modo de Algoritmo Directo:")
        print("Si no conoces la secuencia de decodificación, puedes usar la opción de fuerza bruta (-fb)")
        print("para encontrarla automáticamente. Luego, puedes usar la secuencia numérica (ej. '123')")
        print("con el parámetro '-alg' para un uso más rápido.")
        print("---\n")
        return

if __name__ == "__main__":
    main()