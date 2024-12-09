import argparse

def rot47_char(char, n):
    """Rotates a single character by n positions using ROT-47."""
    if 33 <= ord(char) <= 126:  # Solo caracteres imprimibles
        return chr((ord(char) - 33 + n) % 94 + 33)
    return char  # No modificar caracteres fuera del rango

def rot47(s, n):
    """Encode string s with a custom ROT-n based on ROT-47."""
    return ''.join(rot47_char(char, n) for char in s)

def brute_force_rot47(encoded_string, max_rotations):
    """Apply ROT-n encoding from 1 to max_rotations and return all results."""
    results = []
    
    for i in range(1, max_rotations + 1):  # Rotaciones de 1 a max_rotations
        rotated_string = rot47(encoded_string, i)  # Aplicar ROT-n usando ROT-47
        results.append(rotated_string)
    
    return results

def main():
    parser = argparse.ArgumentParser(description="Aplica ROT-n usando ROT-47 a una cadena.")
    parser.add_argument('-s', '--string', required=True, help='Cadena a codificar')
    parser.add_argument('-n', '--rotations', type=int, default=100, help='Número máximo de rotaciones (default: 100)')
    
    args = parser.parse_args()
    
    # Generar resultados de ROT-n
    rot_results = brute_force_rot47(args.string, args.rotations)

    # Generar resultados de ROT-47 (con la cadena original)
    rot47_results = brute_force_rot47(rot_results[0], args.rotations)

    # Comparar resultados ignorando mayúsculas y minúsculas
    matches = []
    for i in range(len(rot_results)):
        for j in range(len(rot47_results)):
            if rot_results[i].lower() == rot47_results[j].lower():
                matches.append((i + 1, rot_results[i], j + 1, rot47_results[j]))

    # Mostrar resultados
    print("ROT-n Results:")
    for attempt in range(len(rot_results)):
        print(f"Amount = {attempt + 1:>3}: {rot_results[attempt]}")

    print("\nMatches (ignoring case):")
    for match in matches:
        print(f"ROT-n Amount {match[0]}: '{match[1]}' matches ROT-47 Amount {match[2]}: '{match[3]}'")

if __name__ == "__main__":
    main()