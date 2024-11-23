import random
import string
import argparse
import math
import hashlib
from datetime import datetime

# Clasificación de Contraseñas por Entropía
# 1. Muy Débil (Very Weak): 0 - 40 bits
# 2. Débil (Weak): 41 - 60 bits
# 3. Moderada (Moderate): 61 - 80 bits
# 4. Fuerte (Strong): 81 - 100 bits
# 5. Muy Fuerte (Very Strong): 101 bits o más

# Define códigos de color (valores RGB)
colores = {
    "rojo": (255, 0, 0),
    "naranja": (255, 165, 0),
    "amarillo": (255, 255, 0),
    "verde": (0, 255, 0),
    "azul": (0, 0, 255),
    "morado": (128, 0, 128),
}

# Función para interpolar valores de color según la posición
def interpolar_color(color_inicio, color_fin, posicion):
    r_inicio, g_inicio, b_inicio = color_inicio
    r_fin, g_fin, b_fin = color_fin

    r_nuevo = int(r_inicio + (posicion * (r_fin - r_inicio)))
    g_nuevo = int(g_inicio + (posicion * (g_fin - g_inicio)))
    b_nuevo = int(b_inicio + (posicion * (b_fin - b_inicio)))

    return (r_nuevo, g_nuevo, b_nuevo)

# Función para generar código ANSI de escape a partir de valores RGB
def rgb_a_codigo_ansi(rgb):
    r, g, b = rgb
    return f"\033[38;2;{r};{g};{b}m"

# Generar un degradado de colores
def generar_degradado_colores(color_inicio, color_fin, pasos):
    degradado = []
    for i in range(pasos + 1):
        posicion = i / pasos
        color = interpolar_color(color_inicio, color_fin, posicion)
        codigo_ansi = rgb_a_codigo_ansi(color)
        degradado.append(codigo_ansi)

    return degradado

# Texto ASCII art #https://patorjk.com/software/taag/#p=display&f=Alligator2&t=Generador%20%0AClaves
texto = """
 ::::::::  :::::::::: ::::    ::: :::::::::: :::::::::      :::     :::::::::   ::::::::  :::::::::       
:+:    :+: :+:        :+:+:   :+: :+:        :+:    :+:   :+: :+:   :+:    :+: :+:    :+: :+:    :+:      
+:+        +:+        :+:+:+  +:+ +:+        +:+    +:+  +:+   +:+  +:+    +:+ +:+    +:+ +:+    +:+      
:#:        +#++:++#   +#+ +:+ +#+ +#++:++#   +#++:++#:  +#++:++#++: +#+    +:+ +#+    +:+ +#++:++#:       
+#+   +#+# +#+        +#+  +#+#+# +#+        +#+    +#+ +#+     +#+ +#+    +#+ +#+    +#+ +#+    +#+      
#+#    #+# #+#        #+#   #+#+# #+#        #+#    #+# #+#     #+# #+#    #+# #+#    #+# #+#    #+#      
 ########  ########## ###    #### ########## ###    ### ###     ### #########   ########  ###    ###      
 ::::::::  :::            :::     :::     ::: :::::::::: ::::::::                                         
:+:    :+: :+:          :+: :+:   :+:     :+: :+:       :+:    :+:                                        
+:+        +:+         +:+   +:+  +:+     +:+ +:+       +:+                                               
+#+        +#+        +#++:++#++: +#+     +:+ +#++:++#  +#++:++#++                                        
+#+        +#+        +#+     +#+  +#+   +#+  +#+              +#+                                        
#+#    #+# #+#        #+#     #+#   #+#+#+#   #+#       #+#    #+#                                        
 ########  ########## ###     ###     ###     ########## ########                                           

                        v01 by Apuromafo
"""

# Generar colores degradados para el texto
color_inicio = colores[random.choice(list(colores.keys()))]
color_fin = colores[random.choice(list(colores.keys()))]
degradado = generar_degradado_colores(color_inicio, color_fin, len(texto))

# Imprimir el texto con el degradado de color
for i, c in enumerate(texto):
    print(degradado[i % len(degradado)] + c + "\033[0m", end="")
print()  # Nueva línea tras el banner

def clasificar_entropia(entropia):
    """Clasifica la entropía de una contraseña en categorías de fuerza."""
    if entropia < 41:
        return "Muy Débil (Very Weak): 0 - 40 bits"
    elif entropia < 61:
        return "Débil (Weak): 41 - 60 bits"
    elif entropia < 81:
        return "Moderada (Moderate): 61 - 80 bits"
    elif entropia < 101:
        return "Fuerte (Strong): 81 - 100 bits"
    else:
        return "Muy Fuerte (Very Strong): 101 bits o más"

def calcular_longitud_necesaria(entropia_deseada, complejidad):
    """Calcula la longitud necesaria para alcanzar la entropía deseada."""
    num_caracteres = sum([
        10 if complejidad['digitos'] else 0,
        26 if complejidad['mayusculas'] else 0,
        26 if complejidad['minusculas'] else 0,
        10 if complejidad['especiales'] else 0
    ])
    
    if num_caracteres == 0:
        raise ValueError("Se debe seleccionar al menos un tipo de carácter.")
    
    longitud_necesaria = math.ceil(entropia_deseada / math.log2(num_caracteres))
    return longitud_necesaria

def generar_contraseña(longitud, complejidad):
    """Genera una contraseña de la longitud y complejidad especificadas."""
    caracteres = ''.join([
        string.digits if complejidad['digitos'] else '',
        string.ascii_uppercase if complejidad['mayusculas'] else '',
        string.ascii_lowercase if complejidad['minusculas'] else '',
        "!@#$%^&*()" if complejidad['especiales'] else ''
    ])

    return ''.join(random.choice(caracteres) for _ in range(longitud))

def guardar_contraseñas_en_archivo(contrasenas):
    """Guarda una lista de contraseñas en un archivo de texto con la fecha actual en el nombre."""
    fecha_actual = datetime.now().strftime("%Y%m%d")  # Formato: YYYYMMDD
    nombre_archivo = f"passw_{fecha_actual}.log"
    
    with open(nombre_archivo, 'w') as f:
        f.writelines(f"{contrasena}\n" for contrasena in contrasenas)

def obtener_preferencias_usuario():
    """Obtiene interactivamente las preferencias del usuario para la generación de contraseñas."""
    complejidad = {
        'digitos': input("Incluir dígitos (S/N)? [S]: ").strip().lower() in ['s', ''],
        'mayusculas': input("Incluir mayúsculas (S/N)? [S]: ").strip().lower() in ['s', ''],
        'minusculas': input("Incluir minúsculas (S/N)? [S]: ").strip().lower() in ['s', ''],
        'especiales': input("Incluir caracteres especiales (S/N)? [S]: ").strip().lower() in ['s', '']
    }
    
    longitud = int(input("Ingrese la longitud deseada de la contraseña: "))
    
    return complejidad, longitud

def calcular_entropia(longitud, complejidad):
    """Calcula la entropía en bits de una contraseña basada en los tipos de caracteres usados."""
    num_caracteres = sum([
        10 if complejidad['digitos'] else 0,
        26 if complejidad['mayusculas'] else 0,
        26 if complejidad['minusculas'] else 0,
        10 if complejidad['especiales'] else 0
    ])
    
    if num_caracteres == 0:
        return 0
    
    return longitud * math.log2(num_caracteres)

def analizar_contraseña(contrasena):
    """Analiza la contraseña ingresada y devuelve su configuración y entropía."""
    longitud = len(contrasena)
    complejidad = {
        'digitos': any(c.isdigit() for c in contrasena),
        'mayusculas': any(c.isupper() for c in contrasena),
        'minusculas': any(c.islower() for c in contrasena),
        'especiales': any(c in "!@#$%^&*()" for c in contrasena)
    }
    entropia = calcular_entropia(longitud, complejidad)
    clasificacion = clasificar_entropia(entropia)
    
    return longitud, complejidad, entropia, clasificacion

def establecer_seed(seed):
    """Establece la semilla para el generador de números aleatorios a partir de una cadena."""
    if seed:
        # Convertir la cadena a un número hash
        hash_object = hashlib.sha256(seed.encode())
        seed_value = int(hash_object.hexdigest(), 16) % (2**32)  # Limitar el valor a 32 bits
        random.seed(seed_value)

def main():
    parser = argparse.ArgumentParser(description="Generador de contraseñas aleatorias.")
    parser.add_argument('-l', '--longitud', type=int, default=12, help='Longitud de la contraseña (default: 12)')
    parser.add_argument('-n', '--numero', type=int, default=10, help='Número de contraseñas a generar (default: 10)')
    parser.add_argument('-i', '--interactivo', action='store_true', help='Activar modo interactivo para configurar opciones de contraseña')
    parser.add_argument('-p', '--password', type=str, help='Contraseña a analizar')
    parser.add_argument('-s', '--seed', type=str, help='Semilla para el generador de números aleatorios (cualquier cadena)')
    parser.add_argument('-e', '--entropia', type=int, help='Entropía deseada para las contraseñas generadas')

    args = parser.parse_args()

    # Establecer la semilla si se proporciona
    establecer_seed(args.seed)

    # Si se proporciona una contraseña para analizar
    if args.password:
        longitud, complejidad, entropia, clasificacion = analizar_contraseña(args.password)
        print(f"Contraseña: {args.password}")
        print(f"Longitud: {longitud}")
        print(f"Configuración: {complejidad}")
        print(f"Entropía: {entropia:.2f} bits")
        print(f"Clasificación: {clasificacion}")
        return

    # Obtener preferencias del usuario si se activa el modo interactivo
    if args.interactivo:
        print("Configuración de opciones de contraseña:")
        complejidad_contrasena, longitud = obtener_preferencias_usuario()
    else:
        complejidad_contrasena = {
            'digitos': True,
            'mayusculas': True,
            'minusculas': True,
            'especiales': True
        }
        longitud = args.longitud

    # Validar longitud con respecto a la entropía deseada
    if args.entropia:
        longitud_necesaria = calcular_longitud_necesaria(args.entropia, complejidad_contrasena)
        if longitud < longitud_necesaria:
            print(f"Advertencia: Para alcanzar una entropía de {args.entropia} bits, ")
            print(f"considera aumentar la longitud de la contraseña a al menos {longitud_necesaria} caracteres.")
            longitud = max(longitud, longitud_necesaria)

        contrasenas = [generar_contraseña(longitud, complejidad_contrasena) for _ in range(args.numero)]
        print(f"Contraseñas generadas con {args.entropia} bits de entropía:")
    else:
        contrasenas = [generar_contraseña(longitud, complejidad_contrasena) for _ in range(args.numero)]
        print("Contraseñas generadas:")

    for i, contrasena in enumerate(contrasenas, 1):
        entropia = calcular_entropia(longitud, complejidad_contrasena)
        clasificacion = clasificar_entropia(entropia)
        print(f"{i}. {contrasena} (Longitud: {longitud}, Entropía: {entropia:.2f} bits, Clasificación: {clasificacion})")

    guardar_contraseñas_en_archivo(contrasenas)
    print(f"Contraseñas guardadas en passw_{datetime.now().strftime('%Y%m%d')}.log")

if __name__ == '__main__':
    main()