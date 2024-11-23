from colorama import Fore, Style #banner
import random #banner
import math #banner


# Definición de colores
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

# Función para imprimir el banner
def print_banner():
    banner = r"""
.d8888.  .o88b. d8888b. d888888b d8888b. d888888b 
88'  YP d8P  Y8 88  `8D   `88'   88  `8D `~~88~~' 
`8bo.   8P      88oobY'    88    88oodD'    88    
  `Y8b. 8b      88`8b      88    88~~~      88    
db   8D Y8b  d8 88 `88.   .88.   88         88    
`8888Y'  `Y88P' 88   YD Y888888P 88         YP    
                     v0.1 
"""
    # Generar colores degradados para el texto
    color_inicio = colores[random.choice(list(colores.keys()))]
    color_fin = colores[random.choice(list(colores.keys()))]
    degradado = generar_degradado_colores(color_inicio, color_fin, len(banner.splitlines()))

    # Imprimir el texto con el degradado de color
    for i, line in enumerate(banner.splitlines()):
        print(degradado[i % len(degradado)] + line + "\033[0m")
        
def main():
    print_banner()
     
if __name__ == "__main__":
    main()            