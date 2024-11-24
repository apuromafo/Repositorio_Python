import sys
import random
import time  # sleep

def print_banner():
    clear = "\x1b[0m"  # color reset

    # Mapa de colores
    colors = {
        "magenta": "\x1b[35m",
        "red": "\x1b[31m",
        "green": "\x1b[32m",
        "yellow": "\x1b[33m",
        "blue": "\x1b[34m",
        "cyan": "\x1b[36m",
        "white": "\x1b[37m"
    }

    banner = r"""
.d8888.  .o88b. d8888b. d888888b d8888b. d888888b 
88'  YP d8P  Y8 88  `8D   `88'   88  `8D `~~88~~' 
`8bo.   8P      88oobY'    88    88oodD'    88    
  `Y8b. 8b      88`8b      88    88~~~      88    
db   8D Y8b  d8 88 `88.   .88.   88         88    
`8888Y'  `Y88P' 88   YD Y888888P 88         YP    
                     v0.1 
"""

    # Elegir colores aleatorios de las claves del diccionario
    color_keys = list(colors.keys())
    
    for line in banner.split("\n"):
        color = random.choice(color_keys)  # Elegir un color aleatorio
        sys.stdout.write(f"{colors[color]}{line}{clear}\n")  # Imprimir con color del mapa
        time.sleep(0.03)  # Pausa para efecto de tipo máquina de escribir

def main():
    print_banner()

if __name__ == "__main__":
    main()