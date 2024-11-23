"""source : https://t.me/aprenderpython 
Fecha: 9 enero 2023
Primer reto Nivel Facil:
 Crea un programa que lea la hora de tu pc y que cuando ejecutes el programa, te salude dependiendo la hora, ej
"Buen dia", "Buenas tardes" o "Buenas noches".
primero instalamos la librería datetime
pip install datetime
ahora configuramos a manejar el saludo según la hora del día del pc.
Mañana: del amanecer al mediodía (00:00 – 12:00)
Tarde: del mediodía al atardecer (12:00 – 18.00)
 Noche: del atardecer a la medianoche (18.00 – 24:00)
"""
#!/usr/bin/python3

import datetime as dt

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
    print (banner)
def main():
    print_banner()

    try:
        # Obtener la hora actual
        now = dt.datetime.now()
        hour = now.hour

        # Determinar el saludo
        greeting = "Buenos días" if 0 <= hour < 12 else "Buenas tardes" if 12 <= hour < 18 else "Buenas noches"

        # Imprimir saludo y hora
        print(f"Son las: {hour:02d}: {now.minute:02d}")
        print(greeting)
 
    except ModuleNotFoundError:
        print("La librería datetime no está instalada. Por favor, instala con 'pip install datetime'")
    except Exception as e:
        print(f"Ocurrió un error inesperado: {e}")

if __name__ == "__main__":
    main()

# ejemplo de salida de consola
# Son las :   10 : 23
# ¡Buenos días!
# 
# Son las: 18:08
# ¡Buenas noches!
#