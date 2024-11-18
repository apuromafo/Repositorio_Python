"""source : https://t.me/aprenderpython 
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

import datetime as d

# Obtener la hora actual
hora_actual = d.datetime.now()
hora = hora_actual.hour
minuto = hora_actual.minute

# Imprimir la hora actual
print(f"Son las: {hora:02}:{minuto:02}")

# Determinar el saludo según la hora
if 0 <= hora < 12:
    saludo = "¡Buenos días!"
elif 12 <= hora < 18:
    saludo = "¡Buenas tardes!"
else:
    saludo = "¡Buenas noches!"

print(saludo)

"""ejemplo de salida de consola
Son las :   10 : 23
¡Buenos días!

Son las: 18:08
¡Buenas noches!

"""
