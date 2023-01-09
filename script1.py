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
import datetime as d

HH = d.datetime.now()

H= HH.hour
m= HH.minute

print("Son las :  ",H, ":" ,m)
if (H>=0 and m<= 59 )  and  (H<= 11  and m<=59):
    print ("Buenos días!!" )
elif (H>=12 and m<59) and (h<=17   and m<=59):
    print ("Buenas tardes!!")
else:
    print("Buenas Noches!!")

"""ejemplo de salida de consola
Son las :   10 : 23
Buenos días!!
"""
