Hay muchas nuevas opciones posibles   en el ejercicio , no solicitadas, pero que no está de más pensarlas

# TODO: Calendario laboral
# 1a) de un usuario  exportación en un formato   html
# 1b) exportación en formato pdf 
# 1c) exportación masiva de calendarios laborales como csv u archivo de excel


# TODO: Bases de datos .db /json
# 2a)posibilidad de cifrado en las bases de datos bajo una contraseña 
# 2b) funciones posibilidad de validación de checksum, e integridad, antes de siquiera leer el archivo, de estar sin integridad,
#  entonces indica mensaje y sugiere crear el archivo de 0,  respaldando el anterior (.bak al que deben revisar )
# y crear uno nuevo válido en la integridad lo almacena

# TODO: posibilidad de tener una base de datos de configuración inicial
# 3a) donde indique que menús desea dejar disponible para la vista, ejemplo todos en la misma línea
# uno que valide para admin, otro para el usuario final, otro para temas de backup

# TODO: Usuarios:
# 4a) es usuario valido (datos correctos para alias o nombre) pudiendo usar patrones , 2 primeras letras de nombre y luego una cantidad de numeros o parte del apellido
# eliminar usuarios
# 4b) desactivar alguno (nueva bandera que afectaría a la forma de consultar el calendario) considerando solo usuarios vigente
# o bien es que el json sea algo así
# "activo": True,
#        "contrato": {
#           "fecha_inicio": "2020-01-01",
#            "fecha_fin": "2022-01-01"
#si llega fin de contrato, cambiar el status de activo true, a activo false

#admemás  de eliminar que los guarde como y los saque de usuarios.db antes de eliminarlo , por si necesitan restaurar alguien
#usuarios.old.bak , por el momento solo eliminación directa. 

# TODO: Disponibilidad de usuarios:
# hacer funciones específicas de consulta  de disponibilidad
# 5a)  ejemplo para consultar a x  usuario si tiene o no libre una fecha
# 5b) ejemplo para consultar a x usuario si tiene o no feriado
# 5c)ejemplo para consultar a x usuario si tieen o no laboral ese día (que no sea feriado, ni libre)

# TODO :  Opciones con código según país
# 6a) incluir excepción, por licencia médica  bajo algún estándart o documento;
# 6b) que indique un rango de fechas, y las añada de forma individual ,con bandera true/false, por si se termina la licencia

# TODO :  opciones en el campo de "Sugerencias"
# 7a) que se ha creado, desde el admin, pues , al usuario al ingresar a su sesión de cierta fecha a cierta fecha, que esté al entrar a su menú
# le preguntará volver a avisar (indicará la fecha máxima de cuando le mostrará esa sugerencia en su calendario), o eliminar la sugerencia.
# admin puede guardar esa sugerencia, y tambien eliminar esa sugerencia, la idea de esas sugerencias o avisos,
#  es notificarle o recordarle que debe renovar su contrato, que tiene autorizado algún día libre u otro fin

# TODO:Backup:
# 8a) capacidad de listar los backups hechos, y restaurar ese backup

# TODO: Potencialidades en mundo laboral
# 9a)los usuarios podrían tener campos como correo, donde se les puede notificar al mismo correo del usuario
# 9b)pueden tener departamentos, la disponibilidad puede mostrarse por departamentos


#igual armé alguna estructura o idea para algunos código, aquí los comparto.

"""ideas de codigo TODO  """


#idea código 1a
"""
import datetime

# días laborables
dias_laborales = [0, 1, 2, 3, 4] # 0=domingo, 1=lunes, 2=martes, ...

# fecha actual
now = datetime.datetime.now()

# número de días en el mes actual
dias_mes = datetime.date(now.year, now.month+1, 1) - datetime.date(now.year, now.month, 1)

# inicio de la tabla
html = "<table>\n"

# encabezado de la tabla
html += "<tr><th colspan='7'>" + now.strftime("%B %Y") + "</th></tr>\n"
html += "<tr><th>Lun</th><th>Mar</th><th>Mie</th><th>Jue</th><th>Vie</th><th>Sab</th><th>Dom</th></tr>\n"

# generación de la tabla
d = 1
while d <= dias_mes.days:
    html += "<tr>"
    for i in range(7):
        if i == datetime.date(now.year, now.month, d).weekday() and i in dias_laborales and d <= dias_mes.days:
            html += "<td>" + str(d) + "</td>"
            d += 1
        else:
            html += "<td></td>"
    html += "</tr>\n"

# fin de la tabla
html += "</table>"

print(html)
"""


# idea de código 4a, generar alias
"""
def generar_username(nombre, apellido1, apellido2, num_letras):
    username = nombre[0].lower() + apellido1[:len(apellido1)-1][:num_letras].lower() + apellido2[0].lower()
    return username

# Ejemplo de uso
nombre = "Nombre"
apellido1 = "Apellido1"
apellido2 = "Apellido2"
num_letras = 5
username = generar_username(nombre, apellido1, apellido2, num_letras)
print(username)

#patrón    primera letra del nombre, apellido1, sin su carácter final, y el apellido 2 en minuscula, solo la primera letr
# nueva idea, si genera una palabra en malas palabras, entonces genera un usuario en un array genérico Ufinal00numero
#
"


#idea de código 4b
""" 
#esta opción requiere un esfuerzo adicional, ya que en cada clave donde listan a los usuarios, deben validar si es vigente, desde el login, disponibilidad, calendario y otros
#es preferible, listar, eliminar, y directamente tienes los valores
def desactivar_usuario():
    # Si el archivo de usuarios no existe, se aborta la operación
    if not os.path.exists(database_usuarios):
        print("El archivo de usuarios no existe")
        return

    # Se carga el contenido del archivo de usuarios
    with open(database_usuarios, "r") as f:
        usuarios = json.load(f)

    # Se solicita el nombre de usuario a desactivar
    nombre_usuario = input("Ingrese el nombre de usuario a desactivar: ")

    # Se verifica que el usuario exista en el diccionario
    if nombre_usuario not in [usuario["nombre_de_usuario"] for usuario in usuarios.values()]:
        print("Usuario no encontrado")
        return

    # Se actualiza la información del usuario para marcarlo como desactivado
    for usuario in usuarios.values():
        if usuario["nombre_de_usuario"] == nombre_usuario:
            usuario["vigente"] = False

    # Se guarda el diccionario actualizado en el archivo de usuarios
    with open(database_usuarios, "w") as f:
        json.dump(usuarios, f, indent=4)

    print(f"El usuario {nombre_usuario} ha sido desactivado exitosamente")
"""


#idea 9a  idea 1
"""
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import pystache
from datetime import datetime
import os
import json
from colorama import init
init(True)

class SmtpClient:
    sender_email = "my@gmail.com"
    password = "mypassword"
    smtp_server = "smtp.gmail.com"
    port = 465
    text_template = "template.txt"
    html_template = "template.html"
    filename = os.path.join(os.getcwd(), 'smtp_settings.json')
    def __init__(self):
        if not os.path.isfile(self.filename):
            with open(self.filename, 'w') as outfile:
                json.dump({
                    'sender_email': self.sender_email,
                    'password': self.password,
                    'smtp_server': self.smtp_server,

"""
#idea 9a  idea2

#https://www.tutorialspoint.com/python3/python_sending_email.htm
