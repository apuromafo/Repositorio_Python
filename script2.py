"""source : https://t.me/aprenderpython 
Segundo reto Nivel intermedio:

Proyecto: Calendario Laboral

Se solicita crear un programa que en una vista de calendario laboral muestre la disponibilidad de los usuarios en los dias que trabaja,
la idea es que exista dos roles de usuarios:

Administrador: Este puede modificar el calendario
Usuario FInal: Este solo puede leer los datos.

El administrador podra realizar las siguientes modificaciones:

1.) Asignar dias feriados:
Podra dar dias libres a los usuarios en dias feriados o vacaciones, en dado caso el sistema debe tener el minimo personal ese dia para trabajar.

El usuario final podra leer los siguiente:
Su calendario y sus dias de trabajo, ademas podra enviar sugerencias de cuando querra sus dias feriados al administrador.

Mas detalles:

La construccion y todo de como funcionara el programa sera a consideracion del programador, ya sea mediante web, cli, gui, etc... mientras se cumplan los requisitos y se utilize python.


fecha 07-02-2023
"""

"""  Modelado e ideas de como armar
 primera etapa menú  Principal , donde tenga un loguin, usuario+clave= acceso a su menú.
 usuario y clave se almacenan en un documento llamado "usuarios", 
recolección de información según rol ( 2 roles, usuario y administrador)

Segunda etapa menú Administrador
vista de administrador
visualizar calendario (Ver calendario laboral de el
ver calendario laboral de otro usuario
ver calendario laboral de todos los usuarios
ver calendario del año
ver calendario del mes
ver días feriado
ver calendario por fecha dada) 
Ver sugerencias desde usuarios
cambio de clave de el o de otros usuarios
salir

vista de usuario
ver calendario laboral
solicitar día libre
ver feriados del mes actual
cambio de clave
salir
"""
import os
import datetime
#zona configuración
#nombre usuario administrador
nombre_admin_sistema="administrador"
#nombre base de datos con datos de usuarios ejemplo claves.txt , usuarios, (nombre que se desee)
nombre_archivo_usuario_clave="usuarios"
global usuariologed
usuariologed = ''


# Función para mostrar el menú principal
def menu_principal():
    
    while True:
        claves = leer_claves()
        print("Bienvenido a Empresa 1.0 ")
        print("control de calendarios")
        print("--- Menú Principal ---")
        usuario = input("Usuario: ")
        clave = input("Clave: ")
        if verificar_acceso(usuario, clave):
            if usuario == nombre_admin_sistema:
                menu_administrador()
            else:
                usuariologed == usuario
                menu_usuario()
        else:
            print("Acceso denegado.")


# Función para cambiar la clave de un usuario
def cambiar_clave(usuario, claves):
    clave_actual = input("Ingrese su clave actual: ")
    if clave_actual == claves[usuario]:
        nueva_clave = input("Ingrese su nueva clave: ")
        confirmar_clave = input("Confirme su nueva clave: ")
        if nueva_clave == confirmar_clave:
            claves[usuario] = nueva_clave
            # Guardar las claves en el archivo
            with open(nombre_archivo_usuario_clave, "w") as archivo:
                for usuario, clave in claves.items():
                    archivo.write("{}:{}\n".format(usuario, clave))
            print("Clave cambiada con éxito.")
        else:
            print("Las claves no coinciden.")
    else:
        print("Clave incorrecta.")


def verificar_acceso(usuario, clave):
    # Verifica si el usuario y clave están en el archivo nombre_archivo_usuario_clave
    if os.path.exists(nombre_archivo_usuario_clave):
        with open(nombre_archivo_usuario_clave) as f:
            for linea in f:
                nombre, contrasena = linea.strip().split(":")
                if nombre == usuario and contrasena == clave:
                    return True
    return False

# Leer las claves del archivo
def leer_claves():
    claves = {}
    with open(nombre_archivo_usuario_clave, "r") as archivo:
        for linea in archivo:
            usuario, clave = linea.strip().split(":")
            claves[usuario] = clave
    return claves

# ...

# Se cargan las claves al iniciar el programa


# Función para mostrar el menú de administrador
def menu_administrador():
    while True:
        print("--- Menú Administrador ---")
        print("1. Ver calendario laboral ADMIN")
        print("2. Ver calendario laboral de otro usuario")
        print("3. Ver calendario laboral de todos los usuarios")
        print("4. Ver calendario del año")
        print("5. Ver calendario del mes")
        print("6. Ver días feriado")
        print("7. Ver calendario por fecha dada")
        print("8. Ver sugerencias desde usuarios")
        print("9. Cambiar clave de el o de otros usuarios")
        print("10. Salir")
        opcion = int(input("Seleccione una opción: "))
        if opcion == 1:
            # Ver calendario laboral de el ADMIN
            pass
        elif opcion == 2:
            # Ver calendario laboral de otro usuario
            pass
        elif opcion == 3:
            # Ver calendario laboral de todos los usuarios
            pass
        elif opcion == 4:
            # Ver calendario del año
            pass
        elif opcion == 5:
            # Ver calendario del mes
            pass
        elif opcion == 6:
            # Ver días feriado
            pass
        elif opcion == 7:
            # Ver calendario por fecha dada
            pass
        elif opcion == 8:
            # Ver sugerencias desde usuarios
            pass
        elif opcion == 9:
            # Cambiar clave de el o de otros usuarios
            pass
        elif opcion == 10:
            break

# Función para mostrar el menú de usuario
def menu_usuario():
    while True:
        print("--- Menú Usuario ---")
        print("bienvenido"+ usuariologed)
        print("1. Ver calendario laboral")
        print("2. Solicitar día libre dd-mm-aaaa")
        print("3. Ver feriados del mes actual ")
        print("4. Cambiar clave")
        print("5. Salir")
        opcion = int(input("Seleccione una opción: "))
        if opcion == 1:
            # Ver calendario laboral
            pass
        elif opcion == 2:
            # Solicitar día libre
            pass
        elif opcion == 3:
            # Ver feriados del mes actual
            mes = datetime.datetime.now().month
            print("Feriados del mes {}:".format(mes))
            # Aquí puedes añadir los feriados para el mes actual
        elif opcion == 4:
            # Cambiar clave
            cambiar_clave(usuariologed, claves)
            pass
        elif opcion == 5:
            break

# Llamada a la función para mostrar el menú principal

menu_principal()
