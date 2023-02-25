#!/usr/bin/env python
# -*- coding: utf-8 -*-
# autor @apuromafo
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

""" Modelado
    Desarrollo de un sistema de inicio de sesión y autenticación de usuarios:
        El sistema debe permitir el registro de usuarios con un nombre de usuario único y una contraseña segura.
        Debe haber dos roles de usuario: Administrador y Usuario Final.
        El administrador podrá acceder a funciones adicionales en comparación con el usuario final.
    Desarrollo de una vista de calendario laboral:
        El calendario debe mostrar la disponibilidad de los usuarios en los días que trabajan.
        La vista debe ser clara y fácil de usar.
    Modificaciones por parte del administrador:
        El administrador puede asignar días feriados o vacaciones a los usuarios.
        El sistema debe tener un mínimo de personal ese día para trabajar.
    Visualización del calendario por parte del usuario final:
        El usuario final puede ver su propio calendario y sus días de trabajo.
        El usuario final puede enviar sugerencias para sus días feriados al administrador.
    Almacenamiento de datos:
        El sistema debe almacenar los datos de usuario y su disponibilidad de manera segura.
        Cada usuario debe tener su propio calendario y su información debe ser accesible solo por el usuario y el administrador.
    Seguridad:
        El sistema debe tener medidas de seguridad para proteger los datos y prevenir accesos no autorizados.
"""

from core.banner import *  # banner custom.
#
# idea de agregar un banner, usando un componente externo, y se vea el código mas limpio
#
import calendar
#
# backup
# idea de manejar en base de datos la información de usuarios, respaldos o lo que se estime conveniente
# solo hacer backup al término del día o bien cada un cierto tiempo
# idea https://www.geeksforgeeks.org/python-shutil-copytree-method/
#
import shutil
import os
#
# al loguear la cuenta quiero que tenga privacidad (no mostrará la clave ingresada)
#
import getpass
# para almacenado de información usaré json
import json
# para el manejo de fechas, tiempos, calendarios
# idea https://micro.recursospython.com/recursos/como-obtener-la-fecha-y-hora-actual.html
#
import time
import datetime
from datetime import date
from datetime import datetime
from datetime import timedelta
#
# para las contraseñas usen cifrado , para salt usaré "os"
#
import hashlib

#
# espacio de configuración de rutas
# Ruta del calendario


ruta_calendario = "database"
database_usuarios = "usuarios.db"
# uso   "calendario": f"{ruta_calendario}/calendario_{nombre_usuario}.db"
ruta_usuario = "usuarios"
# login(usuario)=  cargar_datos_desde_archivo(ruta_usuario+"/"+database_usuarios)
ruta_backup = "backup"
# uso ruta_usuario+"_"+ruta_backup+"_"+append_nowtime

config_archivo_solicitudes = "solicitudes.db"
# solicitudes(usuario_final)todas las peticiones realizadas por todos los usuarios, estarán en este archivo.
nombre_feriado = "feriados.db"
# solicitar_feriado(admin) = guardar_datos_en_archivo(nombre_feriado)
# suele ser común que necesite saber los ["dias_feriados"] , estos son comúnes para todos los usuarios asi que debe estar aparte.


# config inicial , variables para json/base de datos
usuario_actual = None
rol_usuario = None
calendario_usuario = None
# variables para contadores que usarán mas adelante.
contador_feriados, contador_libres, contador_excepcion, contador_laborales = 0, 0, 0, 0
# contador_sugerencia=0  #desactivado realmente no lo usaré, pero si lo almacenaré por si se desea tener una opción adicional

# inicio funcion de usuario
# carga de usuarios existenets


# inicio de creación de usuarios


def crear_archivo_usuarios():
    # Si el archivo ya existe, se aborta la operación
    if os.path.exists(ruta_usuario+"/"+database_usuarios):
        print("El archivo de usuarios ya existe, puedes ya utilizar el sistema")
        return

    # Se solicita la información del usuario administrador
    nombre_admin = input("Ingrese el nombre de usuario: ")
    # su contraseña es visible
    # contrasena_admin = input("Ingrese la contraseña: ")
    # su contraseña no es visible
    contrasena_admin = getpass.getpass()

    # Se genera el salt y la contraseña hasheada del usuario administrador
    salt = os.urandom(16)
    password_hash = hashlib.pbkdf2_hmac(
        "sha256", contrasena_admin.encode("utf-8"), salt, 100000)

    # Se guarda la información del usuario administrador en un diccionario
    admin = {"nombre_de_usuario": nombre_admin, "contrasena": password_hash.hex(
    ), "salt": salt.hex(), "rol": "administrador", "calendario": "database/calendario_admin.db"}

    # Se crea el archivo de usuarios y se guarda el diccionario como contenido inicial
    with open(ruta_usuario+"/"+database_usuarios, "w") as f:
        json.dump({"1": admin}, f, indent=4)

    print("Archivo de usuarios creado exitosamente")


def listar_usuarios():
    for usuario_id, datos_usuario in usuarios.items():
        print(f"ID: {usuario_id}")
        print(f"Nombre de usuario: {datos_usuario['nombre_de_usuario']}")
        print(f"Rol: {datos_usuario['rol']}")
        print(f"Calendario: {datos_usuario['calendario']}")
        print()


def eliminar_usuario():
    # 1 de 3 :primero lo listamos
    listar_usuarios()
    # 2 paso : eliminamos si es válido el id
    global usuarios
    usuario_id = sanitizar_input(input("ID del usuario a eliminar: "))
    # reseteamos su calendario
    for usuario_id, datos_usuario in usuarios.items():
        calendario = {
            "dias_libres": [],
            "dias_excepcion": [],
            "sugerencias": []
        }
        guardar_datos_en_archivo_main(
            calendario, f"database/calendario_{datos_usuario['nombre_de_usuario']}.db")
    if usuario_id in usuarios:
        del usuarios[usuario_id]
        print("Usuario eliminado exitosamente.")
        # 3er paso, eliminar su base de datos

    else:
        print("ID de usuario inválido.")


def crear_usuario():
    # Si el archivo de usuarios no existe, se aborta la operación
    if not os.path.exists(ruta_usuario+"/"+database_usuarios):
        print("El archivo de usuarios no existe")
        return

    # Se carga el contenido del archivo de usuarios
    with open(ruta_usuario+"/"+database_usuarios, "r") as f:
        usuarios = json.load(f)

    # Se solicita la información del nuevo usuario
    nombre_usuario = input("Ingrese el nombre de usuario: ")
    contrasena = input("Ingrese la contraseña: ")
    rol = input("Rol:\n1. Administrador\n2. Usuario final\nElija una opción: ")

    # Se verifica que el rol ingresado sea válido
    if rol not in ["1", "2"]:
        print("Rol inválido")
        return

    # Se genera el salt y la contraseña hasheada del nuevo usuario
    salt = os.urandom(16)
    password_hash = hashlib.pbkdf2_hmac(
        "sha256", contrasena.encode("utf-8"), salt, 100000)

    # Se agrega la información del nuevo usuario al diccionario existente
    usuarios[str(len(usuarios) + 1)] = {"nombre_de_usuario": nombre_usuario, "contrasena": password_hash.hex(), "salt": salt.hex(
    ), "rol": "administrador" if rol == "1" else "usuario final", "calendario": f"database/calendario_{nombre_usuario}.db"}

    # Se guarda el diccionario actualizado en el archivo de usuarios
    with open(ruta_usuario+"/"+database_usuarios, "w") as f:
        json.dump(usuarios, f, indent=4)

    print("Usuario creado exitosamente")
    #ya que creamos el usuario, ahora vamos por su calendario (crearlo)
    calendario = {
        "dias_libres": [],
        "dias_excepcion": [],
        "sugerencias": []
    }
    guardar_datos_en_archivo_main(
        calendario, f"database/calendario_{nombre_usuario}.db")
    print("calendario_creado exitosamente")

# fin de creación de usuarios


def cargar_datos_desde_archivo(ruta_archivo):
    try:
        with open(ruta_archivo, "r") as archivo:
            contenido = json.load(archivo)
        return contenido
    except FileNotFoundError:
        print(f"El archivo '{ruta_archivo}' no existe.")
        return {}
    except json.JSONDecodeError:
        print(f"El archivo '{ruta_archivo}' no es un archivo JSON válido.")
        return None


usuarios = cargar_datos_desde_archivo(ruta_usuario+"/"+database_usuarios)


def sanitizar_input(texto):
    return texto.strip()
# recordar si sanitizo, debe ser sobre el input, no al reves.


# opciones con calendario
# vistas de calendario (generar vista por mes) primero debo saber resaltar el día.


def generar_calendario_mes(dia_resaltado, mes, anio):
    # no me da tranquilidad que siempre me muestre el mes correspondiente, asi que armo el nombre a mi medida
    # luego usaré capitalize para colocar el primero en mayúscula
    meses = {
        1: "enero",
        2: "febrero",
        3: "marzo",
        4: "abril",
        5: "mayo",
        6: "junio",
        7: "julio",
        8: "agosto",
        9: "septiembre",
        10: "octubre",
        11: "noviembre",
        12: "diciembre"
    }
    nombre_mes = meses[mes]
    print(f"Calendario de {nombre_mes.capitalize()} {anio}")
    dias_mes = calendar.monthrange(anio, mes)[1]
    primer_dia_semana = calendar.weekday(anio, mes, 1)

    dias_semana = ["Lu", "Ma", "Mi", "Ju", "Vi", "Sa", "Do"]
    for dia in dias_semana:
        print(f"{dia}", end="   ")
    print()
    # otra forma directa sería
    # print(" Lu  Ma  Mi  Ju  Vi  Sa  Do")
    # imprime los valores que serán 0 y en este caso son reemplazados con espacio
    for i in range(0, primer_dia_semana):
        print("  ", end="  ")

    for dia in range(1, dias_mes + 1):
        if dia == dia_resaltado:
            # aquí resaltaré con un [] en el día que sea indicado
            print(f"[{dia:2d}]", end="")
        else:
            print(f" {dia:2d}", end=" ")

        if (dia + primer_dia_semana) % 7 == 0:
            print()
    print()
# fin de resaltado de día

# generando el calendario laboral usa todas las variables que he generado anteriormente

# funcional


def obtener_mes_y_anio():
    while True:
        mes_generar = input("Ingresa el número del mes (1-12): ")
        if not mes_generar.isnumeric():
            print("Error: debes ingresar un valor numérico.")
            continue
        mes_generar = int(mes_generar)
        if mes_generar < 1 or mes_generar > 12:
            print("Error: debes ingresar un valor entre 1 y 12.")
            continue
        break

    while True:
        anio_min = 2023
        anio_max = anio_min+10
        anio_generar = input("Ingresa el año: ")
        if not anio_generar.isnumeric():
            print("Error: debes ingresar un valor numérico.")
            continue
        anio_generar = int(anio_generar)
        if anio_generar < anio_min or anio_generar > anio_max:
            print(
                f"Error: debes ingresar un valor entre {anio_min} y {anio_max}.")
            continue
        break

    return mes_generar, anio_generar


def generar_calendario_laboral():
    #    contador_feriados = globals().get("contador_feriados")
    #    contador_libres= globals().get(" contador_libres")
    #    contador_excepcion= globals().get("contador_excepcion")
    #    contador_laborales=globals().get("contador_laborales")
    # Agregar variables de contador
    contador_feriados,    contador_libres,    contador_excepcion,    contador_laborales = 0, 0, 0, 0
    # Solicitamos mes y año
    mes_generar, anio_generar = obtener_mes_y_anio()

    # Días de la semana
    dias_semana = ["Lun", "Mar", "Mie", "Jue", "Vie", "Sab", "Dom"]
    dias_laborables = ["Lunes", "Martes", "Miércoles", "Jueves", "Viernes"]
    # Feriados
    feriados = []
    if os.path.isfile(nombre_feriado):
        with open(nombre_feriado, "r") as f:
            feriados = json.load(f)["dias_feriados"]

    # Días libres
    calendario_usuario = globals().get("calendario_usuario")
    dias_libres = []
    # sugerencias_aprobadas = []
    dias_excepcion = []
    if os.path.isfile(calendario_usuario):
        with open(calendario_usuario, "r") as f:
            calendario = json.load(f)
            dias_libres = calendario.get("dias_libres", [])
             #print("tipo sugerencias_aprobadas" ,calendario.get("sugerencias", []))
            # dias_sugerencias_aprobadas = calendario.get("sugerencias", [])
            dias_excepcion = calendario.get("dias_excepcion", [])
            # saber los tipos de días libres
            # print("tipo dias_libres" ,calendario.get("dias_libres", []))


# saber las sugerencias que tienen actualmente
#            
            # dias_libres = dias_libres + sugerencias_aprobadas
    meses = {
        1: "enero",
        2: "febrero",
        3: "marzo",
        4: "abril",
        5: "mayo",
        6: "junio",
        7: "julio",
        8: "agosto",
        9: "septiembre",
        10: "octubre",
        11: "noviembre",
        12: "diciembre"

    }
    nombre_mes = meses[mes_generar]
    # Obtener los días y primer día de la semana del mes

    dias_mes = calendar.monthrange(anio_generar, mes_generar)[1]
    primer_dia_semana = calendar.weekday(anio_generar, mes_generar, 1)
    # nombre_mes = meses[mes_generar]
    nuevo_calendario = []
    print(f"Calendario de {nombre_mes.capitalize()} {anio_generar}")
    for dia in dias_semana:
        print(f"{dia}  ", end=" ")
    print()

    for i in range(dias_mes):
        dia = i + 1
    # Obtener el día de la semana
        dia_semana = (i + primer_dia_semana) % 7
    # Agregar un espacio si no es el primer día de la semana
        if dia_semana == 0 and i != 0:
            print("     ")
        elif i == 0:
            print("      " * primer_dia_semana, end="")
    # Verificar si el día es feriado o libre
        if any(f["fecha"] == f"{anio_generar}-{mes_generar:02d}-{dia:02d}" for f in feriados):
            print(f"{dia:02d}[F]", end=" ")
            contador_feriados += 1
        elif any(d == f"{anio_generar}-{mes_generar:02d}-{dia:02d}" for d in dias_excepcion):
            print(f"{dia:02d}[E]", end=" ")
            contador_excepcion += 1    
        elif any(d == f"{anio_generar}-{mes_generar:02d}-{dia:02d}" for d in dias_libres):
            print(f"{dia:02d}[L]", end=" ")
            contador_libres += 1
        elif dia_semana < 5:  # si el día es laboral (Lun a Vie)
            # otra mejor forma suele ser con weekday, pero requiere otro tratamiento
            print(f"{dia:02d}[T]", end=" ")
            contador_laborales += 1
        else:
            print(f"{dia:02d}[L]", end=" ")  # si es fin de semana
            # print()
    print(f"\nLeyenda: \n")
    print(f"[F]=Feriados    total: {contador_feriados} ")
    print(f"[L]=Libre       total: {contador_libres}   ")
    print(f"[E]=Excepción   total: {contador_excepcion}")
    print(f"[T]=Día laboral total: {contador_laborales} \n")
    contador_feriados, contador_libres, contador_excepcion, contador_laborales = 0,0,0,0



def iniciar_sesion():
    global usuario_actual, rol_usuario, calendario_usuario
    #usuario_actual=globals().get("usuario_actual")
    #rol_usuario=globals().get("rol_usuario")
    #calendario_usuario=globals().get("calendario_usuario")
    nombre_de_usuario = sanitizar_input(input("Nombre de usuario: "))
    contrasena = getpass.getpass()
    #time.sleep(1)  # una pequeña pausa
    for usuario_id, datos_usuario in usuarios.items():
        if datos_usuario["nombre_de_usuario"] == nombre_de_usuario:
            salt = bytes.fromhex(datos_usuario['salt'])
            hash_object = hashlib.pbkdf2_hmac(
                'sha256', contrasena.encode('utf-8'), salt, 100000)
            hashed_password = hash_object.hex()
            if datos_usuario["contrasena"] == hashed_password:
                usuario_actual = nombre_de_usuario
                rol_usuario = datos_usuario['rol']
                calendario_usuario = datos_usuario['calendario']
                print("Sistema de Calendario v1.0")
                print(f"Sesión iniciada como {nombre_de_usuario}")
                print(f"Rol: {datos_usuario['rol']}")
                print(f"Calendario: {datos_usuario['calendario']}")
                return
            else:
                print("Contraseña incorrecta.")
                #si hay cuentas logueadas previamente, lo fuerzo a que sea none
                usuario_actual=None
                return
    print("Nombre de usuario inválido.")
    #si hay cuentas logueadas previamente, lo fuerzo a que sea none
    usuario_actual=None

# implementado para obtener los usuarios del sistema, obtener su id, y además establece una variable de su calendario actual para este usuario
# principalmente para que el administrador pueda ver el calendario de quien quiera.

def listar_usuarios_sistema():
    for usuario_id, datos_usuario in usuarios.items():
        print(
            f"ID: {usuario_id}, Nombre de usuario: {datos_usuario['nombre_de_usuario']} Rol: {datos_usuario['rol']}")

    usuario_seleccionado = input(
        "Ingrese el ID del usuario que desea seleccionar: ")

    if usuario_seleccionado in usuarios:
        global usuario_seleccionado_id
        usuario_seleccionado_id = usuarios[usuario_seleccionado]
        return usuarios[usuario_seleccionado]
    else:
        print("ID de usuario inválido, estableciendo tu usuario actual")
    return None


# import datetime suele a ratos ser reconocidos y en otros no, prefiero importarla donde la necesito
# no solamente tenemos una fecha , sino también generará un calendario con esa fecha resaltada.


def solicitar_fecha_d_m_a():
    while True:
        # Pedir el día
        dia_ok = input("Ingresa el número del día (1-31): ")
        if not dia_ok.isnumeric():
            print("Error: debes ingresar un valor numérico en el rango.")
            continue
        dia_ok = int(dia_ok)
        if dia_ok < 1 or dia_ok > 31:
            print("Error: debes ingresar un valor entre 1 y 31.")
            continue
        # Pedir el mes
        mes_ok = input("Ingresa el número del mes (1-12): ")
        if not mes_ok.isnumeric():
            print("Error: debes ingresar un valor numérico en el rango.")
            continue
        mes_ok = int(mes_ok)
        if mes_ok < 1 or mes_ok > 12:
            print("Error: debes ingresar un valor entre 1 y 12.")
            continue

        # Pedir el año
        from datetime import date
        hoy = date.today()
        min_year = hoy.year
        max_year = min_year + 10
        anio_ok = input(
            f"Ingrese el año de la fecha solicitada ({min_year}-{max_year}): ")
        if not anio_ok.isnumeric():
            print("Error: debes ingresar un valor numérico en el rango.")
            continue
        anio_ok = int(anio_ok)
        if anio_ok < min_year or anio_ok > max_year:
            print(
                f"Año inválido. Por favor, ingrese un año entre {min_year} y {max_year}.")
            continue

        # Verificar si es una fecha válida
        try:
            fecha = date(anio_ok, mes_ok, dia_ok)
            return fecha.day, fecha.month, fecha.year
        except ValueError:
            print("Fecha inválida. Por favor, ingrese una fecha válida.")

#
# espacio de funciones de feriado_
#


def cargar_feriados_archivo(ruta_archivo):
    try:
        with open(ruta_archivo, "r") as archivo:
            contenido = json.load(archivo)
            if "dias_feriados" not in contenido:
                contenido["dias_feriados"] = []
            return contenido
    except (FileNotFoundError, json.JSONDecodeError):
        return {"dias_feriados": []}


def guardar_feriados_en_archivo(ruta_archivo, dias_feriados):
    try:
        with open(ruta_archivo, "w") as archivo:
            json.dump({"dias_feriados": dias_feriados}, archivo)
        print(
            f"Se han guardado los días feriados en el archivo {ruta_archivo}")
    except FileNotFoundError:
        print(
            f"No se pudo guardar los días feriados. El archivo {ruta_archivo} no existe.")
    except:
        print(
            f"No se pudo guardar los días feriados en el archivo {ruta_archivo}.")


def mostrar_feriados():
    contenido = cargar_feriados_archivo(nombre_feriado)
    dias_feriados = contenido.get("dias_feriados", [])
    dias_feriados_ordenados = sorted(
        dias_feriados, key=lambda feriado: feriado["fecha"])

    if len(dias_feriados_ordenados) > 0:
        print("Los días feriados registrados son:")
        for feriado in dias_feriados_ordenados:
            print(f"- {feriado['fecha']} ({feriado['descripcion']})")
    else:
        print("No se han registrado días feriados aún.")


def menu_mostrar_feriados():

    opciones = {
        0: "Volver al menú principal",
        1: "Ver feriados ordenados por fecha  ",
        2: "Asignar Feriado",
        3: "Eliminar Feriado",
    }
    while True:
        print("\nOpciones de visualización de sugerencias:")
        for opcion, descripcion in opciones.items():
            print(f"{opcion}. {descripcion}")

        opcion = input("\nIngrese la opción deseada: ")
        if opcion == "0":
            break
        try:
            opcion = int(opcion)
            if opcion not in opciones:
                raise ValueError()
        except ValueError:
            print("Opción inválida. Por favor, ingrese un número del 0 al 3.")
            continue

        if opcion == 1:
            print("\n Ver feriados ordenados por fecha : ")
            mostrar_feriados()
        elif opcion == 2:
            print("\n Asignar Feriados: ")
            agregar_feriado()

        elif opcion == 3:
            print("\n Quitar Feriados: ")
            quitar_feriado()

        else:
            print("No hay Feriados.")


def es_fecha_valida(fecha_str):
    try:
        fecha = datetime.strptime(fecha_str, "%Y-%m-%d")
        return True
    except ValueError:
        return False


def quitar_feriado():
    contenido = cargar_feriados_archivo(nombre_feriado)
    dias_feriados = contenido.get("dias_feriados", [])
    if not dias_feriados:
        print("No hay días feriados registrados.")
        return
    while True:
        # print("Los días feriados registrados son:") ya está este título en mostrar_feriado
        mostrar_feriados()
        fecha = input(
            "Ingrese la fecha del día feriado que desea quitar (formato: AAAA-MM-DD): ")
        if not es_fecha_valida(fecha):
            print("Error: La fecha ingresada es inválida.")
            return

        for feriado in dias_feriados:
            if feriado["fecha"] == fecha:
                dias_feriados.remove(feriado)
                guardar_feriados_en_archivo(nombre_feriado, dias_feriados)
                print(
                    f"Se ha eliminado el día feriado del {fecha} de la lista.")
                return
        print("No se ha encontrado un día feriado registrado en la fecha ingresada.")




def agregar_feriado():
    while True:
        dia_ok, mes_ok, anio_ok = solicitar_fecha_d_m_a()
        generar_calendario_mes(dia_ok, mes_ok, anio_ok)
        fecha_solicitada = date(anio_ok, mes_ok, dia_ok)
        fecha_solicitada = fecha_solicitada.strftime('%Y-%m-%d')
        fecha_str = fecha_solicitada

        descripcion = sanitizar_input(
            input("Ingrese una descripción para este día feriado: "))
        try:
            import time
            fecha = datetime.strptime(fecha_str, "%Y-%m-%d")
        except ValueError:
            print("Error: El formato de la fecha es incorrecto. Intente de nuevo.")
        else:
            fecha_str = fecha.date().isoformat()
            contenido = cargar_feriados_archivo(nombre_feriado)
            dias_feriados = contenido.get("dias_feriados", [])
            index_feriado_existente = None
            for i, feriado in enumerate(dias_feriados):
                if feriado["fecha"] == fecha_str:
                    index_feriado_existente = i
                    break
            if index_feriado_existente is not None:
                dias_feriados[index_feriado_existente]["descripcion"] = descripcion
                print(
                    f"La descripción del día feriado {fecha_str} ha sido actualizada.")
            else:
                nuevo_feriado = {"fecha": fecha_str,
                                 "descripcion": descripcion}
                dias_feriados.append(nuevo_feriado)
                print(
                    f"Se ha agregado el día feriado {fecha_str} ({descripcion}) a la lista.")
            dias_feriados_ordenados = sorted(
                dias_feriados, key=lambda f: f["fecha"])
            guardar_feriados_en_archivo(
                nombre_feriado, dias_feriados_ordenados)
            break


#
# fin de espacio de funciones de feriado_
#
#


# inicio funcion de solicitud de excepción
#


def cargar_dias_excepcion_archivo(nombre_archivo):
    try:
        with open(nombre_archivo, "r") as archivo:
            contenido = json.load(archivo)
    except FileNotFoundError:
        contenido = {}

    return contenido


# ya existe la funcion de cargar_datos_desde_archivo

# Menú Administración Calendario personal
# Establecer días de excepción


def menu_excepciones():
    global usuario_seleccionado_excepciones
    usuario_seleccionado_excepciones = listar_usuarios_sistema()
    if usuario_seleccionado_excepciones:
        print("Calendario de usuario seleccionado:",
              usuario_seleccionado_excepciones['nombre_de_usuario'])
        calendario_actual = cargar_datos_desde_archivo(
            usuario_seleccionado_excepciones['calendario'])

        while True:
            print("\nSeleccione una opción:")
            print("1. Ver excepciones")
            print("2. Agregar excepción")
            print("3. Eliminar excepción")
            print("4. Salir")
            opcion = input("Ingrese el número de opción: ")
            if opcion == "1":
                ver_excepciones(calendario_actual)
            elif opcion == "2":
                agregar_excepcion(calendario_actual)
            elif opcion == "3":
                eliminar_excepcion(calendario_actual)
            elif opcion == "4":
                print("Volviendo al menú principal...")
                break
            else:
                print("Opción no válida. Por favor, ingrese un número del 1 al 4.")

# Menú Administración Calendario personal
# opcion 2 menu_excepciones
# opcion 1


def ver_excepciones(calendario):
    if not calendario.get('dias_excepcion'):
        print("No hay excepciones registradas.")
    else:
        print("Excepciones:\n Fecha  Descripción")
        for fecha, descripcion in calendario['dias_excepcion'].items():
            print(f"{fecha} : { descripcion}")


# Menú Administración Calendario personal
# opcion 2 menu_excepciones
# opcion 2
def agregar_excepcion(calendario):
    fecha = input("Ingrese la fecha de la excepción (formato AAAA-MM-DD): ")
    descripcion = input("Ingrese la descripción de la excepción: ")
    if not calendario.get('dias_excepcion'):
        calendario['dias_excepcion'] = {}
    calendario['dias_excepcion'][fecha] = descripcion
    guardar_datos_en_archivo_main(
        calendario,  usuario_seleccionado_excepciones['calendario'])
    print("Excepción agregada con éxito.")

# Menú Administración Calendario personal
# opcion 2 menu_excepciones
# opcion 3


def eliminar_excepcion(calendario):
    if not calendario.get('dias_excepcion'):
        print("No hay excepciones registradas.")
    else:
        # mostrar las excepciones actuales
        print(f"Excepciones:")
        print(f"Fecha           Descripción")
        for fecha, descripcion in calendario['dias_excepcion'].items():
            print(f"{fecha} : { descripcion}")
        # ahora recién manipulamos la fecha a eliminar
        fecha = input(
            "Ingrese la fecha de la excepción a eliminar (formato AAAA-MM-DD): ")
        if fecha in calendario['dias_excepcion']:
            del calendario['dias_excepcion'][fecha]
            guardar_datos_en_archivo_main(
                calendario,  usuario_seleccionado_excepciones['calendario'])
            print("Excepción eliminada con éxito.")
        else:
            print("No se encontró una excepción para la fecha ingresada.")

# fin excepciones#

#espacio funciones días libre
# inicio dias libres
def menu_libres():
#para usar estos menús es importante que tengan un calendario seleccionado.
    global usuario_seleccionado_libres
    usuario_seleccionado_libres = listar_usuarios_sistema()
    if usuario_seleccionado_libres:
        print("Calendario de usuario seleccionado:",
              usuario_seleccionado_libres['nombre_de_usuario'])
        calendario_actual = cargar_datos_desde_archivo(
            usuario_seleccionado_libres['calendario'])
        while True:
            print("\nSeleccione una opción:")
            print("1. Ver Días libres")
            print("2. Agregar Libre")
            print("3. Eliminar Libre")
            print("4. Salir")
            opcion = input("Ingrese el número de opción: ")
            if opcion == "1":
                ver_libres(calendario_actual)
            elif opcion == "2":
                agregar_libres(calendario_actual)
            elif opcion == "3":
                eliminar_libres(calendario_actual)
            elif opcion == "4":
                print("Volviendo al menú principal...")
                break
            else:
                print("Opción no válida. Por favor, ingrese un número del 1 al 4.")


def ver_libres(calendario):
    if not calendario.get('dias_libres'):
        print("No hay Días libres en registro.")
    else:
        print("Días libres:\n Fecha  Descripción")
        for fecha, descripcion in calendario['dias_libres'].items():
            print(f"{fecha} : { descripcion}")


def agregar_libres(calendario):
    while True:
        fecha = input("Ingrese la fecha de la Libre (formato AAAA-MM-DD): ")
        if not es_fecha_valida(fecha):
            print("Error: La fecha ingresada es inválida.")
            return
        descripcion = input("Ingrese la descripción de la Libre: ")
        if not calendario.get('dias_libres'):
            calendario['dias_libres'] = {}
        calendario['dias_libres'][fecha] = descripcion
        guardar_datos_en_archivo_main(
            calendario,  usuario_seleccionado_libres['calendario'])
        print("Libre agregada con éxito.")


def eliminar_libres(calendario):
    if not calendario.get('dias_libres'):
        print("No hay Días libres en registro.")
    else:
        # mostrar las Días libres actuales
        print(f"Días libres:")
        print(f"Fecha           Descripción")
        for fecha, descripcion in calendario['dias_libres'].items():
            print(f"{fecha} : { descripcion}")
        # ahora recién manipulamos la fecha a eliminar
        fecha = input(
            "Ingrese la fecha de la Libre a eliminar (formato AAAA-MM-DD): ")

        if fecha in calendario['dias_libres']:
            del calendario['dias_libres'][fecha]
            guardar_datos_en_archivo_main(
                calendario,  usuario_seleccionado_libres['calendario'])
            print("Día Libre eliminado con éxito.")
        else:
            print("No se encontró un día Libre para la fecha ingresada.")

# fin dias libres


#
# Inicio espacio de funciones de solicitud
#


def crear_sugerencias(usuario, fecha, motivo):
    ##
    #   Crea una nueva solicitud (sugerencia) y la agrega a la lista de solicitudes en el archivo JSON.
    # el administrador puede tomar la solicitud y convertirla en día libre  una vez que lee esta información.

    if os.path.exists(config_archivo_solicitudes):
        with open(config_archivo_solicitudes, "r") as archivo:
            solicitudes = json.load(archivo)
    else:
        solicitudes = []

    id_solicitud = len(solicitudes) + 1
    nueva_solicitud = {
        "id": id_solicitud,
        "usuario": usuario,
        "fecha": str(fecha),
        "motivo": str(motivo),
        "estado": "Pendiente"
    }

    solicitudes.append(nueva_solicitud)

    with open(config_archivo_solicitudes, "w") as archivo:
        json.dump(solicitudes, archivo, indent=4)


def ver_sugerencias():
    global usuario_actual, fecha_solicitada
    """
    Muestra las sugerencias de los usuarios finales sobre los días feriados que desean tener.
    num_feriados, num_libres, num_excepcion, num_dias_laborales,, rol, calendario,
    """
    if usuario_actual is not None:
        print("\n----- SUGERENCIAS ------")

        # Implementar lógica para leer las sugerencias de un archivo o base de datos
        # y mostrarlas al usuario.

        fecha = solicitar_fecha_d_m_a()

        opcion_solicitud = input(
            "Elija una opción: \n 1. Solicitar el día elegido \n 2. Cambiar fecha \n Ingrese Opción:  ")
        if opcion_solicitud == "1":
            print("procesando la información")
        elif opcion_solicitud == "2":
            fecha = solicitar_fecha_d_m_a()
        else:
            print("Opción inválida , retornando al menú de usuario")
            return

        if os.path.exists(config_archivo_solicitudes):
            with open(config_archivo_solicitudes, "r") as archivo:
                solicitudes = json.load(archivo)
                for solicitud in solicitudes:
                    if solicitud["usuario"] == usuario_actual and solicitud["fecha"] == str(fecha):
                        print(
                            "Esta fecha ya fue solicitada anteriormente. Por favor, ingrese una fecha diferente.")
                        return

        motivo = sanitizar_input(
            input("Favor indique el motivo de la solicitud brevemente: "))
        crear_sugerencias(usuario_actual, fecha, motivo)

        print("Solicitud creada exitosamente!")


def carga_calendario(nombre_archivo, nombre_usuario):
    try:
        # Cargar los datos del archivo JSON en una variable Python
        with open(nombre_archivo, "r") as archivo:
            calendarios = json.load(archivo)

        # Verificar si el calendario del usuario existe
        if nombre_usuario in calendarios:
            calendario = calendarios[nombre_usuario]
            print("Calendario actual a usar:", calendario)
        else:
            calendario = {
                "dias_feriados": [],
                "dias_libres": [],
                "dias_excepcion": [],
                "sugerencias": []
            }
            print("El calendario de", nombre_usuario,
                  "no existe. Se creará uno nuevo.")

        return calendario

    except FileNotFoundError:
        print(f"El archivo {nombre_archivo} no existe.")
        return None
    except:
        print(
            f"Ha ocurrido un error al cargar el calendario de {nombre_usuario} desde el archivo {nombre_archivo}.")

    return None


def ver_solicitudes():
    usuario_actual = globals().get("usuario_actual")
    solicitudes_usuario = globals().get("solicitudes_usuario")
    solicitudes_usuario = []
    solicitudes = []

    if os.path.exists(config_archivo_solicitudes):
        with open(config_archivo_solicitudes, "r") as archivo:
            solicitudes = json.load(archivo)
    else:
        solicitudes = []

        solicitudes_usuario = solicitudes
    for solicitud in solicitudes:
        if solicitud["usuario"] == usuario_actual:
            solicitudes_usuario.append(solicitud)

    if solicitudes_usuario:
        print(f"Solicitudes de {usuario_actual}:")
        for solicitud in solicitudes_usuario:
            print(
                f'ID Solicitud: {solicitud["id"]}  Fecha: {solicitud["fecha"]}  Estado: {solicitud["estado"]}  Solicitud(Motivo): {solicitud["motivo"]}')
        print()

    else:

        print(f"No hay solicitudes para {usuario_actual}.")
# implementando para sugerencias del admin



def ordenar_sugerencias():

    sugerencias = []

    if os.path.exists(config_archivo_solicitudes):
        with open(config_archivo_solicitudes, "r") as archivo:
            sugerencias = json.load(archivo)
    
    else:
            #print('No hay sugerencias.')
            sugerencias = []
    
    sugerencias_ordenadas = sorted(sugerencias, key=lambda x: x['usuario'])
    return sugerencias_ordenadas



# menu admin
def ver_calendario():

    usuario_actual = globals().get("usuario_actual")
    usuario_seleccionado_id = globals().get("usuario_seleccionado_id")
    calendario_usuario = globals().get("calendario_usuario")
    calendario_seleccionado_id = globals().get("calendario_seleccionado_id")
    contador_feriados = globals().get("contador_feriados")
    contador_libres = globals().get(" contador_libres")
    contador_excepcion = globals().get("contador_excepcion")
    contador_laborales = globals().get("contador_laborales")
    # Agregar variables de contador
    contador_feriados = 0
    contador_libres = 0
    contador_excepcion = 0
    contador_laborales = 0

    if usuario_seleccionado_id is not None:
        usuario_actual = usuario_seleccionado_id

    if usuario_actual is not None:
        # obtener mes y año
        mes_actual, anio_actual = obtener_mes_y_anio()

        dias_laborables = ["Lunes", "Martes", "Miércoles", "Jueves", "Viernes"]
        dias_laborables_imprimir = ["Lun", "Mar", "Mié", "Jue", "Vie"]
        tag_str = "Trabajo "
        # carga del calendario del usuario
        calendario_actual = cargar_datos_desde_archivo(calendario_usuario)
        # carga de los feriados del sistema
        contenido = cargar_datos_desde_archivo(nombre_feriado)

        dias_feriados = [date.fromisoformat(
            d["fecha"]) for d in contenido.get("dias_feriados", [])]
        dias_libres = [date.fromisoformat(
            d) for d in calendario_actual.get("dias_libres", [])]
        dias_excepcion = [date.fromisoformat(
            d) for d in calendario_actual.get("dias_excepcion", [])]

        # Agregar variables de contador
        contador_feriados, contador_libres, contador_excepcion, contador_laborales = 0, 0, 0, 0
        fecha_inicial = date(anio_actual, mes_actual, 1)
        fecha_final = date(anio_actual, mes_actual + 1, 1) - timedelta(days=1)
        dias_mes = [fecha_inicial + timedelta(days=i)
                    for i in range((fecha_final - fecha_inicial).days + 1)]

        for dia_actual in dias_mes:
            if dia_actual.day == 1:
                print("   \n" * dia_actual.weekday(), end="")
            if dia_actual in dias_feriados:
                print(f" {dia_actual.strftime('%d/%m/%Y')} Feriado \n", end="")
                contador_feriados += 1  # Incrementar contador
            elif dia_actual in dias_libres:
                print(f" {dia_actual.strftime('%d/%m/%Y')} Libre \n", end="")
                contador_libres += 1  # Incrementar contador
            elif dia_actual in dias_excepcion:
                print(f" {dia_actual.strftime('%d/%m/%Y')} Excepción \n", end="")
                contador_excepcion += 1  # Incrementar contador
            elif dia_actual.weekday() in [dias_laborables.index(dia) for dia in dias_laborables]:
                print(
                    f" {dia_actual.strftime('%d/%m/%Y')} {tag_str+dias_laborables_imprimir[dia_actual.weekday()]} \n", end="")
                contador_laborales += 1  # Incrementar contador
            else:
                print("  Libre(Fin de semana)    \n", end="")

        # Retornar contadores

        return contador_feriados, contador_libres, contador_excepcion, contador_laborales

    else:
        print("Por favor inicie sesión primero")
        # Si no hay usuario actual, retornar 0 en todos los contadores
        return 0


def ver_calendario_admin():
    contador_feriados = globals().get("contador_feriados")
    contador_libres = globals().get(" contador_libres")
    contador_excepcion = globals().get("contador_excepcion")
    contador_laborales = globals().get("contador_laborales")
    usuario_actual = globals().get("usuario_actual")

    # rol_usuario=globals().get("rol_usuario")
    # calendario_usuario=globals().get("calendario_usuario")
    print("Listado de usuarios disponibles: ")
    usuario_seleccionado = listar_usuarios_sistema()
    calendario_actual = cargar_datos_desde_archivo(
        usuario_seleccionado_id['calendario'])
    if usuario_seleccionado:
        usuario_actual = usuario_seleccionado
    else:
        usuario_seleccionado = usuario_actual
    if usuario_actual is not None:
        generar_calendario_laboral()
    else:
        # no deberían ver este mensaje
        print("Por favor inicie sesión primero")


def agregar_sugerencia_calendario(calendario, usuario_seleccionado_sugerencia):
    print("Día Libre autorizado por el sistema de sugerencias: (requiere firma desde RRHH)")
    fecha = solicitar_fecha_d_m_a()
    #  input("Ingrese la fecha de la Libre (formato AAAA-MM-DD): ")
    descripcion = "Libre_autorizado_sistema por sugerencias"
    if not calendario.get('dias_libres'):
        calendario['dias_libres'] = {}
    calendario['dias_libres'][fecha] = descripcion
    guardar_datos_en_archivo_main(
        calendario,  usuario_seleccionado_sugerencia['calendario'])
    print("Libre agregada con éxito.")


def almacenar_sugerencia_libre():
    global usuario_seleccionado_sugerencia
    usuario_seleccionado_sugerencia = listar_usuarios_sistema()
    if usuario_seleccionado_sugerencia:
        print("Calendario de usuario seleccionado:",
              usuario_seleccionado_sugerencia['nombre_de_usuario'])
    calendario_actual = cargar_datos_desde_archivo(
        usuario_seleccionado_sugerencia['calendario'])
    agregar_sugerencia_calendario(
        calendario_actual, usuario_seleccionado_sugerencia)
    print("Recuerde si debe eliminar una sugerencia Autorizada")
    print("puede realizarlo en el menú de los días libres en administración de calendarios")
    print("NOTA: solo se asignan estos días libres a los usuarios que han firmado en RRHH")


def ver_aprobar_rechazar_sugerencias():
    sugerencias = ordenar_sugerencias()

    if not sugerencias:
        print("No hay sugerencias.")
        return

    # Agrupar sugerencias por usuario
    usuarios_sugerencias = {}
    for sugerencia in sugerencias:
        usuario = sugerencia['usuario']
        if usuario not in usuarios_sugerencias:
            usuarios_sugerencias[usuario] = []
        usuarios_sugerencias[usuario].append(sugerencia)

    # Mostrar sugerencias y preguntar por la acción a realizar
    while True:
        print("Sugerencias por usuario:")
        for usuario, sugerencias in usuarios_sugerencias.items():
            print(f"Usuario: {usuario}")
            print("{:<5} | {:<20} | {:<15} | {}".format(
                "ID", "Fecha solicitada", "Estado", "Motivo"))
            for sugerencia in sugerencias:
                print("{:<5} | {:<20} | {:<15} | {}".format(
                    sugerencia['id'], sugerencia['fecha'], sugerencia['estado'], sugerencia['motivo']))
            print()
            # print("idea",usuarios_sugerencias.items())

        try:
            id_seleccionado = int(sanitizar_input(input(
                "Seleccione el ID de la solicitud que desea aprobar o rechazar (Enter para volver al menú principal): ")))
            if not id_seleccionado:
                print("no hay opción seleccionada")
                break
            sugerencia_seleccionada = None
        except:
            print("ingresa un valor válido entre 1 y 10")
            break

        if int(id_seleccionado) < 1 or int(id_seleccionado) > 10:
            print("id inválido")
            continue

        for usuario, sugerencias in usuarios_sugerencias.items():
            for sugerencia in sugerencias:
                if sugerencia['id'] == int(id_seleccionado):
                    sugerencia_seleccionada = sugerencia
                    print("se ha seleccionado la sugerencia")
                    break
                if sugerencia_seleccionada:
                    break

            if not sugerencia_seleccionada:
                print(
                    "ID de solicitud inválido. Por favor, intente nuevamente y seleccione correctamente la información")
                return
                # continue

            print(f"Solicitud {id_seleccionado}")
            print(f"Usuario: {sugerencia_seleccionada['usuario']}")
            print(f"Fecha solicitada: {sugerencia_seleccionada['fecha']}")
            print(f"Solicitud(motivo): {sugerencia_seleccionada['motivo']}")
            print(f"Estado actual: {sugerencia_seleccionada['estado']}")
            import datetime
            fecha1 = datetime.datetime.strptime(
                sugerencia_seleccionada['fecha'], "%Y-%m-%d")
            dia_datetime = fecha1.day
            mes_datetime = fecha1.month
            anio_datetime = fecha1.year
            generar_calendario_mes(dia_datetime, mes_datetime, anio_datetime)

        while True:
            opcion01 = input(
                "Seleccione una opción:\n1. Aprobar solicitud\n2. Rechazar solicitud\n3. Status Pendiente\n4. Mantener estado actual\nOpción: ")
            if opcion01 == '1':
                sugerencia_seleccionada['estado'] = 'Aprobado'
                print(
                    f" Solicitud {sugerencia['id']} \n Usuario: {sugerencia['usuario']}\n Fecha solicitada: {sugerencia['fecha']} \n Estado: {sugerencia['estado']}\n La sugerencia ha sido aprobada.\n ")
                # Opciones disponibles
                print(
                    "la solicitud ha sido modificada a aprobado Opciones disponibles: \n ")
                print("1. Almacenar el día libre respectivo usuario")
                print("2. Volver al menú principal\n")
                # Pedir al usuario que seleccione una opción
                opcion02 = input("Por favor seleccione una opción: ")
                if opcion02 == "1":
                    # TODO: enviar un mensaje al usuario informando que su sugerencia ha sido aprobada
                    # por lo tanto debe firmar la solicitud de día libre en personal, una vez realizado esto, el admin
                    # ya puede almacenar el día libre, ya que las sugerencias pueden no tener relación a algo de salud que puedan pagarle el día trabajado
                    # usuario_seleccionado_sugerencia = sugerencia['usuario']
                    # almacenar_sugerencia_libre()
                    calendario_actual = cargar_datos_desde_archivo(
                        f"database/calendario_{sugerencia['usuario']}.db")
                    # agregar_sugerencia_calendario(calendario_actual,sugerencia['usuario'])
                    print(
                        "Día Libre autorizado por el sistema de sugerencias: (requiere firma desde RRHH)")
                    fecha = sugerencia['fecha']  # solicitar_fecha_d_m_a()
    #  input("Ingrese la fecha de la Libre (formato AAAA-MM-DD): ")
                    descripcion = "Libre_autorizado_sistema por sugerencias"
                    calendario = calendario_actual
                    if not calendario.get('dias_libres'):
                        calendario['dias_libres'] = {}
                    calendario['dias_libres'][fecha] = descripcion
                    guardar_datos_en_archivo_main(
                        calendario, f"database/calendario_{sugerencia['usuario']}.db")
                    print("Libre agregada con éxito.")
                    print("Recuerde si debe eliminar una sugerencia Autorizada")
                    print(
                        "puede realizarlo en el menú de los días libres en administración de calendarios")
                    print(
                        "NOTA: solo se asignan estos días libres a los usuarios que han firmado en RRHH")

                    pass
                elif opcion02 == "2":
                    # Regresar al menú principal
                    print(
                        "volviendo al menú principal, no se ha almacenado el día libre, hasta cuando firme el usuario en RRHH")
                    return
                else:
                    print("Opción inválida.\n")
                return
            elif opcion01 == '2':
                sugerencia_seleccionada['estado'] = 'Rechazado'
                break
            elif opcion01 == '3':
                sugerencia_seleccionada['estado'] = 'Pendiente'
                break
            elif opcion01 == '4':
                break
            else:
                print("Opción inválida. Por favor, intente nuevamente.")

            with open(config_archivo_solicitudes, "w") as archivo:
                json.dump(sugerencias, archivo)
            break
    print("Volviendo al menú principal...")

def menu_administrador():
    print("Menú de administrador")
    print("1. Menu Administración Usuario  \n a. Crear Usuario  \n b. Listar Usuarios   \n c. Eliminar Usuario")
    print("2. Ver calendario(Admin/Usuario_final) por ID ")
    print("3. Sugerencias día Libre de Usuario Final \n a. Por usuario \n b. Por fecha \n c. Por estado \n d. Aprobar/Rechazar Sugerencia ")
    print("4. Feriados \n a. Ver feriados ordenados por fecha \n b. Agregar Feriados \n c. Quitar un feriado")
    print("5. Ver calendario como listado (calendario modo usuario) ")
    print("6. Administración_calendario_personal \n a. Ver el calendario del usuario(Libres-Excepciones-Sugerencias)")
    print(" b. Crear/Resetear calendario de usuario  \n c. Establecer días de excepción \n d. Establecer días libres")
    print(" e. Establecer Sugerencias_aprobadas en libres \n f. Realizar backup del calendario")
    print("7. Disponibilidad  Laboral Total Usuarios por día")
    print("8. Realizar Backup")
    print("9. Cerrar sesión")

def menu_usuario():
    print("Menú de usuario")
    print("1. Ver calendario usuario")
    print("2. Enviar sugerencia de día libre al administrador")
    print("3. Ver Solicitudes realizadas(sugerencias)")
    print("4. Cerrar sesión")

def ver_menu_sugerencias():
    sugerencias = ordenar_sugerencias()

    if sugerencias is not None:
        opciones = {
            0: "Volver al menú principal",
            1: "Ver todas las sugerencias",
            2: "Ver sugerencias por usuario",
            3: "Ver sugerencias por estado",
            4: "Aprobar/rechazar Sugerencias"
        }

        while True:
            print("\nOpciones de visualización de sugerencias:")
            for opcion, descripcion in opciones.items():
                print(f"{opcion}. {descripcion}")

            opcion = input("\nIngrese la opción deseada: ")
            if opcion == "0":
                break
            try:
                opcion = int(opcion)
                if opcion not in opciones:
                    raise ValueError()
            except ValueError:
                print("Opción inválida. Por favor, ingrese un número del 0 al 4.")
                continue

            if opcion == 1:
                print("\nTodas las sugerencias:")
                imprimir_sugerencias(sugerencias)

            elif opcion == 2:
                print("\nSugerencias por usuario:")
                usuarios = set(sugerencia["usuario"]
                               for sugerencia in sugerencias)
                for usuario in usuarios:
                    sugerencias_usuario = [
                        sugerencia for sugerencia in sugerencias if sugerencia["usuario"] == usuario]
                    print(f"Nombre: {usuario}:")
                    imprimir_sugerencias(sugerencias_usuario)

            elif opcion == 3:
                print("\nSugerencias por estado:")
                estados = set(sugerencia["estado"]
                              for sugerencia in sugerencias)
                for estado in estados:
                    sugerencias_estado = [
                        sugerencia for sugerencia in sugerencias if sugerencia["estado"] == estado]
                    print(f"Sugerencias {estado}:")
                    imprimir_sugerencias(sugerencias_estado)
            elif opcion == 4:
                ver_aprobar_rechazar_sugerencias()

    else:
        print("No hay sugerencias.")
        ver_menu_sugerencias()

def imprimir_sugerencias(sugerencias):
    print("{:<5} | {:<20} | {:<15} | {:<20} | {}".format(
        "ID", "Fecha solicitada", "Usuario", "Estado", "Motivo"))
    for sugerencia in sugerencias:
        print("{:<5} | {:<20} | {:<15} | {:<20} | {}".format(
            sugerencia["id"], sugerencia["fecha"], sugerencia["usuario"], sugerencia["estado"], sugerencia["motivo"]))
    print()

# espacio funciones de backup


def backup(src, dst):
    try:
        shutil.copytree(src, dst)
    except:
        print("Error: solo se realiza un backup diario (al final de la jornada) ")


def hacer_backup():
    now = datetime.datetime.now()
    fecha = f"{now.day}-{now.month}-{now.year}_{now.hour}-{now.minute}-{now.second}"
    src1 = ruta_usuario
    dst1 = ruta_usuario + "_" + ruta_backup + "_" + fecha
    backup(src1, dst1)
    src2 = ruta_calendario
    dst2 = ruta_calendario + "_" + ruta_backup + "_" + fecha
    backup(src2, dst2)
    print(
        f"Backup realizado en {ruta_usuario} y {ruta_calendario} con fecha {fecha}")

# fin funciones backup

# funcion de administracion del calendario personal
# opcion 1


def guardar_datos_en_archivo_main(datos, archivo_destino, ruta_usuario=None):
    try:
        if ruta_usuario:
            ruta_calendario = ruta_usuario["calendario"]
        else:
            ruta_calendario = archivo_destino

        with open(ruta_calendario, "w") as f:
            json.dump(datos, f)
        print("Datos guardados exitosamente.")
    except Exception as e:
        print(f"Error al guardar los datos en el archivo: {str(e)}")

 # Menú Administración Calendario personal")
 # 2. Crear/Resetear calendario de usuario")
 #


def resetear_calendario_usuario():
    global ruta_calendario_seleccionado

    usuario_seleccionado_id = listar_usuarios_sistema()
    ruta_calendario_seleccionado = usuario_seleccionado_id['calendario']
    calendario = {
        "dias_libres": [],
        "dias_excepcion": [],
        "sugerencias": []
    }
    guardar_datos_en_archivo_main(calendario, ruta_calendario_seleccionado)


# espacio calendario personal


# calendario personal


def menu_administracion_calendario_personal():

    print("Menú Administración Calendario personal")
    print("1. Ver el calendario del usuario(Libres-Excepciones-Sugerencias)")
    print("2. Crear/Resetear calendario de usuario")
    print("3. Establecer días de excepción")
    print("4. Establecer días libres ")
    print("5. Establecer Sugerencias_aprobadas")
    print("6. Realizar backup del calendario")
    print("7. Volver al menú principal")

    opcion = input("Ingrese una opción: ")
    if opcion == "1":
        ver_calendario_trabajar()
    elif opcion == "2":
        resetear_calendario_usuario()
    elif opcion == "3":
        menu_excepciones()
    elif opcion == "4":
        menu_libres()
    elif opcion == "5":
        ver_menu_sugerencias()
    elif opcion == "6":
        hacer_backup()
    elif opcion == "7":
        return
    else:
        print("Opción inválida")

# Menu Administrador (1) menú de administración Usuarios


def menu_administracion_usuarios():

    print("Menú Administración Usuarios")
    print("1. Crear Usuario \n2. Listar Usuarios\n3. Eliminar Usuario\n4. Volver al menu Principal")

    opcion = input("Ingrese una opción: ")
    if opcion == "1":
        crear_usuario()
    elif opcion == "2":
        listar_usuarios()
    elif opcion == "3":
        eliminar_usuario()
    elif opcion == "4":
        return
    else:
        print("Opción inválida")

 # Menú Administración Calendario personal")
 # 1. Ver el calendario del usuario(Libres-Excepciones-Sugerencias)")


def ver_calendario_trabajar():
    global calendario_actual
    usuario_seleccionado_id = listar_usuarios_sistema()
    calendario_actual = cargar_datos_desde_archivo(
        usuario_seleccionado_id['calendario'])
    if calendario_actual is None:
        print("No se ha seleccionado ningún calendario. Seleccionando calendario...")
        usuario_seleccionado_id = listar_usuarios_sistema()
    else:
        print(
            f"El calendario seleccionado contiene lo siguiente \n {calendario_actual}")

    return calendario_actual

# inicio de la opcion 7 (establece calendario de todos los usuarios y disponibilidad laboral)


def generar_disponibilidad_mes():
    # Pedir el mes y año al usuario
    mes_ingresado = int(input("Por favor ingrese el mes (formato MM): "))
    year_ingresado = int(input("Por favor ingrese el año (formato AAAA): "))
    ultimo_dia = calendar.monthrange(year_ingresado, mes_ingresado)[1]
    # print(f"tiene: {ultimo_dia} dias")
    # Cargar los usuarios
    # usuarios_dir_R = "usuarios"
    # usuarios_r = os.listdir(usuarios_dir_R)

    # Cargar los días feriados
    if os.path.isfile(nombre_feriado):
        with open(nombre_feriado, "r") as f:
            dias_feriados = json.load(f)["dias_feriados"]
    else:
        dias_feriados = []
    # Contar la disponibilidad de cada usuario para cada día del mes

    disponibilidad = {day: {"T": 0, "L": 0, "E": 0, "F": 0}
                      for day in range(1, ultimo_dia + 1)}
    usuarios3 = cargar_datos_desde_archivo(ruta_usuario+"/"+database_usuarios)
    for usuario_id, datos_usuario in usuarios3.items():
        # capacidad de validar si está haciendo bien el recorrido de los usuarios
        # print(f"ID: {usuario_id}, Nombre de usuario: {datos_usuario['nombre_de_usuario']} Rol: {datos_usuario['rol']}")
        calendario_usuario = datos_usuario['calendario']
        if os.path.isfile(calendario_usuario):
            with open(calendario_usuario, "r") as f:
                calendario = json.load(f)
        dias_libres = calendario.get("dias_libres", [])
        # dias_sugerencias_aprobadas = calendario.get("sugerencias", [])
        dias_excepcion = calendario.get("dias_excepcion", [])
        # esto no existe pero al menos es una idea
        estados = calendario.get("dias_laborales", {})
        for day in range(1, ultimo_dia + 1):
            # Obtener el día de la semana
            fecha = datetime(int(year_ingresado), int(mes_ingresado), day)
            fecha_formateada = fecha.strftime("%Y-%m-%d")
            if any(f["fecha"] == f"{year_ingresado}-{mes_ingresado:02d}-{day:02d}" for f in dias_feriados):
                # print(f"{dia:02d}[F]", end=" ")
                disponibilidad[day]["F"] += 1
                continue
                # contador_feriados += 1
            elif any(d == f"{year_ingresado}-{mes_ingresado:02d}-{day:02d}" for d in dias_libres):
                disponibilidad[day]["L"] += 1
                continue
            # print(f"{dia:02d}[L]", end=" ")
            # contador_libres += 1
            elif fecha.weekday() < 5:  # si el día es laboral (Lun a Vie)
                disponibilidad[day]["T"] += 1
                # aqui se podría armar una nuevo diccionario que considere por usuario, el día que trabaja
                # print( f"dia: {year_ingresado}-{mes_ingresado:02d}-{day:02d}  id:{usuario_id} nombre: {datos_usuario['nombre_de_usuario']}")
                # print(f"dia sem {fecha.weekday()}")
                continue
            # print(f"{dia:02d}[T]", end=" ")
            # contador_laborales += 1
            else:
                # print(f"{dia:02d}[L]", end=" ")  # si es fin de semana
                disponibilidad[day]["L"] += 1
                continue

    # Contar la disponibilidad del usuario para este día
    # Mostrar la tabla de disponibilidad
    meses = {
        1: "enero",
        2: "febrero",
        3: "marzo",
        4: "abril",
        5: "mayo",
        6: "junio",
        7: "julio",
        8: "agosto",
        9: "septiembre",
        10: "octubre",
        11: "noviembre",
        12: "diciembre"
    }
    nombre_mes = meses[mes_ingresado]
    print(f"Calendario de {nombre_mes.capitalize()} {year_ingresado}")
    print("-------------------------------------------------------------")
    print(("{:<4} |  {:<10} | {:<30} | {:<15}").format("Dia", "Fecha",
          "Disponibilidad de usuarios", "Total usuarios disponibles"))
    print("-------------------------------------------------------------")

    for day in range(1, ultimo_dia+1):
        if day in disponibilidad:
            fecha = f"{year_ingresado}-{mes_ingresado}-{day:02d}"
            disponible_s = disponibilidad[day]["T"]
            libre = disponibilidad[day]["L"]
            excepcio_n = disponibilidad[day]["E"]
            feriado_s = disponibilidad[day]["F"]
            total = disponible_s + libre + excepcio_n + feriado_s
            days = ["Lun", "Mar", "Mie", "Jue", "Vie", "Sab", "Dom"]
            dia_sem_actual = days[datetime(
                year_ingresado, mes_ingresado, day, 00, 00, 00).weekday()]
            if total > 0:
                disp_str = ""
            if disponible_s > 0:
                disp_str += f"[T]({disponible_s} disponible)"
                # print( f"dia: {year_ingresado}-{mes_ingresado:02d}-{day:02d}  id:{usuario_id} nombre: {datos_usuario['nombre_de_usuario']}")
                # print(f"dia sem {dia_sem_actual}")
            if feriado_s > 0:
                disp_str += f"[F]({feriado_s} Feriado)"
            if libre > 0:
                disp_str += f"[L]({libre} Libre)"
            if excepcio_n > 0:
                disp_str += f"[E]({excepcio_n} Excepción)"
        if ultimo_dia+1 == day:
            print("llegamos a ultimo dia")
            print(
                f"dia: {year_ingresado}-{mes_ingresado:02d}-{day:02d}  id:{usuario_id} nombre: {datos_usuario['nombre_de_usuario']}")
            print(f"dia sem {dia_sem_actual}")
            continue
        print(("{:<4} |  {:<10} | {:<30} | {:<15}").format(
            dia_sem_actual, fecha, disp_str, disponible_s))  # total))
    print("-------------------------------------------------------------")
    print(f"Leyenda: \n")
    print(f"[F]=Feriados    \n[L]=Libre       \n[E]=Excepción   \n[T]=Día laboral \n")


# Definimos menú principal
# permite login
# permite definir el rol y según ese llevará a 2 calendarios
# menu_administrador()
# menu_usuario()

def menu_principal():
    print(" Menú principal \n 1. Iniciar sesión \n 2. Salir ")
    opcion = input("Ingrese la opción: ")
    if opcion == "1":
        iniciar_sesion()
    elif opcion == "2":
        print("Gracias por utilizar Menú Laboral")
        exit()
    else:
       # print("Esperando opción Menu_principal")
        menu_principal()
    while True:
        if usuario_actual is not None:
            if rol_usuario == "administrador":
                menu_administrador()
                print("Opciones de administrador")
                opcion = input("Ingrese la opción: ")
                if opcion == "1":
                    menu_administracion_usuarios()
                if opcion == "2":
                    ver_calendario_admin()
                if opcion == "3":
                    ver_menu_sugerencias()
                if opcion == "4":
                    menu_mostrar_feriados()
                if opcion == "5":
                    generar_calendario_laboral()
                if opcion == "6":
                    menu_administracion_calendario_personal()
                if opcion == "7":
                    generar_disponibilidad_mes()
                if opcion == "8":
                    hacer_backup()
                elif opcion == "9":
                    cerrar_sesion(usuario_actual, rol_usuario,
                                  calendario_usuario)
                    break
                else:
                    print()
            else:
                menu_usuario()
                opcion = input("Ingrese la opción: ")
                if opcion == "1":
                    ver_calendario()
                if opcion == "2":
                    ver_sugerencias()
                if opcion == "3":
                    ver_solicitudes()
                elif opcion == "4":
                    cerrar_sesion(usuario_actual, rol_usuario,
                                  calendario_usuario)
                    break
                else:
                    print()
        else:
            print()  # "Por favor inicie sesión primero"
            break

# manejamos un cerrar sesión y que se lleve las variables de usuario mas importante o no


def cerrar_sesion(usuario_actual, rol_usuario, calendario_usuario):
    print("¿Está seguro de que desea salir del programa?\n 1. Sí (cerrar sesión y salir) \n 2. No (volver al menú principal) \n")

    while True:
        opcion = input("Elija una opción: ")
        if opcion == "1":
            print(f"\n¡Hasta pronto, {usuario_actual}!\n")
            # Devuelve los valores iniciales para los argumentos de la función.
            # al inicio las dejé en none, pero prefiero cerrarlo abruptamente y evitar inyección
            exit()
            # return None, None, None

        elif opcion == "2":
            menu_principal()
            return usuario_actual, rol_usuario, calendario_usuario
        else:
            print("\nOpción inválida, por favor inténtelo de nuevo.\n")
            # al inicio las dejé en none, pero prefiero cerrarlo abruptamente
            # return None, None, None
            exit()


# este es el inicio de todo, necesito tener usuarios y además crearle usuarios , pero está mejor en un script aparte, por eso, se deja aparte, ya que es funcional.
#def primer_uso():
 #   crear_archivo_usuarios()  # comenzar
 #   crear_usuario()  # crear admin
 #   crear_usuario()  # crear usuario/
 #   print()


def main():

    bienvenida()  # este proviene de banner, muestra el menú
menu_principal()  # establezco el menú principal


if __name__ == "__main__":

    main()
