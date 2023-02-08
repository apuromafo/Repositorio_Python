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

