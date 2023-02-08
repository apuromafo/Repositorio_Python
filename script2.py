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


import calendar
#mostraremos el año actual
print(calendar.LocaleTextCalendar(locale='es').formatyear(2023))

#imagino que necesitamos al menos 2 clases una para el calendario laboral y otra para la cuenta


"""  clase llamada "CalendarioLaboral"  debe considerar
• Días de trabajo: una lista de enteros que representan los días de la semana en que los usuarios estarán trabajando.
• Feriados: una lista de enteros que representan los días de la semana en que los usuarios tendrán días libres.
• Mínimo personal: un entero que representa el número mínimo de personas necesarias para trabajar en un día en que haya un feriado.
• Usuarios: una lista de usuarios, donde cada usuario tendrá sus propios días de trabajo y feriados asignados.

una clase llamada "Cuenta/usuario" que tendrá los siguientes atributos:

• Nombre: una cadena que representa el nombre del usuario.
• Días de trabajo: una lista de enteros que representan los días de la semana en que el usuario estará trabajando.
• Feriados: una lista de enteros que representan los días de la semana en que el usuario tendrá días libres.
• Sugerencias: una lista de sugerencias que el usuario puede enviar al administrador para solicitar días libres.
"""
#luego necesitaré funciones que se activen al ir a estos menús

"""
función llamada "actualizarCalendario()" que 
se encargará de actualizar el calendario con los cambios realizados por el administrador. 
Esta función se ejecutará cada vez que el administrador modifique el calendario.


una función llamada "verCalendario()" que 
se encarga de mostrar el calendario laboral a los usuarios. Esta función recibe como parámetro el nombre de un usuario y
 mostrará su calendario laboral.

una función de "configurarpermisos()" , que valide a cual de las 2 mostrará (como usuario o como admin)  
"""

#finalmente me falta pensar en la interfaz, donde tendríamos que ser capaz de agregar, editar o eliminar usuarios
#y por otro lado que puedan asignar los días

#sobre las personas que usen esto, deberán tener la capacidad de consultar su
# calendario y enviar sugerencias al administrador. 
#y el administrador en cuanto abra su cuenta, podrá leer estas sugerencias.
#esto es mas menos lo que imagino
 

 */

