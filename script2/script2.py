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
  
"""
