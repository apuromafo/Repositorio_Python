#!/usr/bin/env python
descripcion = 'Pequeño script para ver la rutina diaria y el calendario laboral'
autor = 'Apuromafo'
version = '0.0.2'
fecha = '22.01.2025'

# ======================================
from datetime import datetime, timedelta
import calendar

# Lista de feriados legales de Chile para 2025
feriados_chile_2025 = [
    "2025-01-01",  # Año Nuevo
    "2025-04-18",  # Viernes Santo
    "2025-05-01",  # Día del Trabajador
    "2025-05-21",  # Día de las Glorias Navales
    "2025-06-29",  # San Pedro y San Pablo (trasladable)
    "2025-07-16",  # Día de la Virgen del Carmen
    "2025-08-15",  # Asunción de la Virgen
    "2025-09-18",  # Fiestas Patrias
    "2025-09-19",  # Día de las Glorias del Ejército
    "2025-10-12",  # Encuentro de Dos Mundos (trasladable)
    "2025-11-01",  # Día de Todos los Santos
    "2025-11-29",  # Día de la Iglesia Evangélica
    "2025-12-08",  # Inmaculada Concepción
    "2025-12-25",  # Navidad
]

# Diccionario para traducir los nombres de los meses al español
meses_espanol = {
    1: "Enero",
    2: "Febrero",
    3: "Marzo",
    4: "Abril",
    5: "Mayo",
    6: "Junio",
    7: "Julio",
    8: "Agosto",
    9: "Septiembre",
    10: "Octubre",
    11: "Noviembre",
    12: "Diciembre"
}

def imprimir_hora(actividad, hora):
    """Imprime la actividad y la hora en formato legible."""
    print(f"{actividad}: {hora.strftime('%I:%M %p')}")

def validar_hora_actual(hora_actual, hora_actividad, nombre_actividad):
    """
    Valida si la actividad ya ocurrió o está por ocurrir.
    Retorna True si la actividad está por ocurrir, False si ya ocurrió.
    """
    if hora_actual < hora_actividad:
        imprimir_hora(f"Próxima actividad: {nombre_actividad}", hora_actividad)
        return True
    else:
        imprimir_hora(f"Actividad ya realizada: {nombre_actividad}", hora_actividad)
        return False

def generar_mini_calendario():
    """Genera un mini calendario ASCII del mes actual y resalta el día actual."""
    ahora = datetime.now()
    año_actual = ahora.year
    mes_actual = ahora.month
    dia_actual = ahora.day

    # Personalizar los nombres de los días en español
    dias_semana_espanol = ["Lu", "Ma", "Mi", "Ju", "Vi", "Sa", "Do"]

    # Crear un calendario personalizado con nombres en español
    cal = calendar.TextCalendar(calendar.MONDAY)
    calendario_mes = cal.formatmonth(año_actual, mes_actual)

    # Reemplazar los nombres de los días en inglés por los nombres en español
    lineas_calendario = calendario_mes.split("\n")
    lineas_calendario[1] = " ".join(dias_semana_espanol)  # Reemplazar la línea de los días

    # Traducir el nombre del mes al español
    nombre_mes_espanol = meses_espanol[mes_actual]
    lineas_calendario[0] = f"   {nombre_mes_espanol} {año_actual}"

    # Resaltar el día actual con corchetes ([XX])
    for i, linea in enumerate(lineas_calendario):
        if str(dia_actual) in linea:
            linea_modificada = ""
            for parte in linea.split():
                if parte == str(dia_actual):
                    linea_modificada += f"[{parte}] "
                else:
                    linea_modificada += f"{parte} "
            lineas_calendario[i] = linea_modificada.strip()

    # Reconstruir el calendario modificado
    calendario_modificado = "\n".join(lineas_calendario)

    # Mostrar el calendario
    print("\n--- Mini Calendario ---")
    print(calendario_modificado)

    # Determinar si el día actual es laboral
    dia_semana = ahora.weekday()  # Lunes=0, Domingo=6
    fecha_actual_str = ahora.strftime("%Y-%m-%d")
    es_laboral = dia_semana < 5 and fecha_actual_str not in feriados_chile_2025

    # Mostrar si el día es laboral o no
    if es_laboral:
        print("Hoy es un día laboral.")
    else:
        print("Hoy NO es un día laboral.")

def simular_dia():
    # Obtener la hora actual
    ahora = datetime.now()
    print("\n--- Simulación de rutina diaria ---")
    print(f"Hora actual: {ahora.strftime('%I:%M %p')}\n")

    # Inicio del día
    hora_despertarse = ahora.replace(hour=7, minute=0, second=0, microsecond=0)
    if validar_hora_actual(ahora, hora_despertarse, "Despertarse"):
        return

    # Rutina matutina
    hora_ducharse = hora_despertarse + timedelta(minutes=30)
    if validar_hora_actual(ahora, hora_ducharse, "Ducharse"):
        return

    hora_cambiarse_ropa = hora_ducharse + timedelta(minutes=15)
    if validar_hora_actual(ahora, hora_cambiarse_ropa, "Cambiarse de ropa"):
        return

    # Entrar al trabajo o actividad
    hora_empezar_trabajo = ahora.replace(hour=9, minute=0, second=0, microsecond=0)
    if validar_hora_actual(ahora, hora_empezar_trabajo, "Entrar al trabajo/actividad"):
        return

    # Modo almuerzo o hambre
    hora_almuerzo = hora_empezar_trabajo + timedelta(hours=4)
    if validar_hora_actual(ahora, hora_almuerzo, "Hora de almuerzo"):
        return

    # Salir del trabajo o actividad principal
    hora_salir_trabajo = ahora.replace(hour=18, minute=0, second=0, microsecond=0)
    if validar_hora_actual(ahora, hora_salir_trabajo, "Salir del trabajo/actividad principal"):
        return

    # Tiempo de estudio opcional
    hora_estudio = hora_salir_trabajo + timedelta(hours=4)
    while True:
        estudiar = input("¿Quieres estudiar después de las 6pm? (sí/no): ").strip().lower()
        if estudiar in ["sí", "si", "s", "y", "yes"]:
            if ahora >= hora_estudio:
                imprimir_hora("Ya terminaste de estudiar", hora_estudio)
            else:
                imprimir_hora("Terminar de estudiar", hora_estudio)
            break
        elif estudiar in ["no", "n"]:
            print("No hay estudio hoy.")
            break
        else:
            print("Por favor, responde con 'sí' o 'no'.")

    # Fin del día
    if ahora >= hora_estudio:
        print("\n--- ¡El día ha terminado y todas las actividades han sido completadas! ---")
    else:
        print("\n--- Fin del día ---")

if __name__ == "__main__":
    generar_mini_calendario()
    simular_dia()
    