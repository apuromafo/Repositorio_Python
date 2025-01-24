#!/usr/bin/env python

description = 'Pequeño script para ver la rutina diaria'
author = 'Apuromafo'
version = '0.0.1'
date = '22.01.2025'
# ======================================
from datetime import datetime, timedelta

def print_time(activity, time):
    """Imprime la actividad y la hora en formato legible."""
    print(f"{activity}: {time.strftime('%I:%M %p')}")

def simulate_day():
    # Inicio del día
    print("\n--- Inicio del día ---")
    wake_up_time = datetime.now().replace(hour=7, minute=0, second=0, microsecond=0)
    print_time("Despertarse", wake_up_time)

    # Rutina matutina
    shower_time = wake_up_time + timedelta(minutes=30)
    print_time("Ducharse", shower_time)

    change_clothes_time = shower_time + timedelta(minutes=15)
    print_time("Cambiarse de ropa", change_clothes_time)

    # Entrar al trabajo o actividad
    start_work_time = change_clothes_time.replace(hour=9, minute=0)
    print_time("Entrar al trabajo/actividad", start_work_time)

    # Modo almuerzo o hambre
    lunch_time = start_work_time + timedelta(hours=4)
    print_time("Hora de almuerzo", lunch_time)

    # Salir del trabajo o actividad principal
    end_work_time = start_work_time.replace(hour=18, minute=0)
    print_time("Salir del trabajo/actividad principal", end_work_time)

    # Tiempo de estudio opcional
    while True:
        study = input("¿Quieres estudiar después de las 6pm? (sí/no): ").strip().lower()
        if study in ["sí", "si", "s", "y", "yes"]:
            study_time = end_work_time + timedelta(hours=4)
            print_time("Terminar de estudiar", study_time)
            break
        elif study in ["no", "n"]:
            print("No hay estudio hoy.")
            break
        else:
            print("Por favor, responde con 'sí' o 'no'.")

    # Fin del día
    print("\n--- Fin del día ---")

if __name__ == "__main__":
    simulate_day()