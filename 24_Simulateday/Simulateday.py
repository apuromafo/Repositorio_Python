#!/usr/bin/env python
descripcion = 'Pequeño script para ver la rutina diaria y el calendario laboral'
autor = 'Apuromafo'
version = '0.0.7' # Versión actualizada: Muestra el día de la semana del próximo feriado
fecha = '11.08.2025' # Fecha de última actualización

# ======================================
import datetime
from datetime import timedelta
import calendar
from unittest.mock import patch
import argparse # Importamos el módulo para manejar argumentos de línea de comandos

# --- Función para simular el tiempo (Faketime) ---
def create_faketime_context(year, month, day, hour=0, minute=0, second=0):
    """
    Crea un gestor de contexto que temporalmente establece la fecha y hora actual
    a una hora 'falsa' especificada.

    Uso:
    with create_faketime_context(2025, 7, 16, 10, 30):
        # Tu código sensible a la fecha aquí verá la hora falsa
        print(datetime.datetime.now()) # Usará la hora falsa
    # Fuera del bloque 'with', datetime.datetime.now() vuelve a funcionar normalmente
    """
    fake_now = datetime.datetime(year, month, day, hour, minute, second)

    class FakeDatetime(datetime.datetime):
        @classmethod
        def now(cls, tz=None):
            return fake_now

    # Usamos unittest.mock.patch para reemplazar datetime.datetime temporalmente
    return patch('datetime.datetime', FakeDatetime)

# --- FIN de la función Faketime ---

# ==============================================================================
# Lista de feriados legales de Chile para 2025-2030
# Nota: Algunos feriados son trasladables o pueden cambiar por ley.
# Esta lista se basa en la información histórica y proyecciones comunes.
# =ocionalmente se recomienda que esta lista sea obtenida de una API externa.
# ==============================================================================
feriados_chile_extendidos = [
    # Feriados 2025
    {"fecha": "2025-01-01", "nombre": "Año Nuevo"},
    {"fecha": "2025-04-18", "nombre": "Viernes Santo"},
    {"fecha": "2025-05-01", "nombre": "Día del Trabajador"},
    {"fecha": "2025-05-21", "nombre": "Día de las Glorias Navales"},
    {"fecha": "2025-06-29", "nombre": "San Pedro y San Pablo (trasladable) elección primaria presidencial (irrenunciable de segunda categoría)"},
    {"fecha": "2025-07-16", "nombre": "Día de la Virgen del Carmen"},
    {"fecha": "2025-08-15", "nombre": "Asunción de la Virgen"},
    {"fecha": "2025-08-20", "nombre": "5 Nacimiento del Prócer de la Independencia (válido solamente en las comunas de Chillán y Chillán Viejo"},
    {"fecha": "2025-09-18", "nombre": "Fiestas Patrias(Día de la Independencia)"},
    {"fecha": "2025-09-19", "nombre": "Día de las Glorias del Ejército(Día de las Fuerzas Armadas)"},
    {"fecha": "2025-10-12", "nombre": "Encuentro de Dos Mundos (Día de la Raza)"},
    {"fecha": "2025-10-31", "nombre": "Día Nacional de las Iglesias Evangélicas y Protestantes (feriado religioso)"},
    {"fecha": "2025-11-01", "nombre": "Día de Todos los Santos"},
    {"fecha": "2025-11-16", "nombre": "elecciones presidencial (primera vuelta) y congresistas (irrenunciable de segunda categoría"},
    {"fecha": "2025-11-29", "nombre": "Día de la Iglesia Evangélica"},
    {"fecha": "2025-12-08", "nombre": "Inmaculada Concepción"},
    {"fecha": "2025-12-14", "nombre": "elección presidencial (segunda vuelta) (irrenunciable de segunda categoría) (el que este feriado tenga lugar dependerá de la primera vuelta de esta elección)"},
    {"fecha": "2025-12-25", "nombre": "Navidad"},
    #miércoles 31/12/2025 feriado bancario de fin de año (derogado en 01/08/2025)
    # Feriados 2026
    {"fecha": "2026-01-01", "nombre": "Año Nuevo"},
    {"fecha": "2026-04-03", "nombre": "Viernes Santo"},
    {"fecha": "2026-05-01", "nombre": "Día del Trabajador"},
    {"fecha": "2026-05-21", "nombre": "Día de las Glorias Navales"},
    {"fecha": "2026-06-29", "nombre": "San Pedro y San Pablo (trasladable)"},
    {"fecha": "2026-07-16", "nombre": "Día de la Virgen del Carmen"},
    {"fecha": "2026-08-15", "nombre": "Asunción de la Virgen"},
    {"fecha": "2026-09-18", "nombre": "Fiestas Patrias"},
    {"fecha": "2026-09-19", "nombre": "Día de las Glorias del Ejército"},
    {"fecha": "2026-10-12", "nombre": "Encuentro de Dos Mundos (trasladable)"},
    {"fecha": "2026-11-01", "nombre": "Día de Todos los Santos"},
    {"fecha": "2026-11-29", "nombre": "Día de la Iglesia Evangélica"},
    {"fecha": "2026-12-08", "nombre": "Inmaculada Concepción"},
    {"fecha": "2026-12-25", "nombre": "Navidad"},

    # Feriados 2027
    {"fecha": "2027-01-01", "nombre": "Año Nuevo"},
    {"fecha": "2027-03-26", "nombre": "Viernes Santo"},
    {"fecha": "2027-05-01", "nombre": "Día del Trabajador"},
    {"fecha": "2027-05-21", "nombre": "Día de las Glorias Navales"},
    {"fecha": "2027-06-29", "nombre": "San Pedro y San Pablo (trasladable)"},
    {"fecha": "2027-07-16", "nombre": "Día de la Virgen del Carmen"},
    {"fecha": "2027-08-15", "nombre": "Asunción de la Virgen"},
    {"fecha": "2027-09-18", "nombre": "Fiestas Patrias"},
    {"fecha": "2027-09-19", "nombre": "Día de las Glorias del Ejército"},
    {"fecha": "2027-10-12", "nombre": "Encuentro de Dos Mundos (trasladable)"},
    {"fecha": "2027-11-01", "nombre": "Día de Todos los Santos"},
    {"fecha": "2027-11-29", "nombre": "Día de la Iglesia Evangélica"},
    {"fecha": "2027-12-08", "nombre": "Inmaculada Concepción"},
    {"fecha": "2027-12-25", "nombre": "Navidad"},
    
    # Feriados 2028
    {"fecha": "2028-01-01", "nombre": "Año Nuevo"},
    {"fecha": "2028-04-14", "nombre": "Viernes Santo"},
    {"fecha": "2028-05-01", "nombre": "Día del Trabajador"},
    {"fecha": "2028-05-21", "nombre": "Día de las Glorias Navales"},
    {"fecha": "2028-06-29", "nombre": "San Pedro y San Pablo (trasladable)"},
    {"fecha": "2028-07-16", "nombre": "Día de la Virgen del Carmen"},
    {"fecha": "2028-08-15", "nombre": "Asunción de la Virgen"},
    {"fecha": "2028-09-18", "nombre": "Fiestas Patrias"},
    {"fecha": "2028-09-19", "nombre": "Día de las Glorias del Ejército"},
    {"fecha": "2028-10-12", "nombre": "Encuentro de Dos Mundos (trasladable)"},
    {"fecha": "2028-11-01", "nombre": "Día de Todos los Santos"},
    {"fecha": "2028-11-29", "nombre": "Día de la Iglesia Evangélica"},
    {"fecha": "2028-12-08", "nombre": "Inmaculada Concepción"},
    {"fecha": "2028-12-25", "nombre": "Navidad"},

    # Feriados 2029
    {"fecha": "2029-01-01", "nombre": "Año Nuevo"},
    {"fecha": "2029-03-30", "nombre": "Viernes Santo"},
    {"fecha": "2029-05-01", "nombre": "Día del Trabajador"},
    {"fecha": "2029-05-21", "nombre": "Día de las Glorias Navales"},
    {"fecha": "2029-06-29", "nombre": "San Pedro y San Pablo (trasladable)"},
    {"fecha": "2029-07-16", "nombre": "Día de la Virgen del Carmen"},
    {"fecha": "2029-08-15", "nombre": "Asunción de la Virgen"},
    {"fecha": "2029-09-18", "nombre": "Fiestas Patrias"},
    {"fecha": "2029-09-19", "nombre": "Día de las Glorias del Ejército"},
    {"fecha": "2029-10-12", "nombre": "Encuentro de Dos Mundos (trasladable)"},
    {"fecha": "2029-11-01", "nombre": "Día de Todos los Santos"},
    {"fecha": "2029-11-29", "nombre": "Día de la Iglesia Evangélica"},
    {"fecha": "2029-12-08", "nombre": "Inmaculada Concepción"},
    {"fecha": "2029-12-25", "nombre": "Navidad"},

    # Feriados 2030
    {"fecha": "2030-01-01", "nombre": "Año Nuevo"},
    {"fecha": "2030-04-19", "nombre": "Viernes Santo"},
    {"fecha": "2030-05-01", "nombre": "Día del Trabajador"},
    {"fecha": "2030-05-21", "nombre": "Día de las Glorias Navales"},
    {"fecha": "2030-06-29", "nombre": "San Pedro y San Pablo (trasladable)"},
    {"fecha": "2030-07-16", "nombre": "Día de la Virgen del Carmen"},
    {"fecha": "2030-08-15", "nombre": "Asunción de la Virgen"},
    {"fecha": "2030-09-18", "nombre": "Fiestas Patrias"},
    {"fecha": "2030-09-19", "nombre": "Día de las Glorias del Ejército"},
    {"fecha": "2030-10-12", "nombre": "Encuentro de Dos Mundos (trasladable)"},
    {"fecha": "2030-11-01", "nombre": "Día de Todos los Santos"},
    {"fecha": "2030-11-29", "nombre": "Día de la Iglesia Evangélica"},
    {"fecha": "2030-12-08", "nombre": "Inmaculada Concepción"},
    {"fecha": "2030-12-25", "nombre": "Navidad"},
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

# Diccionario para traducir los nombres de los días de la semana al español
dias_semana_espanol = {
    0: "Lunes",
    1: "Martes",
    2: "Miércoles",
    3: "Jueves",
    4: "Viernes",
    5: "Sábado",
    6: "Domingo"
}

def imprimir_hora(actividad, hora):
    """Imprime la actividad y la hora en formato legible."""
    print(f"{actividad}: {hora.strftime('%I:%M %p')}")

def encontrar_proximo_feriado_mes_actual():
    """
    Encuentra el feriado más cercano en el mes actual que aún no ha ocurrido
    y devuelve la información completa, incluyendo el día de la semana.
    """
    ahora = datetime.datetime.now()
    hoy_date = ahora.replace(hour=0, minute=0, second=0, microsecond=0)
    
    proximo_feriado = None
    
    feriados_mes_actual = []
    for feriado_info in feriados_chile_extendidos: # Usamos la lista extendida
        fecha_feriado_dt = datetime.datetime.strptime(feriado_info["fecha"], "%Y-%m-%d")
        if fecha_feriado_dt.year == ahora.year and fecha_feriado_dt.month == ahora.month:
            if fecha_feriado_dt >= hoy_date:
                # Agregamos el día de la semana al diccionario
                feriado_info["dia_semana"] = dias_semana_espanol[fecha_feriado_dt.weekday()]
                feriados_mes_actual.append(feriado_info)
    
    feriados_mes_actual.sort(key=lambda x: datetime.datetime.strptime(x["fecha"], "%Y-%m-%d"))

    if feriados_mes_actual:
        proximo_feriado = feriados_mes_actual[0]
            
    return proximo_feriado


def generar_mini_calendario():
    """Genera un mini calendario ASCII del mes actual y resalta el día actual."""
    ahora = datetime.datetime.now()
    año_actual = ahora.year
    mes_actual = ahora.month
    dia_actual = ahora.day

    dias_semana_espanol_abrev = ["Lu", "Ma", "Mi", "Ju", "Vi", "Sa", "Do"]

    cal = calendar.TextCalendar(calendar.MONDAY)
    calendario_mes = cal.formatmonth(año_actual, mes_actual)

    lineas_calendario = calendario_mes.split("\n")
    lineas_calendario[1] = " ".join(dias_semana_espanol_abrev)

    nombre_mes_espanol = meses_espanol[mes_actual]
    lineas_calendario[0] = f"    {nombre_mes_espanol} {año_actual}"

    import re
    for i, linea in enumerate(lineas_calendario):
        linea_modificada_partes = []
        matches = list(re.finditer(r'\b\d{1,2}\b', linea))
        
        last_idx = 0
        for match in matches:
            num_str = match.group(0)
            num_int = int(num_str)
            start, end = match.span()

            linea_modificada_partes.append(linea[last_idx:start])

            if num_int == dia_actual:
                linea_modificada_partes.append(f"[{num_str}]")
            else:
                linea_modificada_partes.append(num_str)
            last_idx = end
        
        linea_modificada_partes.append(linea[last_idx:])

        temp_line = "".join(linea_modificada_partes)
        
        temp_line = re.sub(r'(\s*)\[(\d{1,2})\](\s*)', r' [\2] ', temp_line)
        temp_line = re.sub(r' {2,}', ' ', temp_line).strip()
        
        if dia_actual < 10:
            parts = temp_line.split(' ')
            for j, part in enumerate(parts):
                if f"[{dia_actual}]" == part:
                    if j > 0 and len(parts[j-1]) == 1 and parts[j-1].isdigit():
                        parts[j-1] = parts[j-1] + " "
                    elif j == 0:
                        temp_line = " " + temp_line
            temp_line = " ".join(parts).strip()
            if not temp_line.startswith("[") and temp_line.startswith(" "):
                    temp_line = temp_line.strip()

        lineas_calendario[i] = temp_line


    calendario_modificado = "\n".join(lineas_calendario)

    print("\n--- Mini Calendario ---")
    print(calendario_modificado)

    dia_semana = ahora.weekday()
    
    # Usamos la lista extendida de feriados
    fechas_feriados_str = [f["fecha"] for f in feriados_chile_extendidos]
    fecha_actual_str = ahora.strftime("%Y-%m-%d")
    es_laboral = dia_semana < 5 and fecha_actual_str not in fechas_feriados_str

    if es_laboral:
        print("Hoy es un día laboral.")
    else:
        print("Hoy NO es un día laboral.")

    proximo_feriado = encontrar_proximo_feriado_mes_actual()
    if proximo_feriado:
        fecha_prox_feriado = datetime.datetime.strptime(proximo_feriado["fecha"], "%Y-%m-%d")
        # Aquí es donde se usa la nueva información del día de la semana
        print(f"Próximo feriado en el mes: {proximo_feriado['nombre']} ({proximo_feriado['dia_semana']}, {fecha_prox_feriado.day} de {meses_espanol[fecha_prox_feriado.month]})")
    else:
        print("No hay feriados restantes este mes.")

def simular_dia():
    ahora = datetime.datetime.now()
    print("\n--- Simulación de rutina diaria ---")
    print(f"Hora actual: {ahora.strftime('%I:%M %p')}\n")

    actividades = [
        {"nombre": "Despertarse", "hora": ahora.replace(hour=7, minute=0, second=0, microsecond=0)},
        {"nombre": "Ducharse", "hora": ahora.replace(hour=7, minute=30, second=0, microsecond=0)},
        {"nombre": "Cambiarse de ropa", "hora": ahora.replace(hour=7, minute=45, second=0, microsecond=0)},
        {"nombre": "Entrar al trabajo/actividad", "hora": ahora.replace(hour=9, minute=0, second=0, microsecond=0)},
        {"nombre": "Hora de almuerzo", "hora": ahora.replace(hour=13, minute=0, second=0, microsecond=0)},
        {"nombre": "Salir del trabajo/actividad principal", "hora": ahora.replace(hour=18, minute=0, second=0, microsecond=0)},
        {"nombre": "Terminar de estudiar", "hora": ahora.replace(hour=22, minute=0, second=0, microsecond=0)}
    ]

    alguna_actividad_futura = False
    for actividad in actividades:
        if ahora < actividad["hora"]:
            imprimir_hora(f"Próxima actividad: {actividad['nombre']}", actividad['hora'])
            alguna_actividad_futura = True
            break

    if not alguna_actividad_futura:
        print("Todas las actividades programadas para hoy han sido completadas.")
    
    hora_salir_trabajo = actividades[5]["hora"]
    hora_estudio = actividades[6]["hora"]

    if ahora >= hora_salir_trabajo and ahora < hora_estudio:
        estudio_decision_hecha = False
        while not estudio_decision_hecha:
            estudiar = input("¿Quieres estudiar después de las 6pm? (sí/no): ").strip().lower()
            if estudiar in ["sí", "si", "s", "y", "yes"]:
                imprimir_hora("Terminar de estudiar", hora_estudio)
                estudio_decision_hecha = True
            elif estudiar in ["no", "n"]:
                print("No hay estudio hoy.")
                estudio_decision_hecha = True
            else:
                print("Por favor, responde con 'sí' o 'no'.")
    elif ahora >= hora_estudio:
        print("El tiempo para estudiar ya pasó.")
    else:
        pass

    if not alguna_actividad_futura and (ahora >= hora_estudio or (ahora.hour >= hora_salir_trabajo.hour and (not (ahora < hora_estudio) or 'estudiar' in locals() and estudiar in ["no", "n"]))):
        print("\n--- ¡El día ha terminado y todas las actividades han sido completadas! ---")
    elif alguna_actividad_futura:
        print("\n--- Fin del día ---")
    else:
        print("\n--- El día ha terminado para las actividades principales. ---")


if __name__ == "__main__":
    # --- Configuración de Argumentos de Línea de Comandos ---
    parser = argparse.ArgumentParser(description='Simula la rutina diaria y el calendario para una fecha/hora específica o la actual.')
    parser.add_argument('--fecha', type=str, help='Fecha a simular en formato YYYY-MM-DD (ej: 2026-04-03)')
    parser.add_argument('--hora', type=str, help='Hora a simular en formato HH:MM (ej: 10:00)')
    args = parser.parse_args()

    if args.fecha and args.hora:
        try:
            # Intentar parsear la fecha y hora de los argumentos
            fake_date_str = args.fecha
            fake_time_str = args.hora
            
            fake_dt = datetime.datetime.strptime(f"{fake_date_str} {fake_time_str}", "%Y-%m-%d %H:%M")
            
            print(f"\n==============================================")
            print(f"--- EJECUCIÓN CON FAKETIME (Argumentos): {fake_dt.strftime('%d de %B de %Y, %H:%M')} ---")
            print(f"==============================================")
            
            with create_faketime_context(fake_dt.year, fake_dt.month, fake_dt.day, 
                                         fake_dt.hour, fake_dt.minute):
                generar_mini_calendario()
                simular_dia()
                
        except ValueError:
            print("Error: Formato de fecha o hora inválido. Usa YYYY-MM-DD para --fecha y HH:MM para --hora.")
            print("Ejemplo: python script.py --fecha 2026-04-03 --hora 10:00")
            
    else:
        # --- Ejecución Normal (con la fecha y hora REAL de tu sistema) ---
        print("\n==============================================")
        print("--- EJECUCIÓN NORMAL (Fecha y hora REAL) ---")
        print("==============================================")
        generar_mini_calendario()
        simular_dia()
        
    # --- Ejemplos de ejecución con Faketime (comentados para no ejecutar automáticamente) ---
    # Para usar estos, descomenta el bloque 'with' específico y comenta la lógica 'if args.fecha' de arriba.
    # Estos son solo ejemplos de cómo usarías el faketime directamente en el código.
    '''
    print("\n\n==============================================")
    print("--- PRUEBA CON FAKETIME: 16 de Julio de 2025, 10:00 AM ---")
    print("    (Debería mostrar 'Día de la Virgen del Carmen' como próximo feriado)")
    print("==============================================")
    with create_faketime_context(2025, 7, 16, 10, 0):
        generar_mini_calendario()
        simular_dia()

    print("\n\n==============================================")
    print("--- PRUEBA CON FAKETIME: 17 de Septiembre de 2025, 14:00 PM ---")
    print("    (Debería mostrar 'Fiestas Patrias' como próximo feriado)")
    print("==============================================")
    with create_faketime_context(2025, 9, 17, 14, 0):
        generar_mini_calendario()
        simular_dia()

    print("\n\n==============================================")
    print("--- PRUEBA CON FAKETIME: 20 de Septiembre de 2025, 09:00 AM ---")
    print("    (Debería mostrar 'No hay feriados restantes este mes' ya que Fiestas Patrias ya pasó)")
    print("==============================================")
    with create_faketime_context(2025, 9, 20, 9, 0):
        generar_mini_calendario()
        simular_dia()

    print("\n\n==============================================")
    print("--- PRUEBA CON FAKETIME: 26 de Diciembre de 2025, 08:00 AM ---")
    print("    (Debería mostrar 'No hay feriados restantes este mes' ya que Navidad ya pasó)")
    print("==============================================")
    with create_faketime_context(2025, 12, 26, 8, 0):
        generar_mini_calendario()
        simular_dia()

    print("\n\n==============================================")
    print("--- PRUEBA CON FAKETIME: 1 de Junio de 2025, 11:00 AM ---")
    print("    (Debería mostrar 'San Pedro y San Pablo' como próximo feriado)")
    print("==============================================")
    with create_faketime_context(2025, 6, 1, 11, 0):
        generar_mini_calendario()
        simular_dia()

    print("\n\n==============================================")
    print("--- PRUEBA CON FAKETIME: 28 de Noviembre de 2025, 17:00 PM ---")
    print("    (Debería mostrar 'Día de la Iglesia Evangélica' como próximo feriado)")
    print("==============================================")
    with create_faketime_context(2025, 11, 28, 17, 0):
        generar_mini_calendario()
        simular_dia()

    print("\n\n==============================================")
    print("--- PRUEBA CON FAKETIME: 3 de Abril de 2026, 10:00 AM (Viernes Santo 2026) ---")
    print("==============================================")
    with create_faketime_context(2026, 4, 3, 10, 0):
        generar_mini_calendario()
        simular_dia()

    print("\n\n==============================================")
    print("--- PRUEBA CON FAKETIME: 18 de Septiembre de 2028, 15:00 PM (Fiestas Patrias 2028) ---")
    print("==============================================")
    with create_faketime_context(2028, 9, 18, 15, 0):
        generar_mini_calendario()
        simular_dia()

    print("\n\n==============================================")
    print("--- PRUEBA CON FAKETIME: 25 de Diciembre de 2030, 09:00 AM (Navidad 2030) ---")
    print("==============================================")
    with create_faketime_context(2030, 12, 25, 9, 0):
        generar_mini_calendario()
        simular_dia()

    print("\n\n==============================================")
    print("--- PRUEBA CON FAKETIME: 1 de Enero de 2029, 08:00 AM (Año Nuevo 2029) ---")
    print("==============================================")
    with create_faketime_context(2029, 1, 1, 8, 0):
        generar_mini_calendario()
        simular_dia()
    '''        