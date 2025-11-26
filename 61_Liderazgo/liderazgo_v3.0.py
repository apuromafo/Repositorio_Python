#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cuestionario de Estilo de Liderazgo en Ciberseguridad (V3 - Final)

- Escenarios STAR y Puntuación Normalizada.
- Incluye exportación a JSON/CSV.

Referencias de Lógica y Diseño:
- careerminds.com/blog/how-to-use-the-star-method-to-assess-leadership-skills
- mindtools.com/azr30oh/whats-your-leadership-style
- blogs.lideresia.com/blog-best-practices-for-designing-psychometric-tests-that-measure-leadership-potential-175400
- leadershipstylesquestionnaire.com/blog/the-complete-guide-to-reliable-leadership-evaluation-tools-and-their-real-world-value
- useshiny.com/blog/leadership-style-assessment/
- bryq.com/blog/likert-scale-vs-forced-choice-for-employee-selection
"""

import json
import argparse
from datetime import datetime

# ------------------ Definición de datos ------------------ #

CUESTIONARIO_LIDERAZGO = {
    1: {
        "pregunta": (
            "SITUACIÓN: Durante una campaña de phishing dirigida, el SOC detecta "
            "un aumento súbito de alertas críticas fuera de horario.\n"
            "TAREA: Como líder de respuesta a incidentes, debes coordinar las "
            "primeras 2 horas de respuesta.\n"
            "¿Qué haces primero?"
        ),
        "opciones": {
            "A": {
                "texto": "Centralizas decisiones, das órdenes directas a cada analista y exiges actualizaciones cada 10 minutos.",
                "puntos": {"Autocrático": 3, "Transaccional": 1},
            },
            "B": {
                "texto": "Reúnes rápidamente al equipo, explicas el contexto y pides propuestas de acción antes de definir el plan.", # CORRECCIÓN: "pedes" -> "pides"
                "puntos": {"Democrático": 3},
            },
            "C": {
                "texto": "Revisas los playbooks, asignas tareas según rol y recuerdas los criterios de escalamiento y SLAs.",
                "puntos": {"Transaccional": 3},
            },
            "D": {
                "texto": "Compartes la visión de proteger la organización, delegas decisiones tácticas a los líderes técnicos y refuerzas la confianza en el equipo.",
                "puntos": {"Transformacional": 3},
            },
        },
    },
    2: {
        "pregunta": (
            "SITUACIÓN: Un proyecto de hardening de servidores lleva semanas retrasado.\n"
            "TAREA: Necesitas recuperar el ritmo sin quemar al equipo.\n"
            "¿Cómo abordas al equipo en la próxima reunión?"
        ),
        "opciones": {
            "A": {
                "texto": "Recalcas el impacto de los retrasos, refuerzas los plazos y asocias el cumplimiento a reconocimientos o sanciones.",
                "puntos": {"Transaccional": 3},
            },
            "B": {
                "texto": "Explicas la visión de madurez de seguridad, escuchas bloqueos y pactas en conjunto cómo reorganizar el trabajo.",
                "puntos": {"Transformacional": 2, "Democrático": 1},
            },
            "C": {
                "texto": "Presentas tú mismo el nuevo plan detallado, reasignas tareas y dejas poco margen de discusión.",
                "puntos": {"Autocrático": 3},
            },
            "D": {
                "texto": "Creas un espacio de diálogo abierto, pides ideas al equipo y solo después propones un cierre consensuado.",
                "puntos": {"Democrático": 3},
            },
        },
    },
    3: {
        "pregunta": (
            "SITUACIÓN: Un pentest interno descubre una cadena de vulnerabilidades críticas en producción.\n"
            "TAREA: Debes decidir cómo priorizar la remediación en los próximos 7 días.\n"
            "¿Qué enfoque eliges?"
        ),
        "opciones": {
            "A": {
                "texto": "Definís tú solo el orden de corrección y comunicas las fechas límite a cada equipo.",
                "puntos": {"Autocrático": 3},
            },
            "B": {
                "texto": "Convocas a los dueños de los sistemas, analizáis juntos el riesgo y consensuáis la priorización.",
                "puntos": {"Democrático": 3},
            },
            "C": {
                "texto": "Utilizas la matriz de riesgo y los SLAs existentes para definir prioridades y medir el cumplimiento.",
                "puntos": {"Transaccional": 3},
            },
            "D": {
                "texto": "Conectas la remediación con la visión de resiliencia y propones retos al equipo para reducir riesgo por encima de lo mínimo requerido.",
                "puntos": {"Transformacional": 3},
            },
        },
    },
    4: {
        "pregunta": (
            "SITUACIÓN: Un analista comete un error en una regla de detección y genera un falso positivo masivo.\n"
            "TAREA: Debes gestionar el fallo y el impacto en el equipo.\n"
            "¿Cómo actúas?"
        ),
        "opciones": {
            "A": {
                "texto": "Identificas al responsable y documentas el fallo como incumplimiento claro, con posibles consecuencias disciplinarias.",
                "puntos": {"Autocrático": 2, "Transaccional": 1},
            },
            "B": {
                "texto": "Organizas un post-mortem donde se analiza la causa raíz y se definen mejoras sin buscar culpables.",
                "puntos": {"Transformacional": 2, "Democrático": 1},
            },
            "C": {
                "texto": "Revisas si el error está cubierto por los procedimientos, ajustas el proceso y registras el incidente como lección aprendida.",
                "puntos": {"Transaccional": 3},
            },
            "D": {
                "texto": "Facilitas una conversación abierta donde el equipo discute qué podría hacerse distinto, priorizando el aprendizaje colectivo.",
                "puntos": {"Democrático": 3},
            },
        },
    },
    5: {
        "pregunta": (
            "SITUACIÓN: Debes definir la estrategia de capacitación en seguridad para todo el año.\n"
            "TAREA: Diseñar un plan que aumente la madurez del equipo.\n"
            "¿Qué haces?"
        ),
        "opciones": {
            "A": {
                "texto": "Marcas tú las temáticas y fechas, asignas cursos obligatorios y mides asistencia y certificaciones.",
                "puntos": {"Autocrático": 2, "Transaccional": 1},
            },
            "B": {
                "texto": "Lanzas una encuesta para conocer intereses, co-diseñas el plan con el equipo y priorizas en conjunto.",
                "puntos": {"Democrático": 3},
            },
            "C": {
                "texto": "Conectas la formación con una visión de crecimiento profesional y propones retos que inspiren a ir más allá del mínimo.",
                "puntos": {"Transformacional": 3},
            },
            "D": {
                "texto": "Defines requisitos mínimos por rol, incentivos por cumplimiento y revisiones trimestrales de objetivos de formación.",
                "puntos": {"Transaccional": 3},
            },
        },
    },
    6: {
        "pregunta": (
            "SITUACIÓN: En una guerra de prioridades entre negocio y seguridad, te piden relajar controles para lanzar un producto más rápido.\n"
            "TAREA: Debes tomar una posición y guiar la decisión.\n"
            "¿Cómo procedes?"
        ),
        "opciones": {
            "A": {
                "texto": "Decides que la seguridad prevalece y comunicas que no se lanza sin cumplir los mínimos que defines.",
                "puntos": {"Autocrático": 3},
            },
            "B": {
                "texto": "Facilitas una discusión con negocio y seguridad para acordar una solución intermedia con riesgos aceptados formalmente.",
                "puntos": {"Democrático": 3},
            },
            "C": {
                "texto": "Negocias excepciones temporales documentadas, defines controles compensatorios y condiciones claras para su revisión.",
                "puntos": {"Transaccional": 3},
            },
            "D": {
                "texto": "Reenmarcas la conversación hacia una visión de confianza digital a largo plazo y alinear el producto con esa visión.",
                "puntos": {"Transformacional": 3},
            },
        },
    },
    7: {
        "pregunta": (
            "SITUACIÓN: Dos miembros de tu equipo tienen un conflicto fuerte sobre cómo abordar una auditoría externa.\n"
            "TAREA: Resolver el conflicto sin perder foco en el objetivo.\n"
            "¿Qué haces?"
        ),
        "opciones": {
            "A": {
                "texto": "Escuchas brevemente y luego impones tú la postura que se seguirá, cerrando el debate.",
                "puntos": {"Autocrático": 3},
            },
            "B": {
                "texto": "Facilitas que ambos expongan sus argumentos ante el equipo y buscáis una solución que integre lo mejor de cada propuesta.",
                "puntos": {"Democrático": 3},
            },
            "C": {
                "texto": "Recuerdas los requisitos de la auditoría, los plazos y los criterios de éxito, y eliges la opción que mejor encaje con ellos.",
                "puntos": {"Transaccional": 3},
            },
            "D": {
                "texto": "Conectas el conflicto con la visión de aprendizaje y mejora, y retas al equipo a diseñar juntos un enfoque superador.",
                "puntos": {"Transformacional": 3},
            },
        },
    },
    8: {
        "pregunta": (
            "SITUACIÓN: Un proyecto de implementación de un SIEM nuevo requiere colaboración entre múltiples áreas.\n"
            "TAREA: Liderar el proyecto de forma efectiva.\n"
            "¿Cómo te posicionas?"
        ),
        "opciones": {
            "A": {
                "texto": "Asumes el control total del proyecto, reasignas tareas según tu criterio y tomas todas las decisiones clave.",
                "puntos": {"Autocrático": 3},
            },
            "B": {
                "texto": "Creas un comité con representantes de cada área, repartís responsabilidades y tomáis decisiones colegiadas.",
                "puntos": {"Democrático": 3},
            },
            "C": {
                "texto": "Defines objetivos, KPIs claros, reportes periódicos y alineas recompensas con el cumplimiento de hitos.",
                "puntos": {"Transaccional": 3},
            },
            "D": {
                "texto": "Construyes una narrativa sobre el impacto del SIEM en la organización y motivas a cada área a liderar parte del cambio.",
                "puntos": {"Transformacional": 3},
            },
        },
    },
    9: {
        "pregunta": (
            "SITUACIÓN: Te incorporas como nuevo líder a un equipo técnico ya conformado.\n"
            "TAREA: Ganar credibilidad y entender cómo trabajan.\n"
            "¿Cuál es tu enfoque inicial?"
        ),
        "opciones": {
            "A": {
                "texto": "Marcas desde el primer día cómo se harán las cosas y qué esperas en términos de disciplina y resultados.",
                "puntos": {"Autocrático": 3},
            },
            "B": {
                "texto": "Escuchas al equipo, haces preguntas abiertas sobre su forma de trabajar y co-definís acuerdos.",
                "puntos": {"Democrático": 3},
            },
            "C": {
                "texto": "Revisas métricas, SLAs y backlog, y alineas objetivos individuales con las expectativas de la organización.",
                "puntos": {"Transaccional": 3},
            },
            "D": {
                "texto": "Compartes tu visión de hacia dónde querés llevar al equipo y pides ideas para construir ese camino juntos.",
                "puntos": {"Transformacional": 3},
            },
        },
    },
    10: {
        "pregunta": (
            "SITUACIÓN: Tras un incidente grave, la dirección quiere \"pasar página\" rápido.\n"
            "TAREA: Decidir qué haces con el aprendizaje del incidente.\n"
            "¿Qué priorizas?"
        ),
        "opciones": {
            "A": {
                "texto": "Preparas tú mismo un informe ejecutivo, defines tú las acciones y cierras el tema.",
                "puntos": {"Autocrático": 2, "Transaccional": 1},
            },
            "B": {
                "texto": "Diriges un post-mortem con múltiples áreas, documentáis causas y acciones y acordáis compromisos explícitos.",
                "puntos": {"Democrático": 2, "Transaccional": 1},
            },
            "C": {
                "texto": "Alineas las acciones de mejora con políticas, controles y métricas existentes para asegurar el seguimiento.",
                "puntos": {"Transaccional": 3},
            },
            "D": {
                "texto": "Transformas el incidente en una historia de aprendizaje, conectas las mejoras con la visión de resiliencia y las comunicas a toda la organización.",
                "puntos": {"Transformacional": 3},
            },
        },
    },
}

MENSAJES_ESTILO = {
    "Transformacional": {
        "contexto": "Tu foco en la visión e inspiración es excelente para la retención de talento y la innovación en ciberseguridad.",
        "consejo": "Consejo: Asegúrate de complementar con protocolos claros y métricas (Transaccional) para gestionar crisis e informes.",
    },
    "Transaccional": {
        "contexto": "Tu estilo es ideal para la gestión de cumplimiento, auditorías y operaciones de SOC estandarizadas.",
        "consejo": "Consejo: Integra elementos Transformacionales para cuidar motivación y creatividad, no solo cumplimiento.",
    },
    "Autocrático": {
        "contexto": "Tu decisividad es crítica para la Respuesta a Incidentes y situaciones de alta presión.",
        "consejo": "Consejo: Fuera de la crisis, practica estilos más Democráticos o Transformacionales para fortalecer confianza.",
    },
    "Democrático": {
        "contexto": "Tu enfoque participativo mejora la moral y la adopción de políticas.",
        "consejo": "Consejo: Equilibra el consenso con la necesidad de decidir rápido en incidentes o decisiones de alto riesgo.",
    },
}


# ------------------ Funciones auxiliares ------------------ #

def preguntar_item(num, item):
    """Muestra la pregunta y solicita la respuesta al usuario."""
    print(f"\n{num}. {item['pregunta']}")
    for clave, opcion in item["opciones"].items():
        print(f"    [{clave}] {opcion['texto']}")

    while True:
        respuesta = input("    Tu respuesta (A, B, C, D): ").upper().strip()
        if respuesta in item["opciones"]:
            return respuesta
        print("Opción no válida. Por favor, ingresa A, B, C o D.")


def inicializar_puntuaciones():
    """Inicializa el diccionario de puntuaciones en cero."""
    return {
        "Transformacional": 0,
        "Transaccional": 0,
        "Democrático": 0,
        "Autocrático": 0,
    }


def obtener_perfiles(puntuaciones, delta_relativo=0.2):
    """
    Identifica el perfil principal y los perfiles secundarios
    basado en un delta_relativo (ej. 20% menos que el máximo).
    """
    perfil_principal = max(puntuaciones, key=puntuaciones.get)
    max_score = puntuaciones[perfil_principal]

    if max_score == 0:
        return perfil_principal, []

    # Se establece un umbral: 80% (1 - 0.2) del máximo score normalizado
    umbral_secundario = max_score * (1 - delta_relativo)
    perfiles_cercanos = [
        estilo
        for estilo, score in puntuaciones.items()
        if estilo != perfil_principal and score >= umbral_secundario
    ]
    return perfil_principal, perfiles_cercanos


def normalizar_puntuaciones(puntuaciones, cuestionario):
    """
    Normaliza la puntuación obtenida dividiéndola por la puntuación máxima
    posible para ese estilo, compensando el desequilibrio en las preguntas.
    """
    conteo_estilos = inicializar_puntuaciones()
    for item in cuestionario.values():
        for opcion in item["opciones"].values():
            for estilo, puntos in opcion["puntos"].items():
                conteo_estilos[estilo] += puntos

    puntuaciones_normalizadas = {}
    for estilo, score in puntuaciones.items():
        total_posible = conteo_estilos.get(estilo, 1) or 1
        # La puntuación normalizada es el porcentaje de puntos obtenidos
        puntuaciones_normalizadas[estilo] = score / total_posible
    return puntuaciones_normalizadas


def crear_reporte_datos(respuestas, puntuaciones_norm, perfil_principal, perfiles_cercanos):
    """Crea el diccionario de datos para reporte (JSON/silencioso)."""
    
    # Prepara el listado de puntuaciones normalizadas ordenadas
    puntuaciones_ordenadas = sorted(
        puntuaciones_norm.items(), key=lambda item: item[1], reverse=True
    )
    
    puntuaciones_norm_dict = {
        estilo: float(f"{score_norm:.4f}") 
        for estilo, score_norm in puntuaciones_ordenadas
    }
    
    # Prepara el diccionario de mensajes
    mensajes_perfiles = {}
    
    # Mensaje principal
    mensaje_principal = MENSAJES_ESTILO[perfil_principal]
    mensajes_perfiles[perfil_principal] = {
        "tipo": "principal",
        "contexto": mensaje_principal['contexto'],
        "consejo": mensaje_principal['consejo']
    }

    # Mensajes secundarios
    for estilo_cercano in perfiles_cercanos:
        mensajes_perfiles[estilo_cercano] = {
            "tipo": "secundario",
            "contexto": MENSAJES_ESTILO[estilo_cercano]['contexto'],
            "consejo": None # Los secundarios no tienen consejo táctico final
        }

    
    return {
        "timestamp": datetime.now().isoformat(),
        "respuestas_raw": respuestas,
        "puntuaciones_normalizadas": puntuaciones_norm_dict,
        "perfil_principal": perfil_principal,
        "perfiles_cercanos": perfiles_cercanos,
        "mensajes": mensajes_perfiles
    }


def mostrar_resultados_terminal(puntuaciones, puntuaciones_norm, perfil_principal, perfiles_cercanos):
    """Imprime el resultado principal, los consejos y la tabla detallada en formato terminal."""
    
    print("\n" + "=" * 60)
    print("RESULTADO DE TU ENCUESTA DE LIDERAZGO EN CIBERSEGURIDAD")
    print("=" * 60)

    # El formato es solo mayúsculas, sin **
    print(f"\nTu estilo de liderazgo principal es: {perfil_principal.upper()}")

    if perfiles_cercanos:
        print(f"    (También muestras características fuertes de: {', '.join(perfiles_cercanos)})")

    # --- Contexto y Consejos ---
    print("\n--- Contexto y Consejos ---")
    mensaje = MENSAJES_ESTILO[perfil_principal]
    print(f"\n[Perfil {perfil_principal.upper()}]")
    print(f"Contexto: {mensaje['contexto']}")
    print(f"Consejo: {mensaje['consejo']}")

    for estilo_cercano in perfiles_cercanos:
        print(f"\n[Perfil {estilo_cercano.upper()} (Secundario)]")
        print(f"Contexto: {MENSAJES_ESTILO[estilo_cercano]['contexto']}")

    # --- Puntuación Detallada (Ahora por Defecto) ---
    print("\n" + "*" * 60)
    print("PUNTUACIÓN DETALLADA POR ESTILO (BRUTA Y NORMALIZADA)")
    print("*" * 60)

    # Ordenar por puntuación normalizada descendente
    estilos_ordenados = sorted(
        puntuaciones_norm.items(), key=lambda item: item[1], reverse=True
    )

    for estilo, score_norm in estilos_ordenados:
        score_bruto = puntuaciones[estilo]
        print(f"- {estilo}: {score_bruto} puntos (normalizado: {score_norm:.2f})")
    print("*" * 60)

    # --- Sugerencias Tácticas ---
    print("\n--- Sugerencias tácticas inmediatas ---")
    if perfil_principal == "Autocrático":
        print("- Elige una reunión semanal donde explícitamente pidas al menos 2 alternativas antes de decidir. (Fomenta el Democrático)")
    elif perfil_principal == "Transaccional":
        print("- Identifica un proceso donde puedas añadir un espacio breve para propuestas de mejora, no solo checklists. (Fomenta el Transformacional)")
    elif perfil_principal == "Democrático":
        print("- Define de antemano en qué tipo de incidentes decidirás tú directamente para ganar velocidad. (Fomenta el Autocrático)")
    elif perfil_principal == "Transformacional":
        print("- Elige un playbook clave y asegúrate de que las reglas y pasos estén tan claros como tu visión. (Fomenta el Transaccional)")


# ------------------ Función principal ------------------ #

def run_quiz():
    """Función principal para ejecutar el cuestionario."""
    
    # 1. Configuración de argumentos
    parser = argparse.ArgumentParser(description="Cuestionario de Estilo de Liderazgo en Ciberseguridad.")
    parser.add_argument(
        "--json", 
        action="store_true", 
        help="Exporta los resultados a un archivo JSON en lugar de imprimir en la terminal."
    )
    args = parser.parse_args()
    
    puntuaciones = inicializar_puntuaciones()
    respuestas_crudas = {} # Para almacenar las respuestas A, B, C, D

    print("--- Cuestionario de Estilo de Liderazgo en Ciberseguridad (V3) ---")

    # 2. Ejecución del cuestionario
    for num, item in CUESTIONARIO_LIDERAZGO.items():
        respuesta = preguntar_item(num, item)
        respuestas_crudas[num] = respuesta
        
        puntos_otorgados = item["opciones"][respuesta]["puntos"]
        for estilo, puntos in puntos_otorgados.items():
            puntuaciones[estilo] += puntos

    # 3. Procesamiento y normalización
    puntuaciones_norm = normalizar_puntuaciones(puntuaciones, CUESTIONARIO_LIDERAZGO)
    perfil_principal, perfiles_cercanos = obtener_perfiles(puntuaciones_norm)
    
    # 4. Presentación de resultados
    if args.json:
        # Modo silencioso/Exportación a JSON
        reporte = crear_reporte_datos(respuestas_crudas, puntuaciones_norm, perfil_principal, perfiles_cercanos)
        
        filename = f"reporte_liderazgo_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(reporte, f, ensure_ascii=False, indent=4)
            print(f"\nReporte de resultados exportado correctamente a: {filename}")
        except IOError:
            print(f"\nError: No se pudo escribir el archivo {filename}.")
            # Fallback a terminal si falla la escritura
            mostrar_resultados_terminal(puntuaciones, puntuaciones_norm, perfil_principal, perfiles_cercanos)

    else:
        # Modo por defecto (Terminal)
        mostrar_resultados_terminal(puntuaciones, puntuaciones_norm, perfil_principal, perfiles_cercanos)


if __name__ == "__main__":
    run_quiz()