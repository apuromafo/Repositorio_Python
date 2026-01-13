import os
import json
from datetime import datetime

# Rutas
DATA_DIR = "data"
REPORTS_DIR = "reports"

os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)

# Diccionario interno de mensajes por idioma
LANG_DATA = {
    "es": {
        "menu": {
            "language_selected": "Idioma seleccionado: Español",
            "start_assessment": "Iniciar Evaluación",
            "starting_assessment": "Iniciando asistente de evaluación NIST...",
            "exit": "Salir",
            "select_option": "Seleccione una opción",
            "goodbye": "Hasta luego"
        },
        "case": {
            "info_header": "Información del Caso",
            "name": "Nombre del caso",
            "date": "Fecha (YYYY-MM-DD)",
            "background": "Antecedentes relevantes"
        },
        "questions": {
            "technical_indicators": "Indicadores Técnicos",
            "visual_presentation_indicators": "Indicadores de Presentación Visual",
            "language_content_indicators": "Lenguaje y Contenido",
            "common_tactics_indicators": "Tácticas Comunes",
            "errors_indicators": "Errores",
            "technical_cues_indicators": "Indicadores Técnico-Numericos",
            "visual_presentation_cues_indicators": "Indicadores de Presentación Visual",
            "language_content_cues_indicators": "Indicadores de Lenguaje y Contenido",
            "common_tactics_cues_indicators": "Indicadores de Tácticas Comunes",
            "premise_alignment": "Premise Alignment",
            "context_yesno": "Este grupo evalúa si ciertos elementos técnicos y de contenido están presentes.",
            "context_count": "En esta sección, cuente cuántas veces aparece cada elemento en el correo electrónico.",
            "context_premise": "Evalúe la alineación del mensaje con situaciones reales y su aplicabilidad."
        },
        "answers": {
            "yes": "s",
            "no": "n"
        },
        "numeric": {
            "prompt_count": "Ingrese cantidad",
            "error_invalid_number": "Ingrese un número entero positivo."
        },
        "scale": {
            "prompt_score": "Asigne una puntuación (0, 2, 4, 6, 8)",
            "error_invalid_score": "Valor inválido. Use solo números de la escala (0, 2, 4, 6, 8)."
        },
        "results": {
            "invalid_yesno": "Por favor ingrese 's' o 'n'.",
            "invalid_option": "Opción no válida.",
            "press_enter": "Presione Enter para continuar..."
        },
        "report": {
            "header": "INFORME DE EVALUACIÓN DE SEGURIDAD - NIST TN 2276",
            "issue_date": "Fecha de Emisión",
            "case_title": "Datos del Caso",
            "background": "Antecedentes Relevantes",
            "cues_total": "Total de Indicadores Observados",
            "risk_category": "Categoría de riesgo",
            "premise_rating": "Premise Alignment Rating",
            "premise_category": "Premise Alignment Category",
            "detection_difficulty": "Nivel de dificultad de detección",
            "recommendations_title": "Recomendaciones"
        }
    },
    "en": {
        "menu": {
            "language_selected": "Language selected: English",
            "start_assessment": "Start Assessment",
            "starting_assessment": "Starting NIST assessment assistant...",
            "exit": "Exit",
            "select_option": "Select an option",
            "goodbye": "Goodbye"
        },
        "case": {
            "info_header": "Case Information",
            "name": "Case name",
            "date": "Date (YYYY-MM-DD)",
            "background": "Relevant background"
        },
        "questions": {
            "technical_indicators": "Technical Indicators",
            "visual_presentation_indicators": "Visual Presentation Indicators",
            "language_content_indicators": "Language and Content",
            "common_tactics_indicators": "Common Tactics",
            "errors_indicators": "Errors",
            "technical_cues_indicators": "Technical Cues",
            "visual_presentation_cues_indicators": "Visual Presentation Cues",
            "language_content_cues_indicators": "Language and Content Cues",
            "common_tactics_cues_indicators": "Common Tactics Cues",
            "premise_alignment": "Premise Alignment",
            "context_yesno": "This section evaluates if certain technical or content elements are present in the email.",
            "context_count": "In this section, count how many times each indicator appears in the email.",
            "context_premise": "Evaluate how well the message aligns with real-life situations and its applicability."
        },
        "answers": {
            "yes": "y",
            "no": "n"
        },
        "numeric": {
            "prompt_count": "Enter quantity",
            "error_invalid_number": "Please enter a positive integer."
        },
        "scale": {
            "prompt_score": "Assign a score (0, 2, 4, 6, 8)",
            "error_invalid_score": "Invalid value. Use only numbers from the scale (0, 2, 4, 6, 8)."
        },
        "results": {
            "invalid_yesno": "Please enter 'y' or 'n'.",
            "invalid_option": "Invalid option.",
            "press_enter": "Press Enter to continue..."
        },
        "report": {
            "header": "NIST PHISH SCALE ASSESSMENT REPORT",
            "issue_date": "Issue Date",
            "case_title": "Case Information",
            "background": "Relevant Background",
            "cues_total": "Total Cues Observed",
            "risk_category": "Risk Category",
            "premise_rating": "Premise Alignment Rating",
            "premise_category": "Premise Alignment Category",
            "detection_difficulty": "Detection Difficulty Level",
            "recommendations_title": "Recommendations"
        }
    }
}

# Diccionario integrado de niveles de riesgo
RISK_CATEGORIES = [
    {"min_score": 1, "max_score": 8, "category": "Few", "category_es": "Pocos", "category_en": "Few"},
    {"min_score": 9, "max_score": 14, "category": "Some", "category_es": "Algunos", "category_en": "Some"},
    {"min_score": 15, "max_score": 100, "category": "Many", "category_es": "Muchos", "category_en": "Many"}
]

# Mapeo de dificultad de detección
DETECTION_DIFFICULTY_MAPPING = [
    # Spanish / English
    {"cue_category": "Few", "premise_category": "Weak", "difficulty": {"es": "Moderadamente difícil", "en": "Moderately difficult"}},
    {"cue_category": "Few", "premise_category": "Medium", "difficulty": {"es": "Muy difícil", "en": "Very difficult"}},
    {"cue_category": "Few", "premise_category": "Strong", "difficulty": {"es": "Muy difícil", "en": "Very difficult"}},

    {"cue_category": "Some", "premise_category": "Weak", "difficulty": {"es": "Menos difícil", "en": "Least difficult"}},
    {"cue_category": "Some", "premise_category": "Medium", "difficulty": {"es": "Moderadamente difícil", "en": "Moderately difficult"}},
    {"cue_category": "Some", "premise_category": "Strong", "difficulty": {"es": "Moderadamente difícil", "en": "Moderately difficult"}},

    {"cue_category": "Many", "premise_category": "Weak", "difficulty": {"es": "Menos difícil", "en": "Least difficult"}},
    {"cue_category": "Many", "premise_category": "Medium", "difficulty": {"es": "Menos difícil", "en": "Least difficult"}},
    {"cue_category": "Many", "premise_category": "Strong", "difficulty": {"es": "Moderadamente difícil", "en": "Moderately difficult"}}
]



# --- Funciones auxiliares ---
def select_language():
    print("Seleccione su idioma / Choose your language:")
    print("1. Español")
    print("2. English")
    choice = input("Ingrese opción (1 o 2): ").strip()

    if choice == "1":
        return "es"
    elif choice == "2":
        return "en"
    else:
        print("Opción inválida. Usando español por defecto.")
        return "es"


def ask_case_info(lang_data, lang_code):
    print(f"\n{lang_data['case']['info_header']}")
    case_name = input(f"{lang_data['case']['name']}: ").strip()

    while True:
        case_date = input(f"{lang_data['case']['date']} (YYYY-MM-DD): ").strip()
        try:
            datetime.strptime(case_date, "%Y-%m-%d")
            break
        except ValueError:
            print("[ERROR] Fecha inválida. Use el formato YYYY-MM-DD.")

    background = input(f"{lang_data['case']['background']}:\n").strip()

    return {
        "case_name": case_name,
        "case_date": case_date,
        "background": background,
        "lang_code": lang_code
    }


def validate_yes_no(lang_data):
    yes_value = lang_data["answers"]["yes"]
    no_value = lang_data["answers"]["no"]

    while True:
        answer = input(f"({yes_value}/{no_value}): ").strip().lower()
        if answer == yes_value:
            return True
        elif answer == no_value:
            return False
        else:
            print(lang_data["results"]["invalid_yesno"])


def validate_numeric(lang_data):
    while True:
        try:
            value = int(input(f"{lang_data['numeric']['prompt_count']}: "))
            if value >= 0:
                return value
            else:
                raise ValueError
        except ValueError:
            print(f"[ERROR] {lang_data['numeric']['error_invalid_number']}")


def validate_premise_score(lang_data):
    prompt = lang_data["scale"]["prompt_score"]
    error_msg = lang_data["scale"]["error_invalid_score"]

    while True:
        try:
            value = int(input(f"{prompt}: ").strip())
            if value in [0, 2, 4, 6, 8]:
                return value
            else:
                raise ValueError
        except ValueError:
            print(f"[ERROR] {error_msg}")


def run_test_yes_no_group(category_label, questions_list, lang_data):
    print(f"\n--- {category_label} ---")
    print(lang_data["questions"]["context_yesno"])

    total_yes = 0
    for q in questions_list:
        question = q[f"question_{lang_data['language_code']}"]
        print(f"\n{question}")
        if validate_yes_no(lang_data):
            total_yes += 1

    return total_yes


def run_test_numeric_group(category_label, questions_list, lang_data):
    print(f"\n--- {category_label} ---")
    print(lang_data["questions"]["context_count"])

    total = 0
    for q in questions_list:
        question = q[f"question_{lang_data['language_code']}"]
        print(f"\n{question}")
        total += validate_numeric(lang_data)

    return total


def run_test_premise_alignment_group(lang_data):
    file_path = os.path.join(DATA_DIR, "partC_premise_alignment.json")
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)["premise_alignment"]

    print(f"\n--- {lang_data['questions']['premise_alignment']} ---")
    print(lang_data["questions"]["context_premise"])

    total_score = 0
    for idx, q in enumerate(data, start=1):
        question = q[f"question_{lang_data['language_code']}"]
        print(f"\n{idx}. {question}")
        score = validate_premise_score(lang_data)
        if idx < 5:
            total_score += score
        else:
            total_score -= score

    category = get_premise_alignment_category(total_score, lang_data['language_code'])
    return total_score, category


def get_premise_alignment_category(premise_rating, lang_code):
    mapping = {
        "Weak": {"es": "Débil", "en": "Weak"},
        "Medium": {"es": "Medio", "en": "Medium"},
        "Strong": {"es": "Fuerte", "en": "Strong"}
    }

    if premise_rating <= 10:
        return mapping["Weak"][lang_code]
    elif 11 <= premise_rating <= 17:
        return mapping["Medium"][lang_code]
    else:
        return mapping["Strong"][lang_code]


def get_premise_alignment_category_raw(premise_rating):
    if premise_rating <= 10:
        return "Weak"
    elif 11 <= premise_rating <= 17:
        return "Medium"
    else:
        return "Strong"


def get_risk_category(total_yes, lang_code):
    for level in RISK_CATEGORIES:
        if level["min_score"] <= total_yes <= level["max_score"]:
            return level.get(f"category_{lang_code}", level["category"])
    return "Unknown"


def get_detection_difficulty(cue_category, premise_category):
    for item in DETECTION_DIFFICULTY_MAPPING:
        if item["cue_category"] == cue_category and item["premise_category"] == premise_category:
            return item["difficulty"]
    return "Unknown"


def generate_recommendations(cue_category, premise_category, detection_difficulty, lang_code):
    rec_file = os.path.join(DATA_DIR, "recommendations.json")
    with open(rec_file, "r", encoding="utf-8") as f:
        rec_data = json.load(f)

    specific_recs = []
    try:
        specific_recs = rec_data[cue_category][premise_category][lang_code]
    except KeyError:
        pass

    general_recs = rec_data["general"].get(lang_code, [])
    return specific_recs + general_recs


def save_report(case_info, cues_total, cue_category, premise_rating, premise_category, detection_difficulty, recommendations, lang_data, lang_code):
    timestamp = datetime.now().strftime("%H%M%S")
    filename = f"report_{case_info['case_name']}_{case_info['case_date']}_{timestamp}.txt"
    filepath = os.path.join(REPORTS_DIR, filename)

    # Obtén solo el texto en el idioma seleccionado
    detection_difficulty_text = detection_difficulty.get(lang_code, "Unknown")

    with open(filepath, "w", encoding="utf-8") as f:
        f.write("####################################################################################################\n")
        f.write(f"## {lang_data['report']['header']} ##\n")
        f.write("####################################################################################################\n\n")

        f.write(f"**{lang_data['report']['issue_date']}**: {case_info['case_date']}\n\n\n")

        f.write(f"**1. {lang_data['report']['case_title']}**\n\n")
        f.write(f"* **{lang_data['report']['case_title']}**: Evaluación de {case_info['case_name']}\n\n\n")

        f.write(f"**2. {lang_data['report']['background']}**\n\n")
        f.write(f"* **{lang_data['report']['background']}**: {case_info['background']}\n\n\n")

        f.write(f"**3. {lang_data['report']['cues_total']}**\n\n")
        f.write(f"    * **{lang_data['report']['risk_category']}**: {cue_category}\n\n\n")

        f.write(f"**4. {lang_data['report']['premise_rating']}**\n\n")
        f.write(f"    * **{lang_data['report']['premise_rating']}**: {premise_rating}\n")
        f.write(f"    * **{lang_data['report']['premise_category']}**: {premise_category}\n\n\n")

        f.write(f"**5. {lang_data['report']['detection_difficulty']}**\n\n")
        f.write(f"    * **{lang_data['report']['detection_difficulty']}**: {detection_difficulty_text}\n\n\n")

        f.write(f"**6. {lang_data['report']['recommendations_title']}**\n\n")
        for idx, rec in enumerate(recommendations, start=1):
            f.write(f"    {idx}. {rec}\n\n")

    print(f"\n[INFO] Informe guardado en: {filepath}")
    
def get_risk_category_raw(total_yes):
    for level in RISK_CATEGORIES:
        if level["min_score"] <= total_yes <= level["max_score"]:
            return level["category"]
    return "Unknown"
        
def start_assessment(lang_data, lang_code):
    print(f"\n[INFO] {lang_data['menu']['starting_assessment']}")

    # Datos del caso
    case_info = ask_case_info(lang_data, lang_code)

    # --- Preguntas Sí/No ---
    cues_yesno = 0
    tests_yesno_config = [
        {"file": "partA_cues_yesno.json", "category_key": "technical_indicators"},
        {"file": "partA_cues_yesno.json", "category_key": "visual_presentation_indicators"},
        {"file": "partA_cues_yesno.json", "category_key": "language_content_indicators"},
        {"file": "partA_cues_yesno.json", "category_key": "common_tactics_indicators"}
    ]

    for test in tests_yesno_config:
        file_path = os.path.join(DATA_DIR, test["file"])
        with open(file_path, "r", encoding="utf-8") as f:
            cues_data = json.load(f)

        count = run_test_yes_no_group(
            lang_data["questions"][test["category_key"]],
            cues_data[test["category_key"]],
            lang_data
        )
        cues_yesno += count

    # --- Conteo de indicadores ---
    cues_count = 0
    tests_count_config = [
        {"file": "partA_cues_count.json", "category_key": "errors_indicators"},
        {"file": "partA_cues_count.json", "category_key": "technical_cues_indicators"},
        {"file": "partA_cues_count.json", "category_key": "visual_presentation_cues_indicators"},
        {"file": "partA_cues_count.json", "category_key": "language_content_cues_indicators"},
        {"file": "partA_cues_count.json", "category_key": "common_tactics_cues_indicators"}
    ]

    for test in tests_count_config:
        file_path = os.path.join(DATA_DIR, test["file"])
        with open(file_path, "r", encoding="utf-8") as f:
            cues_data = json.load(f)

        cues_count += run_test_numeric_group(
            lang_data["questions"][test["category_key"]],
            cues_data[test["category_key"]],
            lang_data
        )

    # --- Premise Alignment ---
    premise_rating, premise_category = run_test_premise_alignment_group(lang_data)

    # --- Calcular nivel de riesgo final ---
    cues_total = cues_yesno + cues_count
    cue_category = get_risk_category(cues_total, lang_code)

    cue_category_raw = get_risk_category_raw(cues_total)
    premise_category_raw = get_premise_alignment_category_raw(premise_rating)

    # --- Detection Difficulty ---
    detection_difficulty = get_detection_difficulty(cue_category_raw, premise_category_raw)

    # --- Generar recomendaciones ---
    recommendations = generate_recommendations(cue_category_raw, premise_category_raw, detection_difficulty, lang_code)

    # --- Guardar informe ---
    save_report(
        case_info,
        cues_total,
        cue_category,
        premise_rating,
        premise_category,
        detection_difficulty,
        recommendations,
        lang_data,lang_code
    )

    input(f"\n{lang_data['results']['press_enter']}")


def main_menu(lang_data, lang_code):
    while True:
        print("\n--- NIST Assessment Assistant ---")
        print(f"1. {lang_data['menu']['start_assessment']}")
        print(f"2. {lang_data['menu']['exit']}")
        choice = input(f"{lang_data['menu']['select_option']} ").strip()

        if choice == "1":
            start_assessment(lang_data, lang_code)
        elif choice == "2":
            print(f"\n{lang_data['menu']['goodbye']}")
            break
        else:
            print(f"[ERROR] {lang_data['results']['invalid_option']}")


def main():
    print("\nInicializando aplicación...\n")
    lang_code = select_language()
    lang_data = LANG_DATA[lang_code]
    lang_data["language_code"] = lang_code

    if not os.path.exists(DATA_DIR):
        print(f"[ERROR] Carpeta '{DATA_DIR}' no encontrada. Asegúrate de tener los archivos JSON necesarios.")
        return

    main_menu(lang_data, lang_code)


if __name__ == "__main__":
    main()