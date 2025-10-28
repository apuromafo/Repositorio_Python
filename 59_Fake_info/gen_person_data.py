# gen_person_data.py

import random
import datetime
from typing import Dict, List, Any
from gen_chile_base import generate_person_rut, generate_address, numberGen
from gen_financial import generate_card, generate_phone_data

# =================================================================
# 1. CONSTANTES
# =================================================================

FIRST_NAMES = (
    "María", "Sofía", "Valentina", "Antonia", "Catalina", "Camila", "José",
    "Juan", "Benjamín", "Martín", "Vicente", "Sebastián", "Matías", "Luis"
)
LAST_NAMES = (
    "González", "Muñoz", "Rojas", "Díaz", "Pérez", "Soto",
    "Contreras", "Silva", "Martínez", "López", "Fuentes", "Torres"
)
EMAIL_DOMAINS = ("mail.cl", "correo-fake.com", "datos-chile.org", "demo-mail.net")
PROFESSIONS = (
    "Abogado/a", "Contador/a Auditor/a", "Ingeniero/a Comercial", "Médico/a Cirujano/a", 
    "Programador/a", "Analista de Sistemas", "Psicólogo/a", "Trabajador/a Social"
)
MARITAL_STATUS = ("Soltero(a)", "Casado(a)", "Divorciado(a)", "Viudo(a)")
GENDERS = ("Femenino", "Masculino", "No Binario")
NATIONALITIES = ("Chilena", "Venezolana", "Peruana", "Argentina")
HEALTH_PLANS = (
    "FONASA (Tramo A)", "FONASA (Tramo C)", "ISAPRE (Cruz Blanca)", "Sin Registro"
)
CONTRACT_TYPES = ("Indefinido", "Plazo Fijo", "Servicios (Boleta de Honorarios)")

# Mapeo de Género para consistencia
GENDER_MAP = {
    'María': 'Femenino', 'Sofía': 'Femenino', 'Juan': 'Masculino', 'Benjamín': 'Masculino'
}


# =================================================================
# 2. FUNCIONES AUXILIARES
# =================================================================

def generate_birth_date(min_age: int = 18, max_age: int = 65) -> str:
    """Genera una fecha de nacimiento aleatoria (DD-MM-YYYY)."""
    today = datetime.date.today()
    start_date = today - datetime.timedelta(days=365 * max_age)
    end_date = today - datetime.timedelta(days=365 * min_age)
    
    time_between_dates = end_date - start_date
    random_days = random.randrange(time_between_dates.days)
    birth_date = start_date + datetime.timedelta(days=random_days)
    
    return birth_date.strftime("%d-%m-%Y")

def generate_person_email(first_name: str, last_name: str) -> str:
    """Genera un email principal y uno secundario."""
    email_base = f"{first_name.lower()}{last_name.lower()}{numberGen(random.randint(1, 2))}".replace(' ', '')
    
    email_principal = f"{email_base}@{random.choice(EMAIL_DOMAINS)}"
    email_secundario = f"{first_name[0].lower()}.{last_name.lower()}@{random.choice(EMAIL_DOMAINS)}"
    
    return email_principal, email_secundario

# =================================================================
# 3. FUNCIÓN DE GENERACIÓN PRINCIPAL
# =================================================================

def generate_fake_person_data(id_num: int) -> Dict[str, Any]:
    """Genera un registro completo de Persona Natural con campos de RR.HH. y financieros."""
    
    first_name = random.choice(FIRST_NAMES)
    last_name = random.choice(LAST_NAMES)
    
    # Generación de datos modulares
    rut = generate_person_rut()
    address_data = generate_address()
    card_data = generate_card()
    phone_principal = generate_phone_data(is_mobile_preferred=True)

    # Datos demográficos y RR.HH.
    gender = GENDER_MAP.get(first_name, random.choice(GENDERS)) 
    email_principal, email_secundario = generate_person_email(first_name, last_name)
    
    return {
        "id": id_num,
        "nombre": first_name,
        "apellido": last_name,
        "rut": rut,
        "genero": gender,
        "nacionalidad": random.choice(NATIONALITIES),
        "fecha_nacimiento": generate_birth_date(),
        "estado_civil": random.choice(MARITAL_STATUS),
        "profesion": random.choice(PROFESSIONS),
        "tipo_contrato": random.choice(CONTRACT_TYPES),
        "prevision_salud": random.choice(HEALTH_PLANS),
        "email_principal": email_principal,
        "email_secundario": email_secundario,
        "telefono": phone_principal['numero'],
        "tipo_telefono": phone_principal['tipo'],
        "region": address_data['region'],
        "direccion_completa": address_data['completa'], 
        "detalle_direccion": address_data,
        "cuenta_bancaria": card_data
    }