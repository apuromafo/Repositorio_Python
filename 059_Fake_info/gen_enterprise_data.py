# gen_enterprise_data.py

import random
from typing import Dict, List, Any
from gen_chile_base import generate_enterprise_rut, generate_address
from gen_person_data import generate_birth_date, FIRST_NAMES, LAST_NAMES
from gen_financial import generate_phone_data, PHONE_PREFIXES_LANDLINE, PHONE_PREFIXES_MOBILE, numberGen

# =================================================================
# 1. CONSTANTES
# =================================================================

COMPANY_SUFFIX = ("SpA", "Ltda", "E.I.R.L.", "S.A.")
COMPANY_STATUS = ("Activa", "Inactiva (Cierre Temporal)", "En Liquidación")
COMPANY_SEGMENTS = ("Microempresa", "Pequeña Empresa (Pyme)", "Mediana Empresa (Pyme)", "Gran Empresa")
COMPANY_BASES = ("Constructora", "Servicios Integrales", "Distribuidora", "Tecnología", "Asesoría")
COMPANY_ACTIVITIES = ("Servicios de TI", "Comercio Mayorista", "Arriendo de Inmuebles", 
                      "Consultoría Financiera", "Venta al por Menor", "Construcción Civil")
EMAIL_DOMAINS_ENT = ("empresa.cl", "corporativo-test.net", "datos-chile.org")

# =================================================================
# 2. FUNCIÓN DE GENERACIÓN PRINCIPAL
# =================================================================

def generate_fake_enterprise_data(id_num: int) -> Dict[str, Any]:
    """Genera un registro completo de Empresa con datos tributarios y operacionales."""
    
    # Generación de datos modulares
    rut = generate_enterprise_rut()
    address_data = generate_address()
    
    # 1. Datos Legales y Razón Social
    business_activity = random.choice(COMPANY_ACTIVITIES)
    business_name_base = random.choice(COMPANY_BASES)
    legal_suffix = random.choice(COMPANY_SUFFIX)
    razon_social = f"{business_name_base} {business_activity.split(' ')[0]} {legal_suffix}"
    
    # 2. Contacto
    phone_principal = f"{random.choice(PHONE_PREFIXES_MOBILE)} {numberGen(8)}"
    phone_rrhh = f"{random.choice(PHONE_PREFIXES_LANDLINE)} {numberGen(7)}"
    email_principal = f"{razon_social.lower().replace('.', '').replace(' ', '')}{numberGen(2)}@{random.choice(EMAIL_DOMAINS_ENT)}"
    
    # 3. Representante Legal
    rep_legal_name = f"{random.choice(FIRST_NAMES)} {random.choice(LAST_NAMES)}"
    
    return {
        "id": id_num,
        "rut": rut,
        "razon_social": razon_social,
        "nombre_fantasia": f"Los {random.choice(LAST_NAMES)} {legal_suffix}",
        "tipo_legal": legal_suffix,
        "giro_economico": business_activity,
        "segmento_tamano": random.choice(COMPANY_SEGMENTS),
        "estado_operacional": random.choice(COMPANY_STATUS),
        "fecha_inicio_actividades": generate_birth_date(min_age=1, max_age=30), # Antigüedad de 1 a 30 años
        "representante_legal": rep_legal_name,
        "email_principal": email_principal,
        "telefono_principal": phone_principal,
        "telefono_rrhh": phone_rrhh,
        "direccion_tributaria": address_data['completa'],
        "detalle_direccion": address_data,
    }