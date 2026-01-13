# gen_financial.py

import random
import datetime
from typing import Dict, List, Tuple

# =================================================================
# 1. CONSTANTES
# =================================================================

# Tipos de Tarjeta y BINs (prefijos) para Luhn
CARD_INFO = {
    "Visa": {"prefix": "4111", "sources": ["Payzen - 3DS v1", "Banco Santander (Falso)", "Banco Chile (Falso)"], "length": 16},
    "Mastercard": {"prefix": "5405", "sources": ["Banco Estado (Falso)", "Transbank", "WebPay Plus"], "length": 16}
}

BANKS = ("Banco Santander", "Banco Estado", "Banco de Chile", "BCI", "Banco Falabella")

# Prefijos separados para generar Tipo de Teléfono
PHONE_PREFIXES_MOBILE = ("+56 9") 
PHONE_PREFIXES_LANDLINE = ("+56 2", "+56 32", "+56 41", "+56 55")
PHONE_TYPES = ("Móvil", "Fijo")


# =================================================================
# 2. FUNCIONES DE CONTACTO
# =================================================================

def numberGen(digits: int) -> str:
    """Genera una cadena de números aleatorios con N dígitos."""
    return "".join(random.choices("0123456789", k=digits))

def generate_phone_data(is_mobile_preferred: bool = True) -> Dict[str, str]:
    """Genera un número de teléfono y su tipo (Móvil/Fijo)."""
    # Preferencia por móvil si se llama desde un contexto general
    if is_mobile_preferred and random.choice([True, True, False]):
        phone_type = "Móvil"
    else:
        phone_type = random.choice(PHONE_TYPES)
    
    if phone_type == "Móvil":
        prefix = random.choice(PHONE_PREFIXES_MOBILE)
        number = numberGen(8)
    else:
        prefix = random.choice(PHONE_PREFIXES_LANDLINE)
        number = numberGen(random.randint(7, 8)) 
        
    return {
        "tipo": phone_type,
        "numero": f"{prefix} {number}"
    }

# =================================================================
# 3. FUNCIONES FINANCIERAS (LUHN)
# =================================================================

def _luhn_checksum(card_number: str) -> str:
    """Calcula el dígito de control de Luhn para un prefijo de tarjeta."""
    digits = [int(d) for d in card_number]
    checksum = 0
    for i, d in enumerate(reversed(digits)):
        if (i % 2) == 0: # Duplicar cada segundo dígito
            d *= 2
            if d > 9: d -= 9
        checksum += d
    
    # El DV es el número que hace que la suma total sea divisible por 10
    return str((10 - (checksum % 10)) % 10)

def generate_card() -> Dict[str, str]:
    """Genera una tarjeta de crédito o débito con Luhn válido."""
    
    card_type = random.choice(list(CARD_INFO.keys()))
    info = CARD_INFO[card_type]
    prefix = info["prefix"]
    length = info["length"]
    
    # 1. Generar cuerpo de la tarjeta
    body_length = length - len(prefix) - 1
    card_body = numberGen(body_length)
    
    # 2. Calcular dígito de Luhn
    luhn_prefix = prefix + card_body
    luhn_digit = _luhn_checksum(luhn_prefix)
    card_number = luhn_prefix + luhn_digit
    
    # 3. Vencimiento (MM/YY) y CVV
    current_year = datetime.date.today().year
    exp_year = str(random.randint(current_year + 1, current_year + 5))[2:]
    exp_month = str(random.randint(1, 12)).zfill(2)
    cvv = numberGen(3)
    
    source = random.choice(info["sources"])

    return {
        "banco_institucion": random.choice(BANKS),
        "tipo_tarjeta": card_type,
        "numero_tarjeta": card_number,
        "vencimiento": f"{exp_month}/{exp_year}",
        "cvv": cvv,
        "bin_prueba": prefix,
        "origen_datos_prueba": source
    }