# gen_chile_base.py

import random
from typing import Dict, List, Any, Tuple

# =================================================================
# 1. CONSTANTES GEOGRÁFICAS
# =================================================================

def regions_data() -> List[Tuple[str, str, str]]:
    """Comunas, CP y Regiones (Tupla de (Comuna, CP, Región))."""
    return [
        ("Arica", "1000000", "Arica y Parinacota"), ("Iquique", "1100000", "Tarapacá"), 
        ("Antofagasta", "1240000", "Antofagasta"), ("Copiapo", "1530000", "Atacama"), 
        ("La Serena", "1700000", "Coquimbo"), ("Coquimbo", "1780000", "Coquimbo"),
        ("Valparaiso", "2340000", "Valparaíso"), ("Viña Del Mar", "2520000", "Valparaíso"), 
        ("Rancagua", "2820000", "O'Higgins"), ("Talca", "3460000", "Maule"), 
        ("Chillan", "3780000", "Ñuble"), ("Concepcion", "4030000", "Biobío"), 
        ("Temuco", "4780000", "La Araucanía"), ("Valdivia", "5090000", "Los Ríos"), 
        ("Puerto Montt", "5480000", "Los Lagos"), ("Punta Arenas", "6200000", "Magallanes"), 
        ("Santiago", "8320000", "Metropolitana"), ("Las Condes", "7550000", "Metropolitana"), 
        ("Providencia", "7500000", "Metropolitana"), ("Maipu", "9250000", "Metropolitana"), 
        ("Puente Alto", "8150000", "Metropolitana"), ("Ñuñoa", "7750000", "Metropolitana")
    ]

ADDRESS_PREFIXES = ("Avenida", "Calle", "Pasaje", "Alameda", "Transversal")

# =================================================================
# 2. FUNCIONES DE DIRECCIÓN
# =================================================================

def numberGen(digits: int) -> str:
    """Genera una cadena de números aleatorios con N dígitos."""
    return "".join(random.choices("0123456789", k=digits))

def generate_address() -> Dict[str, str]:
    """Genera una dirección completa con Región, Comuna y Código Postal consistente."""
    comuna, cp, region = random.choice(regions_data())
    address_prefix = random.choice(ADDRESS_PREFIXES)
    address_number = numberGen(random.randint(3, 4))
    
    # Usar un apellido aleatorio para el nombre de la calle
    streetNames = ("Arturo Prat", "Esmeralda", "Gabriela Mistral", "Los Alerces", "Balmaceda")
    street_name = random.choice(streetNames)
    
    street_address = f"{address_prefix} {street_name} N°{address_number}"
    full_address = f"{street_address}, {comuna}, {region}, Chile"
    
    return {
        "calle": street_address,
        "comuna": comuna,
        "region": region,
        "codigo_postal": cp,
        "completa": full_address
    }

# =================================================================
# 3. FUNCIONES DE RUT VÁLIDO
# =================================================================

def _calculate_dv(rut_body: str) -> str:
    """Implementa el algoritmo real del Dígito Verificador (DV) del RUT."""
    rut_rev = rut_body[::-1]
    multiplication_table = [2, 3, 4, 5, 6, 7] * 2 # Ciclo de 2 a 7
    
    # Calcular la suma ponderada
    total = sum(int(rut_rev[i]) * multiplication_table[i] for i in range(len(rut_body)))
    
    dv_num = 11 - (total % 11)
    if dv_num == 11:
        return "0"
    if dv_num == 10:
        return "K"
    return str(dv_num)

def dotRutFormat(rut: str) -> str:
    """Formatea un RUT completo con puntos y guion (xx.xxx.xxx-x)."""
    try:
        return f"{int(rut[:-1]):,d}-{rut[-1]}".replace(",", ".")
    except ValueError:
        return rut # En caso de error, devuelve el RUT sin formato

def generate_person_rut() -> str:
    """Genera y formatea un RUT de persona válido."""
    # RUT de persona típicamente entre 11 y 28 millones
    rut_body = str(random.randrange(11111111, 28999999))
    full_rut = f"{rut_body}{_calculate_dv(rut_body)}"
    return dotRutFormat(full_rut)

def generate_enterprise_rut() -> str:
    """Genera y formatea un RUT de empresa válido."""
    # RUT de empresa típicamente entre 76 y 79 millones
    rut_body = str(random.randrange(76111111, 79999999))
    full_rut = f"{rut_body}{_calculate_dv(rut_body)}"
    return dotRutFormat(full_rut)