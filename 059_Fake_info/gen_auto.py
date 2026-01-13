# gen_auto.py (v4.0.0 - Coherencia Estricta por Modelo)

import random
import datetime
from typing import Dict, Any, Tuple

# =================================================================
# 1. CONSTANTES Y DATOS DE ENTRADA
# =================================================================

# Asignación de Norma de Emisiones según el año de fabricación (Simulación Chile/Europa)
EMISSION_NORMS = {
    2020: "Euro 6d", 2018: "Euro 6c", 2014: "Euro 6b",
    2010: "Euro 5", 2005: "Euro 4", 1992: "Euro 1"
}

# Códigos de año VIN simplificados
VIN_YEAR_CODES = {2024: 'R', 2023: 'P', 2022: 'N', 2021: 'M', 2020: 'L', 2019: 'K'}


# 🎯 ESTRUCTURA CLAVE: Coherencia Estricta por Modelo
# Cada modelo define sus propios rangos y atributos válidos.
VEHICLE_COHERENT_SPECS = {
    # 🚗 Compactos/Sedanes de Entrada
    "Accent": {
        "marca": "Hyundai", "carrocerias": ["Sedán"], "combustible": "Bencina",
        "ano_min": 2012, "ano_max": 2020,
        "cilindradas_cc": [1400, 1600], 
        "transmisiones": ["Manual", "Automática"],
    },
    
    # 🚙 Sedanes Medianos/Premium
    "Corolla": {
        "marca": "Toyota", 
        "carrocerias": ["Sedán"], # <--- AJUSTE: Limitado a Sedán para mayor estrictez
        "combustible": "Bencina",
        "ano_min": 2018, "ano_max": 2024,
        "cilindradas_cc": [1800, 2000],
        "transmisiones": ["CVT", "Automática"],
    },
    # NUEVO: Entrada para la variante Hatchback (si es necesario un nombre diferente)
    "Corolla Sport": { 
        "marca": "Toyota", 
        "carrocerias": ["Hatchback"], 
        "combustible": "Bencina",
        "ano_min": 2018, "ano_max": 2024,
        "cilindradas_cc": [1800, 2000], 
        "transmisiones": ["CVT", "Automática"],
    },
    "Clase C": {
        "marca": "Mercedes-Benz", "carrocerias": ["Sedán"], "combustible": "Bencina",
        "ano_min": 2018, "ano_max": 2022,
        "cilindradas_cc": [1500, 2000, 3000], 
        "transmisiones": ["Automática"], # <--- AJUSTE: Eliminado "CVT"
    },
    
    # 🚨 Carrocería corregida para Mazda 3
    "3": {
        "marca": "Mazda", "carrocerias": ["Sedán", "Hatchback"], 
        "combustible": "Bencina",
        "ano_min": 2017, "ano_max": 2023,
        "cilindradas_cc": [1500, 2000, 2500],
        "transmisiones": ["Automática", "Manual"],
    },

    # 🏞️ SUV Medianos
    "Qashqai": {
        "marca": "Nissan", "carrocerias": ["SUV"], "combustible": "Bencina",
        "ano_min": 2018, "ano_max": 2023,
        "cilindradas_cc": [1300, 2000], 
        "transmisiones": ["CVT", "Manual"],
    },
    "Sportage": {
        "marca": "Kia", "carrocerias": ["SUV"], "combustible": "Bencina",
        "ano_min": 2016, "ano_max": 2024,
        "cilindradas_cc": [1600, 2000], 
        "transmisiones": ["Automática", "Manual"],
    },
    
    # 🚚 Camionetas Diésel
    "Ranger": {
        "marca": "Ford", "carrocerias": ["Camioneta"], "combustible": "Diésel",
        "ano_min": 2015, "ano_max": 2024,
        "cilindradas_cc": [2000, 3000, 3200],
        "transmisiones": ["Automática", "Manual"],
    },
    "L200": {
        "marca": "Mitsubishi", "carrocerias": ["Camioneta"], "combustible": "Diésel",
        "ano_min": 2016, "ano_max": 2024,
        "cilindradas_cc": [2400, 2500],
        "transmisiones": ["Automática", "Manual"],
    },

    # ⚡ Eléctricos
    "Model 3": {
        "marca": "Tesla", "carrocerias": ["Hatchback"], "combustible": "Eléctrico",
        "ano_min": 2021, "ano_max": 2024, "cilindradas_cc": [0], 
        "transmisiones": ["Automática"],
    },
    "Dolphin": {
        "marca": "BYD", "carrocerias": ["Hatchback"], "combustible": "Eléctrico",
        "ano_min": 2023, "ano_max": 2024, "cilindradas_cc": [0], 
        "transmisiones": ["Automática"],
    },
}

MODEL_LIST = list(VEHICLE_COHERENT_SPECS.keys())


# =================================================================
# 2. FUNCIONES DE GENERACIÓN DE DATOS BASE
# =================================================================

def _generate_license_plate() -> str:
    """Genera una patente chilena válida (formato AA-BB-11 o BB-BB-11)."""
    letters = lambda count: "".join(random.choices("BCDFGHJKLMNPQRSTVWXYZ", k=count))
    numbers = lambda count: "".join(random.choices("0123456789", k=count))
    # Genera el formato simplificado más común
    if random.choice([True, True, False]):
        return f"{letters(2)}-{letters(2)}-{numbers(2)}"
    else:
        return f"{letters(2)}-{letters(2)}-{numbers(2)}"

def _generate_vin(year: int) -> str:
    """Genera un VIN (Número de Identificación Vehicular) simulado."""
    year_code = VIN_YEAR_CODES.get(year, random.choice(list(VIN_YEAR_CODES.values()))) 
    vin_prefix = "".join(random.choices("ABCDEFGHIJKLMNPQRSTUVWXYZ0123456789", k=9))
    vin_serial = "".join(random.choices("0123456789", k=6))
    return f"{vin_prefix[:9]}{year_code}{vin_serial}"
    
def _get_engine_data_from_cc(cilindrada_cc: int) -> Tuple[float, int]:
    """
    Deriva Litros de la Cilindrada (CC) seleccionada. Garantiza la coherencia 1L=1000CC.
    """
    if cilindrada_cc == 0:
        return 0.0, 0
        
    motor_litros = round(cilindrada_cc / 1000.0, 1) 
    return motor_litros, cilindrada_cc

def _get_emission_norm(year: int) -> str:
    """Asigna la norma de emisión coherente según el año del vehículo."""
    for min_year, norm in sorted(EMISSION_NORMS.items(), reverse=True):
        if year >= min_year:
            return norm
    return "No aplica (Pre-Euro)"


# =================================================================
# 3. FUNCIÓN DE GENERACIÓN PRINCIPAL
# =================================================================

def generate_fake_vehicle_data(id_num: int) -> Dict[str, Any]:
    """Genera un registro completo de vehículo con coherencia estricta de modelo."""
    
    # 1. Selección del Modelo y Extracción de Atributos Válidos
    modelo_nombre = random.choice(MODEL_LIST)
    specs = VEHICLE_COHERENT_SPECS[modelo_nombre]
    
    # Seleccionar año dentro del rango válido
    year = random.randint(specs["ano_min"], specs["ano_max"])
    
    # 2. Selección de Atributos Coherentes
    marca = specs["marca"]
    carroceria = random.choice(specs["carrocerias"]) # Uso de valores válidos del modelo
    combustible = specs["combustible"]
    transmision = random.choice(specs["transmisiones"]) # Uso de valores válidos del modelo
    
    # 3. Generación de Motor Coherente
    cilindrada_cc = random.choice(specs["cilindradas_cc"]) # Uso de motores de fábrica
    motor_litros, cilindrada_cc = _get_engine_data_from_cc(cilindrada_cc)
    
    # 4. Generación de Identificadores y Datos Secundarios
    patente = _generate_license_plate()
    vin = _generate_vin(year)
    norma_emision = _get_emission_norm(year) 
    color = random.choice(["Gris", "Blanco", "Negro", "Rojo", "Azul", "Plata"])
    
    # 5. Cálculo del valor fiscal (se mantiene)
    current_year = datetime.date.today().year
    age = current_year - year
    base_value = random.randrange(10000000, 30000000)
    if combustible == "Eléctrico": base_value += 15000000
    
    depreciation_factor = min(age * 0.07, 0.8)
    valor_fiscal = int(base_value * (1 - depreciation_factor))
    valor_fiscal = max(1000000, valor_fiscal) 
    
    return {
        "id": id_num,
        "patente": patente,
        "vin": vin,
        "marca": marca,
        "modelo": modelo_nombre,
        "ano_fabricacion": year,
        "carroceria": carroceria,
        "color": color,
        "combustible": combustible,
        "motor_litros": motor_litros,
        "cilindrada_cc": cilindrada_cc,
        "transmision": transmision,
        "norma_emision": norma_emision, 
        "valor_fiscal_clp": f"${valor_fiscal:,.0f}".replace(",", "."), 
        "estado_registro": random.choice(["Activo", "Prenda", "Robado (Falso)", "Baja Temporal"])
    }