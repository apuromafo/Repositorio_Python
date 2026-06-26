
# =============================================================================
# AVISO LEGAL / LEGAL NOTICE
# -----------------------------------------------------------------------------
# Esta herramienta es unicamente para fines educativos y de auditoria de
# seguridad autorizada. El uso no autorizado contra sistemas sin el
# consentimiento explicito del propietario es ilegal.
# El usuario asume toda responsabilidad por el uso indebido.
#
# This tool is for educational and authorized security auditing purposes only.
# Unauthorized use against systems without the owner's explicit consent is
# illegal. The user assumes all responsibility for misuse.
# =============================================================================

# main.py

import datetime
import os
from typing import List, Dict, Any, Tuple

# Importaciones de Módulos (Asegúrate de que estos archivos existan)
from gen_person_data import generate_fake_person_data
from gen_enterprise_data import generate_fake_enterprise_data
from gen_auto import generate_fake_vehicle_data
from gen_exporter import export_to_json, export_to_csv, export_to_txt
from gen_manejo_errores import run_with_error_handling

# =================================================================
# 🛡️ DISCLAIMER Y CONTROL DE VERSIÓN 🛡️
# =================================================================
SCRIPT_NAME = "Generador de Datos Chilenos QA - Modular"
VERSION = "4.1.0" # Versión con menú de exportación
LAST_UPDATE = datetime.date.today().strftime("%Y-%m-%d")
DEFAULT_OUTPUT_FOLDER = "output"

DISCLAIMER = (
    "🛡️ ESTE SCRIPT GENERA DATOS FALSOS PERO MATEMÁTICAMENTE VÁLIDOS (RUT/TARJETA).\n"
    "   USAR SÓLO PARA AMBIENTES DE DESARROLLO Y PRUEBAS (QA/TESTING). ⚠️\n"
    "   NO UTILIZAR EN PRODUCCIÓN O PARA FINES ILÍCITOS."
)

def print_header(title: str):
    """Imprime el encabezado principal del script."""
    print(f"\n{'=' * 70}")
    print(f" {title} v{VERSION} | Actualizado: {LAST_UPDATE} ")
    print(f"{'=' * 70}")
    print(DISCLAIMER)
    print("\nGeneración Modular (RUTs/Tarjetas Válidas. Coherencia Geográfica y Técnica).\n")

# --- Funciones de Entrada de Usuario ---

def safe_input_count(prompt: str, default: int) -> int:
    """Función auxiliar para solicitar un número entero positivo."""
    while True:
        try:
            user_input = input(f"{prompt} (Por defecto: {default}): ")
            if not user_input:
                return default
            count = int(user_input)
            if count >= 0:
                return count
            else:
                print("Por favor, ingrese un número positivo.")
        except ValueError:
            print("Entrada inválida. Por favor, ingrese un número entero.")

def get_user_input_counts() -> Tuple[int, int, int]:
    """Solicita al usuario la cantidad de registros a generar por tipo."""
    print("\n--- Configuración de la Generación ---")
    num_personas = safe_input_count("¿Cuántos registros de PERSONAS NATURALES desea generar?", 4)
    num_empresas = safe_input_count("¿Cuántos registros de EMPRESAS desea generar?", 3)
    num_vehiculos = safe_input_count("¿Cuántos registros de VEHÍCULOS desea generar?", 2)
    print("-------------------------------------\n")
    return num_personas, num_empresas, num_vehiculos

# --- Funciones de Display ---

def display_person_data(data: Dict[str, Any]):
    """Muestra un registro de persona en formato legible."""
    print(f"ID: {data['id']} | Nombre: **{data['nombre']} {data['apellido']}** ({data['genero']})")
    print(f"RUT: {data['rut']} | Nacimiento: {data['fecha_nacimiento']} | Nacionalidad: {data['nacionalidad']}")
    print(f"Estado/Profesión: {data['estado_civil']} / {data['profesion']}")
    print(f"Contrato: {data['tipo_contrato']} | Salud: {data['prevision_salud']}")
    print(f"Contacto: {data['telefono']} ({data['tipo_telefono']}) | E-mail Ppal: {data['email_principal']}")
    print(f"Dirección ({data['region']}): {data['direccion_completa']} [CP: {data['detalle_direccion']['codigo_postal']}]")
    print(f"--- Datos Bancarios ---")
    print(f"Banco/Cuenta: {data['cuenta_bancaria']['banco_institucion']}")
    print(f"Tarjeta ({data['cuenta_bancaria']['tipo_tarjeta']}): {data['cuenta_bancaria']['numero_tarjeta']} (Vence: {data['cuenta_bancaria']['vencimiento']})")
    print("=" * 70)

def display_enterprise_data(data: Dict[str, Any]):
    """Muestra un registro de empresa en formato legible."""
    print(f"ID: {data['id']} | RUT: **{data['rut']}** | Tipo Legal: {data['tipo_legal']}")
    print(f"Razón Social: {data['razon_social']} | Fantasía: {data['nombre_fantasia']}")
    print(f"Segmento: {data['segmento_tamano']} | Giro: {data['giro_economico']} | Estado: {data['estado_operacional']}")
    print(f"Fecha Inicio Act.: {data['fecha_inicio_actividades']} | Rep. Legal: {data['representante_legal']}")
    print(f"Dirección ({data['detalle_direccion']['region']}): {data['direccion_tributaria']} [CP: {data['detalle_direccion']['codigo_postal']}]")
    print(f"Teléfonos: Ppal: {data['telefono_principal']} / RRHH: {data['telefono_rrhh']}")
    print("=" * 70)

def display_vehicle_data(data: Dict[str, Any]):
    """Muestra un registro de vehículo en formato legible, incluyendo la Norma de Emisión."""
    print(f"ID: {data['id']} | Patente: **{data['patente']}** | VIN: {data['vin']}")
    print(f"Marca/Modelo: {data['marca']} {data['modelo']} | Año: {data['ano_fabricacion']}")
    print(f"Carrocería: {data['carroceria']} | Color: {data['color']} | Transmisión: {data['transmision']}")
    print(f"Combustible: {data['combustible']} | Motor: {data['motor_litros']}L ({data['cilindrada_cc']} CC)")
    print(f"Norma Emisión: {data.get('norma_emision', 'N/A')}")
    print(f"Valor Fiscal (Simulado): {data['valor_fiscal_clp']} | Estado: {data['estado_registro']}")
    print("=" * 70)


# --- Lógica de Exportación Mejorada ---

def get_export_formats() -> List[str]:
    """Solicita al usuario los formatos de exportación deseados (TXT/JSON/CSV)."""
    while True:
        print("\n--- Formatos de Exportación Disponibles ---")
        print("1. TXT (Texto Plano por Línea)")
        print("2. JSON (Ideal para APIs y Bases de Datos NoSQL)")
        print("3. CSV (Ideal para Bases de Datos Relacionales y Hojas de Cálculo)")
        
        choice = input("Seleccione formatos (e.g., 1,2,3 ó 2-3): ").strip()
        
        if not choice:
            print("Exportación omitida.")
            return []

        formats_to_export = []
        
        # 🚨 INCLUIR TXT
        if '1' in choice:
            formats_to_export.append("txt") 
            
        if '2' in choice:
            formats_to_export.append("json")
            
        if '3' in choice:
            formats_to_export.append("csv")
            
        unique_formats = sorted(list(set(formats_to_export)))
        
        if not unique_formats:
            print("❌ Opción inválida. Por favor, intente de nuevo o presione Enter para omitir.")
        else:
            print(f"⚙️ Exportando en formato(s): {', '.join(unique_formats).upper()}")
            return unique_formats

def handle_export(data_list: List[Dict[str, Any]], prefix: str, formats: List[str]):
    """Ejecuta la exportación para una lista de datos dada."""
    if not data_list:
        return

    # 🚨 NUEVA LÓGICA PARA TXT
    if "txt" in formats: 
        # Llamar a la función recién añadida
        print(export_to_txt(data_list, prefix, DEFAULT_OUTPUT_FOLDER)) 
        
    if "json" in formats:
        print(export_to_json(data_list, prefix, DEFAULT_OUTPUT_FOLDER))
    
    if "csv" in formats:
        print(export_to_csv(data_list, prefix, DEFAULT_OUTPUT_FOLDER))
# --- Función Principal ---

def run_generator():
    """Función principal para solicitar la cantidad, generar, mostrar y exportar los datos."""
    
    print_header(SCRIPT_NAME)
    
    num_personas, num_empresas, num_vehiculos = get_user_input_counts() 
    
    # Listas para almacenar los datos
    person_data_list = []
    enterprise_data_list = []
    vehicle_data_list = []

    # 1. Generación de Personas
    if num_personas > 0:
        print(f"## 👤 Datos de Personas Naturales Generados ({num_personas} Registros) ##\n")
        for i in range(1, num_personas + 1):
            person_data = generate_fake_person_data(i)
            display_person_data(person_data)
            person_data_list.append(person_data)

    # 2. Generación de Empresas
    if num_empresas > 0:
        print(f"\n## 🏢 Datos de Empresas Generados ({num_empresas} Registros) ##\n")
        for i in range(1, num_empresas + 1):
            enterprise_data = generate_fake_enterprise_data(i)
            display_enterprise_data(enterprise_data)
            enterprise_data_list.append(enterprise_data)
        
    # 3. Generación de Vehículos 
    if num_vehiculos > 0:
        print(f"\n## 🚗 Datos de Vehículos Generados ({num_vehiculos} Registros) ##\n")
        for i in range(1, num_vehiculos + 1):
            vehicle_data = generate_fake_vehicle_data(i)
            display_vehicle_data(vehicle_data)
            vehicle_data_list.append(vehicle_data)     
        
    # =========================================================
    # 4. LÓGICA DE EXPORTACIÓN CON MENÚ
    # =========================================================
    
    total_generated = num_personas + num_empresas + num_vehiculos
    print(f"\nTOTAL GENERADO: {total_generated} registros en total.")
    
    if total_generated == 0:
        print("No se generaron registros. Finalizando.")
        return

    export_formats = get_export_formats()
    
    if export_formats:
        # Crea la carpeta de salida si no existe
        if not os.path.exists(DEFAULT_OUTPUT_FOLDER):
            os.makedirs(DEFAULT_OUTPUT_FOLDER)
            print(f"\nCreando carpeta de salida: ./{DEFAULT_OUTPUT_FOLDER}")
        
        print("\n" + "=" * 70)
        print(f"INICIANDO EXPORTACIÓN A LA CARPETA: ./{DEFAULT_OUTPUT_FOLDER}")
        print("=" * 70)
        
        # Exportar los 3 tipos de datos
        handle_export(person_data_list, "personas", export_formats)
        handle_export(enterprise_data_list, "empresas", export_formats)
        handle_export(vehicle_data_list, "vehiculos", export_formats)
        
        print("\nEXPORTACIÓN FINALIZADA.")
    else:
        print("\nExportación omitida. Datos generados se mostraron en la terminal.")



print("\n[!] AVISO LEGAL: Use solo con autorizacion. / LEGAL NOTICE: Authorized use only.\n")
if __name__ == "__main__":
    run_with_error_handling(run_generator)