import re
import os
from spellchecker import SpellChecker
from typing import Set

# NOTA: Asegúrate de tener instalada la librería: pip install pyspellchecker

# --- 1. DEFINICIÓN DEL DICCIONARIO PERSONALIZADO ---
# Palabras y acrónimos válidos que no están en el diccionario estándar en español,
# pero que son correctas para el formulario de Coopeuch.
PALABRAS_CONOCIDAS = {
    "fatca", "irs", "account", "compliance", "foreign", 
    "marketing", "online", "call", "center", "cod", "rut", "pac", 
    "dpto", "celulartelefono", "informaré", "infórmese", "actividades",
    "antecedentes", "autorizaciones", "correspondientes", "cuotas", 
    "descuentos", "servicios", "políticas", "movimientos", "vigencia",
    "acreencia", "abonos", "cuentas", "contratados", "operaciones",
    "reguladores", "filiales", "terceros", "sistemas", "registros",
    "relacionados", "renovaciones", "vencimientos", "siguientes",
    "estén", "podrá", "ésta", "éstas", "éstos", "comunique", "modifique",
    "declaración", "género", "económica", "participación", "recaudación", # Correcciones de tilde
    "educacional" # Aunque raro, es el término usado en el formulario
    #nombres de empresas
    
}


def revisar_ortografia(ruta_archivo: str) -> None:
    """
    Revisa la ortografía de un archivo de texto utilizando un diccionario estándar en español
    complementado con palabras específicas de un formulario legal/comercial.
    """
    print(f"⚙️ Iniciando revisión del archivo: **{ruta_archivo}**")

    # 2. Configurar SpellChecker para español y añadir las palabras personalizadas
    spell = SpellChecker(language='es')
    spell.word_frequency.load_words(PALABRAS_CONOCIDAS)

    palabras_erroneas = set()
    
    try:
        with open(ruta_archivo, 'r', encoding='utf-8') as f:
            texto = f.read()
    except FileNotFoundError:
        print(f"❌ Error: El archivo '{ruta_archivo}' no fue encontrado. ¡Asegúrate de que exista!")
        return
    except Exception as e:
        print(f"❌ Error al leer el archivo: {e}")
        return

    # 3. Tokenizar y filtrar: Encontrar todas las palabras y convertirlas a minúsculas.
    # Se añade \. para capturar palabras con tildes que faltaban en el ejemplo anterior
    palabras_totales = re.findall(r'[a-zA-ZáéíóúüñÁÉÍÓÚÜÑ]+', texto.lower())

    # 4. Encontrar las palabras mal escritas o desconocidas
    palabras_erroneas = spell.unknown(palabras_totales)

    print("-" * 50)
    
    if palabras_erroneas:
        print("🚨 **Faltas de Ortografía Detectadas:**\n")
        
        # 5. Generar y mostrar sugerencias
        for palabra_mal_escrita in sorted(palabras_erroneas):
            
            sugerencia = spell.correction(palabra_mal_escrita)
            
            if sugerencia is not None and sugerencia != palabra_mal_escrita:
                print(f"• **'{palabra_mal_escrita.capitalize()}'** -> Sugerencia: '{sugerencia.capitalize()}'")
            else:
                 candidatos_raw = spell.candidates(palabra_mal_escrita)
                 
                 if candidatos_raw:
                    mejores_candidatos = list(candidatos_raw)
                    print(f"• **'{palabra_mal_escrita.capitalize()}'** -> Sugerencia no clara. Posibles: {', '.join(c.capitalize() for c in mejores_candidatos[:3])}")
                 else:
                    print(f"• **'{palabra_mal_escrita.capitalize()}'** -> Sin sugerencias encontradas.")

    else:
        print("✅ **¡El documento no contiene faltas de ortografía (según el diccionario)!**")
        
    print("-" * 50)
    print("✨ Revisión finalizada.")


if __name__ == '__main__':
    NOMBRE_ARCHIVO_A_REVISAR = "demo.txt" 
    
    # Este bloque debe contener el texto EXACTO del formulario que me enviaste al inicio, 
    # incluyendo las faltas de ortografía originales como "Declaracion", "Genero", etc.
    revisar_ortografia(NOMBRE_ARCHIVO_A_REVISAR)