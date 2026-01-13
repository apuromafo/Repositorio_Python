import os
import requests
import json

# --- Configuración ---
OLLAMA_API_URL = "http://localhost:11434/api/generate"
MODELO_OLLAMA = "mistral"  # Cambia esto si usas un modelo diferente (e.g., "llama3")
NOMBRE_ARCHIVO_A_REVISAR = "demo.txt"

def revisar_ortografia_con_ollama(ruta_archivo: str, modelo: str) -> None:
    """
    Lee un archivo de texto y envía su contenido a un modelo local de Ollama 
    para corrección ortográfica y contextual.
    """
    print(f"⚙️ Conectando con Ollama y el modelo **{modelo}**...")
    
    try:
        with open(ruta_archivo, 'r', encoding='utf-8') as f:
            texto_a_revisar = f.read()
    except FileNotFoundError:
        print(f"❌ Error: El archivo '{ruta_archivo}' no fue encontrado.")
        return

    # --- 1. Definición del Prompt (La clave de la IA) ---
    # Este prompt le indica a la IA su tarea y el formato de salida deseado.
    prompt_ia = f"""
    Eres un revisor de documentos experto. Tu tarea es analizar el siguiente texto de un formulario legal/comercial.

    Instrucciones:
    1. **Identifica** únicamente las faltas de ortografía (errores de tildes, letras o tipeo) y los errores gramaticales flagrantes.
    2. **Ignora** los nombres propios, acrónimos (como FATCA, IRS, RUT, COD), nombres de empresas (Coopeuch), y anglicismos de uso común (marketing, online, email).
    3. **Formato de Salida:** Para cada error que encuentres, devuelve la palabra original y su corrección, separadas por un guion. No incluyas explicaciones.
    4. **Ejemplo de Salida:**
        DECLARACION - Declaración
        CELULARTELEFONO - Celular/Teléfono
        
    TEXTO A REVISAR:
    ---
    {texto_a_revisar}
    ---
    """

    # --- 2. Preparación de la Carga Útil (Payload) ---
    payload = {
        "model": modelo,
        "prompt": prompt_ia,
        "stream": False,  # No necesitamos el streaming de la respuesta
        "options": {
            "temperature": 0.0,  # Queremos una respuesta lógica, no creativa
        }
    }

    # --- 3. Llamada a la API ---
    try:
        response = requests.post(OLLAMA_API_URL, json=payload, timeout=120)
        response.raise_for_status()  # Lanza un error para códigos de estado HTTP 4xx/5xx

        data = response.json()
        correcciones = data.get("response", "").strip()

        print("-" * 50)
        print("✅ **Correcciones Contextuales Sugeridas por el LLM:**\n")
        print(correcciones)
        print("-" * 50)

    except requests.exceptions.ConnectionError:
        print("\n❌ **ERROR DE CONEXIÓN:** Asegúrate de que **Ollama** esté corriendo y que el modelo **mistral** (o el que uses) esté descargado. URL de la API: http://localhost:11434")
    except requests.exceptions.RequestException as e:
        print(f"\n❌ **ERROR DE SOLICITUD:** Ocurrió un error al llamar a la API: {e}")


if __name__ == '__main__':
    # Creación de un archivo de prueba con los errores contextuales originales
    if not os.path.exists(NOMBRE_ARCHIVO_A_REVISAR):
        # Texto original de tu solicitud con los errores de tilde y tipeo.
        contenido_original_formulario = """
        demo
        """
        with open(NOMBRE_ARCHIVO_A_REVISAR, 'w', encoding='utf-8') as f:
             f.write(contenido_original_formulario.strip())
        print(f"📝 Archivo de ejemplo **{NOMBRE_ARCHIVO_A_REVISAR}** creado con el texto del formulario original.")
        
    revisar_ortografia_con_ollama(NOMBRE_ARCHIVO_A_REVISAR, MODELO_OLLAMA)