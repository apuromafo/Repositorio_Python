# gen_manejo_errores.py

import sys
from typing import NoReturn

# =================================================================
# 1. MANEJO DE INTERRUPCIONES Y ERRORES DE SALIDA
# =================================================================

def handle_keyboard_interrupt() -> NoReturn:
    """
    Función que se llama cuando el usuario presiona Ctrl+C (KeyboardInterrupt).
    Garantiza una salida limpia del programa.
    """
    print("\n\n👋 ¡Interrupción detectada (Ctrl+C)! Finalizando el generador de forma segura.")
    print("Los archivos de exportación incompletos (si existen) pueden no ser válidos.")
    sys.exit(0) # Salida con código 0 (éxito), ya que fue una acción intencional del usuario.

def handle_generic_exception(e: Exception, context: str):
    """
    Función para manejar y reportar excepciones genéricas de forma legible.

    Args:
        e: La excepción capturada.
        context: Descripción de la parte del código que falló (e.g., "Generación de Personas").
    """
    print("\n" + "=" * 70)
    print(f"❌ ¡ERROR CRÍTICO DETECTADO EN: {context.upper()}!")
    print(f"Tipo de Error: {type(e).__name__}")
    print(f"Mensaje: {e}")
    print("=" * 70)
    print("El generador se detendrá. Por favor, revise los logs para depuración.")
    sys.exit(1) # Salida con código 1 (error).

def run_with_error_handling(main_function):
    """
    Función wrapper que ejecuta la función principal dentro de un bloque
    try-except para manejar KeyboardInterrupt y otras excepciones genéricas.
    """
    try:
        main_function()
    except KeyboardInterrupt:
        handle_keyboard_interrupt()
    except Exception as e:
        # Aquí puedes capturar el nombre de la función principal o dejar un mensaje genérico
        handle_generic_exception(e, "Flujo principal del script")

# El resto de la lógica de la aplicación no debe estar aquí.
# Este archivo solo debe contener las funciones de manejo de errores.