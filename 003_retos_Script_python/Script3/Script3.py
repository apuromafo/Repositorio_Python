#!/usr/bin/env python
# -*- coding: utf-8 -*-
# autor @Apuromafo

description = 'Juego de Adivinar el Número (CLI) en el rango 1-300 con seguimiento de partidas y tiempo límite.'
author = 'Apuromafo'
version = '2.2.0' # Versión con manejo de KeyboardInterrupt y SystemExit
date = '06.10.2025'
"""
Proyecto: Adivina el Número (Guess the Number)
Requisitos:
- CLI amigable y modular.
- Rango de números: 1 a 300.
- El usuario tiene un total de 10 intentos para adivinar.
- Incluye contador de juegos y tiempo límite de 60 segundos por intento (compatible con Windows).
- Strings separados para futuro multiidioma.
- Manejo de error para salida limpia (Ctrl+C).
"""

import random
import time
import sys
import threading
from queue import Queue, Empty

# ==============================================================================
# 1. STRINGS Y CONFIGURACIÓN
# ==============================================================================

# Configuración del juego
MIN_NUMERO = 1
MAX_NUMERO = 300
MAX_INTENTOS = 10
TIEMPO_LIMITE_SEG = 60
TIEMPO_PREPARACION_SEG = 3 # Reducido a 3s para prueba

# Diccionario para mensajes multiidioma (ESPAÑOL)
STRINGS = {
    'es': {
        'salida_limpia': "\n\n👋 ¡Juego terminado! Vuelve pronto.",
        'bienvenida': "👋 ¡Bienvenido al Gestor de Adivina el Número!",
        'comienzo': "\n" + "="*45 + "\n       *** COMIENZA EL JUEGO #{numero_juego} ***\n",
        'rango_intentos': "El número está entre {min_num} y {max_num}. Tienes {max_intentos} intentos.",
        'limite_tiempo': "       ** Límite de {segundos} segundos ({minutos} minuto) por respuesta **\n" + "="*45,
        'preparacion': "\n⏳ **PREPÁRATE:** El tiempo límite comienza en {segundos}...",
        'intentos_restantes': "\nIntentos restantes: **{restantes}** (Límite: {tiempo} seg)",
        'input_prompt': "Introduce tu adivinanza: ",
        'timeout': "\n\n⏱️ ¡Tiempo agotado! Tu respuesta tardó más de {segundos} segundos.",
        'fuera_rango': "⚠️ Número fuera de rango. Debe ser entre {min_num} y {max_num}.",
        'no_valido': "❌ Entrada no válida. Por favor, introduce un **número entero**.",
        'victoria_msg': "\n🎉 **¡FELICIDADES!** ¡Has adivinado el número secreto!",
        'victoria_detalle': "El número era el **{secreto}**. Lo lograste en {intentos} intentos.",
        'tiempo_total': "Tu tiempo de juego fue de **{tiempo_total} segundos**.",
        'pista_bajo': "⬆️  ¡Demasiado bajo! Intenta con un número mayor.",
        'pista_alto': "⬇️  ¡Demasiado alto! Intenta con un número menor.",
        'derrota_msg': "\n" + "="*45 + "\n¡Oh no! 😔 Te has quedado sin intentos.",
        'derrota_detalle': "**HAS PERDIDO.** El número secreto era el **{secreto}**.\n" + "="*45,
        'jugar_denuevo': "\n¿Quieres jugar de nuevo? (s/n): ",
        'gracias_jugar': "\n¡Gracias por jugar! Total de partidas jugadas: **{total}**.",
        'respuesta_invalida': "Respuesta no válida. Por favor, introduce 's' o 'n'."
    }
}
# Definir idioma actual
LANG = STRINGS['es'] 

# ==============================================================================
# 2. FUNCIONES DE SOPORTE (Timeouts y CLI)
# ==============================================================================

def worker_input(q):
    """Función ejecutada en un hilo para obtener la entrada del usuario."""
    try:
        user_input = input(LANG['input_prompt'])
        q.put(user_input)
    except Exception:
        # Captura cualquier error de entrada inesperado y asegura el retorno
        q.put(None)

def input_con_limite(segundos):
    """Ejecuta la entrada en un hilo con el límite de tiempo configurado."""
    q = Queue()
    input_thread = threading.Thread(target=worker_input, args=(q,))
    input_thread.daemon = True
    input_thread.start()
    
    try:
        respuesta = q.get(timeout=segundos)
        return respuesta
    except Empty:
        print(LANG['timeout'].format(segundos=segundos))
        return None
    except Exception:
        # Aquí también capturamos errores del hilo para evitar fallos
        return None

def preparar_intento():
    """Muestra un contador regresivo visible antes de la entrada."""
    for i in range(TIEMPO_PREPARACION_SEG, 0, -1):
        print(LANG['preparacion'].format(segundos=i), end='\r')
        time.sleep(1)
    # Limpia la línea del contador
    print(" " * 50, end='\r')
    
def procesar_entrada(intento_str):
    """Valida y convierte la entrada del usuario a entero, manejando errores."""
    
    # 1. Intenta convertir y validar el rango
    try:
        intento_usuario = int(intento_str.strip())
        
        if not (MIN_NUMERO <= intento_usuario <= MAX_NUMERO):
            print(LANG['fuera_rango'].format(min_num=MIN_NUMERO, max_num=MAX_NUMERO))
            return None
            
        return intento_usuario
        
    # 2. Manejo de error de formato
    except ValueError:
        print(LANG['no_valido'])
        return None
    
# ... (Funciones mostrar_estado_inicial y mostrar_resultado_final son iguales)
def mostrar_estado_inicial(numero_juego):
    """Muestra los mensajes de inicio de la partida."""
    minutos = TIEMPO_LIMITE_SEG // 60
    print(LANG['comienzo'].format(numero_juego=numero_juego))
    print(LANG['rango_intentos'].format(min_num=MIN_NUMERO, max_num=MAX_NUMERO, max_intentos=MAX_INTENTOS))
    print(LANG['limite_tiempo'].format(segundos=TIEMPO_LIMITE_SEG, minutos=minutos))

def mostrar_resultado_final(victoria, intentos_usados, numero_secreto, tiempo_inicio):
    """Muestra el resultado final (Victoria o Derrota)."""
    if victoria:
        tiempo_fin = time.time()
        tiempo_total = round(tiempo_fin - tiempo_inicio)
        print(LANG['victoria_msg'])
        print(LANG['victoria_detalle'].format(secreto=numero_secreto, intentos=intentos_usados))
        print(LANG['tiempo_total'].format(tiempo_total=tiempo_total))
    else:
        print(LANG['derrota_msg'])
        print(LANG['derrota_detalle'].format(secreto=numero_secreto))


# ==============================================================================
# 3. LÓGICA PRINCIPAL DEL JUEGO
# ==============================================================================

def jugar_adivina_el_numero(numero_juego):
    """Contiene la lógica de una sola partida, enfocándose en el flujo."""
    
    numero_secreto = random.randint(MIN_NUMERO, MAX_NUMERO)
    intentos_restantes = MAX_INTENTOS
    tiempo_inicio = time.time()
    
    mostrar_estado_inicial(numero_juego)

    while intentos_restantes > 0:
        
        print(LANG['intentos_restantes'].format(restantes=intentos_restantes, tiempo=TIEMPO_LIMITE_SEG))
        
        preparar_intento()
        intento_str = input_con_limite(TIEMPO_LIMITE_SEG)
        
        # 1. Manejo de Timeout (intento_str es None)
        if intento_str is None:
            intentos_restantes -= 1
            continue 
            
        # 2. Procesamiento de la entrada (manejo de ValueError y rango)
        intento_usuario = procesar_entrada(intento_str)
        
        # Si la entrada no fue válida (ValueError o fuera de rango)
        if intento_usuario is None:
            continue
            
        # 3. Comprobar la adivinanza
        if intento_usuario == numero_secreto:
            mostrar_resultado_final(True, MAX_INTENTOS - intentos_restantes + 1, numero_secreto, tiempo_inicio)
            return True # Victoria
        elif intento_usuario < numero_secreto:
            print(LANG['pista_bajo'])
        else:
            print(LANG['pista_alto'])
            
        # 4. Restar intento
        intentos_restantes -= 1
        
    # Fin del bucle: Derrota
    mostrar_resultado_final(False, MAX_INTENTOS, numero_secreto, tiempo_inicio)
    return False

def gestor_juegos():
    """Bucle principal para controlar múltiples partidas y el contador de juegos."""
    
    contador_juegos = 0
    print(LANG['bienvenida'])
    
    while True:
        contador_juegos += 1
        jugar_adivina_el_numero(contador_juegos)
        
        # Preguntar si quiere jugar de nuevo
        while True:
            reiniciar = input(LANG['jugar_denuevo']).lower().strip()
            if reiniciar in ('s', 'si', 'y', 'yes'):
                break 
            elif reiniciar in ('n', 'no'):
                print(LANG['gracias_jugar'].format(total=contador_juegos))
                # Usamos sys.exit() para generar una SystemExit y salir limpiamente.
                sys.exit(0) 
            else:
                print(LANG['respuesta_invalida'])

# ==============================================================================
# 4. PUNTO DE ENTRADA CON MANEJO DE ERROR FINAL
# ==============================================================================

if __name__ == "__main__":
    try:
        gestor_juegos()
    except (KeyboardInterrupt, SystemExit):
        # Captura Ctrl+C y la salida limpia (sys.exit(0))
        print(LANG['salida_limpia'])