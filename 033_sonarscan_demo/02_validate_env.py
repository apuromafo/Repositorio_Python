# 01_validate_env.py
# Versión: 1.0.1 (Ahora es ejecutable independientemente y multiplataforma)

import os
import re
import platform

def validate_sonar_path():
    """
    Busca rutas relacionadas con SonarScanner en la variable de entorno PATH.
    Es compatible con Windows, Linux y macOS.
    
    Retorna una lista de las rutas encontradas.
    """
    print("\n\n🔎 [Paso 1: Validación de Entorno]")
    print("Buscando rutas que contengan 'sonar' en la variable PATH...")
    
    # Intenta obtener la variable PATH.
    # El orden de búsqueda (PATH o Path) es más relevante en Windows,
    # pero usamos el estándar de Python para obtener la variable de entorno.
    # En Windows, os.environ.get('PATH') ya suele resolver el problema de mayúsculas/minúsculas.
    path_variable = os.environ.get('PATH')
    
    if not path_variable:
        # Si la variable principal (PATH) no se encuentra, intentamos con Path (Windows)
        path_variable = os.environ.get('Path')
    
    if not path_variable:
        print("❌ Variable de entorno PATH no encontrada.")
        return []

    # Divide el string PATH usando el separador de ruta del sistema operativo
    # os.pathsep es ';' en Windows y ':' en Linux/macOS, garantizando compatibilidad.
    path_list = path_variable.split(os.pathsep)

    # Filtra las rutas que contienen 'sonar' (ignorando mayúsculas/minúsculas)
    sonar_paths = [
        path.strip()
        for path in path_list
        # Usamos re.search para encontrar 'sonar' en cualquier parte de la ruta.
        if re.search(r'sonar', path, re.IGNORECASE) and path.strip()
    ]

    if sonar_paths:
        print(f"✅ ¡Éxito! Se encontraron {len(sonar_paths)} rutas relacionadas con SonarScanner:")
        for path in sonar_paths:
            print(f"   -> {path}")
    else:
        print("⚠️ Advertencia: No se encontraron rutas que contengan 'sonar' en la variable PATH.")
        
        # Sugerencia específica según el sistema operativo
        sistema_os = platform.system().lower()
        if sistema_os == 'windows':
            print("   (Si acabas de instalarlo, recuerda abrir una NUEVA terminal de PowerShell/CMD.)")
        else:
            print("   (Si acabas de instalarlo, revisa tu archivo ~/.bashrc o ~/.zshrc y ejecuta 'source'.)")

    return sonar_paths

# --- Bloque de ejecución principal para independencia ---
if __name__ == "__main__":
    # Si se ejecuta este script directamente (python 01_validate_env.py),
    # se llama a la función de validación.
    validate_sonar_path()