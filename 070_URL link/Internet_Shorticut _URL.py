import os
import sys
import argparse
import urllib.parse

# ==========================================
# CONFIGURACIÓN Y CONSTANTES
# ==========================================
DEFAULT_PROTOCOL = "https://"

if getattr(sys, 'frozen', False):
    OUTPUT_PATH = os.path.dirname(sys.executable)
else:
    OUTPUT_PATH = os.path.dirname(os.path.abspath(__file__))

MSG_WELCOME = "--- GENERADOR DE ACCESOS DIRECTOS INTERNET (.url) ---"
MSG_INPUT_NAME = "Introduce el nombre para el archivo: "
MSG_INPUT_URL = "Introduce la URL de destino: "
MSG_SUCCESS = "Éxito: Se ha creado el acceso directo."


# ==========================================
# GESTIÓN DE DEPENDENCIAS
# ==========================================
def verificar_e_instalar_dependencias():
    """Librerías puras de Python. No requiere instalación externa."""
    pass


# ==========================================
# LÓGICA DE VALIDACIÓN Y BUSQUEDA
# ==========================================
def validar_url(url):
    """Normaliza y valida estructuralmente la URL."""
    if not url:
        return None
        
    if not url.startswith(("http://", "https://")):
        url = DEFAULT_PROTOCOL + url

    parsed = urllib.parse.urlparse(url)
    if not parsed.netloc:
        return None
        
    return url


def obtener_ruta_disponible(nombre_base):
    """Calcula un nombre disponible añadiendo sufijos (_1, _2, _n)."""
    contador = 1
    nombre_archivo = f"{nombre_base}.url"
    ruta_final = os.path.join(OUTPUT_PATH, nombre_archivo)
    
    while os.path.exists(ruta_final):
        nombre_archivo = f"{nombre_base}_{contador}.url"
        ruta_final = os.path.join(OUTPUT_PATH, nombre_archivo)
        contador += 1
        
    return ruta_final, nombre_archivo


def verificar_permisos_escritura():
    """Valida si el directorio de destino permite la creación de archivos."""
    if not os.access(OUTPUT_PATH, os.W_OK):
        print(f"Error: No hay permisos de escritura en la carpeta: {OUTPUT_PATH}", file=sys.stderr)
        return False
    return True


# ==========================================
# LÓGICA DE ESCRITURA
# ==========================================
def crear_acceso_directo_url(ruta_final, url):
    """Escribe el archivo en el disco sin try-except internos."""
    contenido = f"[InternetShortcut]\nURL={url}\n"
    
    with open(ruta_final, "w", encoding="utf-8") as archivo:
        archivo.write(contenido)
        
    if os.name != "nt":
        os.chmod(ruta_final, 0o644)


# ==========================================
# PROCESO PRINCIPAL
# ==========================================
def ejecutar_aplicacion():
    """Controla el flujo de la aplicación validando datos defensivamente."""
    if not verificar_permisos_escritura():
        return

    # Configuración del CLI
    parser = argparse.ArgumentParser(description="Generador .url")
    parser.add_argument("-d", "--descripcion", type=str)
    parser.add_argument("-u", "--url", type=str)
    args = parser.parse_args()

    # Selección de origen de datos (CLI o Consola)
    if args.descripcion or args.url:
        nombre_entrada = args.descripcion.strip() if args.descripcion else ""
        url_input = args.url.strip() if args.url else ""
    else:
        print(MSG_WELCOME)
        print(f"Ruta de destino: {OUTPUT_PATH}\n")
        nombre_entrada = input(MSG_INPUT_NAME).strip()
        url_input = input(MSG_INPUT_URL).strip()

    # Validaciones defensivas de las entradas
    if not nombre_entrada:
        print("Error: El nombre no puede estar vacío.", file=sys.stderr)
        return

    url_validada = validar_url(url_input)
    if not url_validada:
        print("Error: La URL no es válida o está vacía.", file=sys.stderr)
        return

    # Resolución de rutas y guardado seguro
    ruta_final, nombre_final = obtener_ruta_disponible(nombre_entrada)
    crear_acceso_directo_url(ruta_final, url_validada)
    
    print(f"\n{MSG_SUCCESS}")
    print(f"Archivo: {nombre_final}")


# ==========================================
# PUNTO DE ENTRADA ÚNICO (Captura limpia)
# ==========================================
if __name__ == "__main__":
    try:
        ejecutar_aplicacion()
    except KeyboardInterrupt:
        print("\n\nProceso interrumpido por el usuario.")
    except Exception as error_fatal:
        print(f"\n\nOcurrió un error inesperado: {error_fatal}", file=sys.stderr)
    finally:
        if len(sys.argv) == 1:
            try:
                input("\nPresiona Enter para salir...")
            except (KeyboardInterrupt, EOFError):
                pass