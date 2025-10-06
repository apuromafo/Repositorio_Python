import requests
import json
import uuid
import sys
import random
import string

# ==============================================================================
# --- 0. CONFIGURACIÓN DEL PROYECTO ---
# ==============================================================================

FIREBASE_CONFIG = {
    "apiKey": "AIzaSy_DUMMY_API_KEY_PLACEHOLDER",
    "authDomain": "dummy-project-id.firebaseapp.com",
    "projectId": "dummy-project-id",
    "storageBucket": "dummy-project-id.appspot.com",
    "messagingSenderId": "DUMMY_SENDER_ID",
    "appId": "1:DUMMY_SENDER_ID:web:DUMMY_APP_ID_HASH",
    "measurementId": "G-DUMMY_MEASUREMENT_ID"
}

# NOTA IMPORTANTE: TOKEN ID de EJEMPLO. 
# Para pruebas REALES de acceso AUTENTICADO, debe ser un Token ID JWT de Firebase válido.
AUTH_TOKEN = "DUMMY_JWT_TOKEN_FOR_AUTHENTICATION_SAMPLE"
PROJECT_ID = FIREBASE_CONFIG["projectId"]
STORAGE_BUCKET = FIREBASE_CONFIG["storageBucket"]
SESSION = requests.Session()
# Nodo único para las pruebas de escritura (solo usado en RTDB/CFS)
TEST_NODE = f"security-audit/{uuid.uuid4().hex}" 

# CRÍTICO PARA STORAGE: Reemplaza 'test_file_for_audit.txt' con la RUTA de un archivo 
# (por ejemplo, una imagen, un PDF, o un simple TXT) que hayas subido a tu bucket.
# Si el archivo NO existe, la prueba devolverá 404 (inconcluso).
STORAGE_TEST_FILENAME = "test_file_for_audit.txt" 
URL_STORAGE_PUBLIC_FILE = f"https://storage.googleapis.com/{STORAGE_BUCKET}/{STORAGE_TEST_FILENAME}"

# ------------------------------------------------------------------------------
# Utilidades
# ------------------------------------------------------------------------------

def get_status_color(code):
    """Devuelve el código de color ANSI según el estado para una salida más legible."""
    if code == 200:
        return "\033[92m[ÉXITO/VULNERABLE]\033[0m"  # Verde (acceso público = vulnerabilidad)
    elif code in (401, 403):
        return "\033[91m[RECHAZADO/SEGURO]\033[0m"   # Rojo (denegado = seguro)
    elif code == 404:
        return "\033[93m[404/INCONCLUSO]\033[0m"     # Amarillo
    else:
        return "\033[93m[INFO]\033[0m"


def print_separator(char, length=80):
    """Imprime una línea de separación usando el carácter especificado."""
    print(char * length)


def run_request(method, url, data=None, headers=None, description=""):
    """Ejecuta una petición HTTP y formatea la salida para auditoría."""
    print(f"\n--- Petición: {description} ({method}) ---")
    url_clean = url.strip()
    print(f"  URL: {url_clean}")
    
    # ✅ CORREGIDO: Condición completa
    if data:
        try:
            body_preview = json.dumps(data, indent=2)[:100] + "..."
        except Exception:
            body_preview = str(data)[:100] + "..."
        print(f"  Body (Datos): {body_preview}")

    try:
        # Enviar la petición
        response = SESSION.request(
            method,
            url_clean,
            data=json.dumps(data) if data else None,
            headers=headers,
            timeout=10
        )

        # Formato de estado
        color_status = get_status_color(response.status_code)
        print(f"  {color_status}  -> Código: {response.status_code}")

        # --- Procesamiento robusto de la respuesta ---
        response_data = None

        # Intentar parsear JSON solo si hay contenido
        if response.content and response.content.strip():
            try:
                parsed_content = response.json()
                if isinstance(parsed_content, dict):
                    response_data = parsed_content
            except json.JSONDecodeError:
                pass  # No es JSON válido → response_data permanece None

        # --- Manejo de respuestas NO 200 ---
        if response.status_code != 200:
            if isinstance(response_data, dict):
                error_field = response_data.get('error')

                if isinstance(error_field, dict):
                    # Caso: {"error": {"message": "...", "status": "..."}}
                    error_msg = error_field.get('message', response.text or 'Unknown error')
                    error_status = error_field.get('status', 'N/A')
                else:
                    # Caso: {"error": "404 Not Found"} → string
                    error_msg = str(error_field) if error_field is not None else response.text or 'Unknown error'
                    error_status = 'N/A'

                print(f"     -> Mensaje de Error: {str(error_msg).strip()[:100]}...")
                print(f"     -> Status del Error: {error_status}")
                return response.status_code, response_data
            else:
                # Respuesta no JSON o sin estructura
                error_text = response.text.strip() or f"<Sin mensaje> (HTTP {response.status_code})"
                print(f"     -> Mensaje de Error: {error_text[:100]}...")
                print(f"     -> Status del Error: N/A (No es objeto JSON)")
                return response.status_code, response.text

        # --- Manejo de éxito (200) ---
        else:
            if isinstance(response_data, dict):
                try:
                    preview = json.dumps(response_data, ensure_ascii=False, indent=2)[:100].replace('\n', ' ')
                except Exception:
                    preview = str(response_data)[:100]
                print(f"     -> Contenido (Previo): {preview}...")
                return response.status_code, response_data
            else:
                content_preview = (response.text.strip() or "<vacío>")[:100]
                print(f"     -> Contenido (Previo): {content_preview}...")
                return response.status_code, response.text

    except requests.exceptions.RequestException as e:
        print(f"\033[91m[!!! ERROR DE CONEXIÓN !!!]\033[0m {description}: {e}", file=sys.stderr)
        return None, {}


# ------------------------------------------------------------------------------
# 1. AUDITORÍA DE CLOUD FIRESTORE (CFS) - API REST
# ------------------------------------------------------------------------------

def audit_cloud_firestore():
    """Verifica la seguridad de lectura/escritura pública en Cloud Firestore."""
    print(f"\n{'='*10} 1. CLOUD FIRESTORE (CFS) PUBLIC ACCESS AUDIT {'='*10}")

    CFS_TEST_COLLECTION = "users"
    firestore_url_base = f"https://firestore.googleapis.com/v1/projects/{PROJECT_ID}/databases/(default)/documents/{CFS_TEST_COLLECTION}"
    url_public = f"{firestore_url_base}?key={FIREBASE_CONFIG['apiKey']}"

    print("\n--- A. ACCESO PÚBLICO (SIN AUTH) ---")

    status_read, _ = run_request(
        "GET", url_public,
        description=f"Lectura (GET) de /{CFS_TEST_COLLECTION} (Busca 403)"
    )

    write_data_public = {
        "fields": {
            "poc_test_id": {"stringValue": "VULNERABLE_WRITE"},
            "mensaje_auditoria": {"stringValue": "Intento de escritura anonima"}
        }
    }
    status_write, _ = run_request(
        "POST", url_public, write_data_public,
        description=f"Escritura (POST) en /{CFS_TEST_COLLECTION} (Busca 403)"
    )

    return {
        "cfs_read": status_read,
        "cfs_write": status_write
    }


# ------------------------------------------------------------------------------
# 2. AUDITORÍA DE CLOUD STORAGE BUCKET
# ------------------------------------------------------------------------------

def audit_storage_bucket():
    """Verifica si el Cloud Storage Bucket permite listar o leer archivos públicamente."""
    print(f"\n{'='*10} 2. CLOUD STORAGE BUCKET PUBLIC ACCESS AUDIT {'='*10}")

    storage_api_url = f"https://firebasestorage.googleapis.com/v0/b/{STORAGE_BUCKET}/o"

    print("\n--- A. ACCESO PÚBLICO (SIN AUTH) ---")

    status_file_read, _ = run_request(
        "GET", URL_STORAGE_PUBLIC_FILE.strip(),
        description=f"Lectura (GET) del archivo: {STORAGE_TEST_FILENAME} (Busca 403)"
    )

    status_list, data_list = run_request(
        "GET", storage_api_url,
        description="Listado de archivos (GET /o) (Busca 403)"
    )

    if status_list == 200 and isinstance(data_list, dict) and data_list.get("items"):
        print(f"  \033[91m[!!! ADVERTENCIA !!!]\033[0m Se listaron {len(data_list['items'])} archivos. Fuga de información de directorio.")

    print("\n--- B. ACCESO CON TOKEN (EJEMPLO) ---")
    auth_headers = {"Authorization": f"Bearer {AUTH_TOKEN}"}
    run_request(
        "GET", storage_api_url,
        headers=auth_headers,
        description="Listar archivos CON Token (Busca 200)"
    )

    return {
        "storage_file_read": status_file_read,
        "storage_list": status_list
    }


# ------------------------------------------------------------------------------
# 3. AUDITORÍA DE REALTIME DATABASE (RTDB)
# ------------------------------------------------------------------------------

def audit_realtime_database():
    """Realiza la auditoría de seguridad CRUD en RTDB (solo estructura básica)."""
    print(f"\n{'='*10} 3. REALTIME DATABASE (RTDB) PUBLIC ACCESS AUDIT {'='*10}")

    db_url_base = f"https://{PROJECT_ID}-default-rtdb.firebaseio.com"
    url_public = f"{db_url_base}/{TEST_NODE}.json"

    print(f"[*] Nodo de prueba temporal: {TEST_NODE}")
    print("\n--- A. ACCESO PÚBLICO (SIN AUTH) ---")

    write_data_public = {"warning": "Public write detected"}
    status_write, _ = run_request(
        "PUT", url_public, write_data_public,
        description="Escritura (PUT) SIN Token (Busca 403)"
    )

    status_read, _ = run_request(
        "GET", url_public,
        description="Lectura (GET) SIN Token (Busca 403)"
    )

    return {
        "rtdb_read": status_read,
        "rtdb_write": status_write
    }


# ------------------------------------------------------------------------------
# Ejecución Principal
# ------------------------------------------------------------------------------

if __name__ == "__main__":
    global vulnerable_found
    vulnerable_found = False

    if "SAMPLE" in AUTH_TOKEN or AUTH_TOKEN == "POC":
        print("\033[91m[!!!] ADVERTENCIA: Usando un token ID de EJEMPLO. Las pruebas autenticadas no son válidas.\033[0m")

    if STORAGE_TEST_FILENAME == "test_file_for_audit.txt":
        print("\033[93m[!!! CONFIGURACIÓN CRÍTICA !!!] Reemplaza 'test_file_for_audit.txt' con un archivo real subido al bucket.\033[0m")

    print_separator("#")
    print(f"INICIANDO AUDITORÍA UNIFICADA PARA PROYECTO: {PROJECT_ID}")
    print_separator("#")

    results_cfs = audit_cloud_firestore()
    results_storage = audit_storage_bucket()
    results_rtdb = audit_realtime_database()

    # ----------------------------------------------------------------------
    # INFORME FINAL DE SEGURIDAD
    # ----------------------------------------------------------------------
    print_separator("*")
    print("\033[96m               INFORME DE ACCESOS PÚBLICOS (RESUMEN)               \033[0m")
    print_separator("*")

    def print_result(service, status_code):
        global vulnerable_found
        status_label = "SEGURO"
        if status_code == 200:
            status_label = "\033[91mVULNERABLE\033[0m"
            vulnerable_found = True
        elif status_code is None:
            status_label = "ERROR"
        print(f"  - {service.ljust(25)}: {status_label} (Código HTTP: {status_code if status_code else 'N/A'})")

    print("\n[CLOUD FIRESTORE (CFS)]")
    print_result("CFS - Lectura Anónima", results_cfs.get("cfs_read"))
    print_result("CFS - Escritura Anónima", results_cfs.get("cfs_write"))

    print("\n[CLOUD STORAGE (CS)]")
    print_result(f"CS - Lectura de Archivo: {STORAGE_TEST_FILENAME}", results_storage.get("storage_file_read"))
    print_result("CS - Listado de Archivos (/o)", results_storage.get("storage_list"))

    print("\n[REALTIME DATABASE (RTDB)]")
    print_result("RTDB - Lectura Anónima", results_rtdb.get("rtdb_read"))
    print_result("RTDB - Escritura Anónima", results_rtdb.get("rtdb_write"))

    print_separator("-")

    if vulnerable_found:
        print("\033[91m🔴 VULNERABILIDAD CRÍTICA DETECTADA: Algún servicio permitió acceso sin autenticación.\033[0m")
        print("  -> Acción Inmediata: Revisa tus Reglas de Seguridad en Firebase Console.")
    else:
        print("\033[92m🟢 SEGURO (Mínimo): Todos los accesos anónimos fueron denegados (401/403).\033[0m")
        print("  -> Nota: La prueba de lectura de archivo en Storage puede fallar si el archivo no existe.")
    print_separator("*")