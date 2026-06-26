
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

import subprocess
import os
import time
import shutil
from datetime import datetime, timedelta

# Configuración
DB_PATH = os.path.join(os.environ.get('SYSTEMDRIVE', 'C:'), 'grype_db_cache')
LOG_FILE = "historial_actualizaciones_db.log"

def log_evento(mensaje):
    """Guarda eventos en consola y en un archivo de log para auditoría."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    linea = f"[{timestamp}] {mensaje}"
    print(linea)
    with open(LOG_FILE, "a") as f:
        f.write(linea + "\n")

def check_db_status(target_path):
    """Verifica el estado de la BD post-actualización."""
    cmd = [
        "docker", "run", "--rm",
        "-v", f"{target_path}:/db_cache",
        "-e", "GRYPE_DB_CACHE_DIR=/db_cache",
        "anchore/grype:latest", "db", "status"
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout.lower()

def update_grype_db(target_path):
    start_time = time.perf_counter()
    log_evento("=== Iniciando ciclo de actualización de base de datos === ")

    try:
        # 1. Limpieza preventiva
        if os.path.exists(target_path):
            log_evento("[*] Limpiando base de datos antigua para asegurar integridad...")
            shutil.rmtree(target_path)
            os.makedirs(target_path)

        # 2. Descarga (Forzada por carpeta vacía)
        log_evento("[*] Descargando nueva base de datos desde los repositorios de Anchore...tiempo tentativo 15min")
        cmd_up = [
            "docker", "run", "--rm",
            "-v", f"{target_path}:/db_cache",
            "-e", "GRYPE_DB_CACHE_DIR=/db_cache",
            "anchore/grype:latest", "db", "update"
        ]
        subprocess.run(cmd_up, capture_output=True, text=True, check=True)
        
        # 3. Validación de integridad
        status = check_db_status(target_path)
        if "status: valid" in status:
            log_evento("[OK] Base de datos verificada y validada correctamente.")
        else:
            log_evento("[!] Alerta: La base se actualizó pero el estado no es 'valid'.")

    except Exception as e:
        log_evento(f"[!] Error crítico: {str(e)}")
    finally:
        # 4. Cálculo de tiempo humano
        elapsed = int(time.perf_counter() - start_time)
        duration_human = str(timedelta(seconds=elapsed))
        log_evento(f"=== Proceso finalizado. Duración: {duration_human} ({elapsed} segundos) ===")


print("\n[!] AVISO LEGAL: Use solo con autorizacion. / LEGAL NOTICE: Authorized use only.\n")
if __name__ == "__main__":
    update_grype_db(DB_PATH)