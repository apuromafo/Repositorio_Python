
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

import os
import requests
import subprocess
import sys
import tempfile
import logging
from argparse import ArgumentParser

# Configurar logging
def setup_logging():
    logging.basicConfig(
        filename="openssl_install.log",
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )

# Verificar si OpenSSL ya está instalado
def is_openssl_installed():
    try:
        result = subprocess.run(["openssl", "version"], capture_output=True, text=True)
        return result.returncode == 0
    except FileNotFoundError:
        return False

# Verificar permisos de administrador (solo Windows)
def check_admin_permissions():
    if sys.platform != "win32":
        return os.geteuid() == 0 if hasattr(os, 'geteuid') else True
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

# Descargar OpenSSL
def download_openssl(url):
    logging.info("Descargando OpenSSL desde: %s", url)
    response = requests.get(url)
    if response.status_code != 200:
        logging.error("Error al descargar OpenSSL. Código de estado: %d", response.status_code)
        sys.exit(1)

    temp_dir = tempfile.gettempdir()
    installer_path = os.path.join(temp_dir, "Win64OpenSSL_Light-3_4_1.exe")
    with open(installer_path, "wb") as f:
        f.write(response.content)
    logging.info("OpenSSL descargado en: %s", installer_path)
    return installer_path

# Instalar OpenSSL
def install_openssl(installer_path):
    logging.info("Instalando OpenSSL...")
    pf_path = os.environ.get('PROGRAMFILES', r'C:\Program Files')
    install_dir = os.path.join(pf_path, 'OpenSSL-Win64')
    install_command = [
        installer_path,
        "/SILENT",
        f"/DIR={install_dir}"
    ]
    result = subprocess.run(install_command, capture_output=True, text=True)
    if result.returncode != 0:
        logging.error("Error al instalar OpenSSL: %s", result.stderr)
        sys.exit(1)
    logging.info("OpenSSL instalado correctamente.")

# Configurar PATH
def configure_path():
    pf_path = os.environ.get('PROGRAMFILES', r'C:\Program Files')
    openssl_bin_path = os.path.join(pf_path, 'OpenSSL-Win64', 'bin')
    logging.info("Configurando la variable de entorno PATH...")
    try:
        current_path = os.environ.get("PATH", "")
        if openssl_bin_path not in current_path:
            os.environ["PATH"] = f"{openssl_bin_path};{current_path}"
            subprocess.run(
                f'setx PATH "{openssl_bin_path};%PATH%"',
                shell=True,
                check=True
            )
        logging.info("Variable de entorno PATH configurada correctamente.")
    except Exception as e:
        logging.error("Error al configurar PATH: %s", str(e))
        sys.exit(1)

# Validar instalación
def validate_openssl():
    logging.info("Validando la instalación de OpenSSL...")
    try:
        result = subprocess.run(["openssl", "version"], capture_output=True, text=True)
        if result.returncode == 0:
            logging.info("OpenSSL instalado correctamente: %s", result.stdout.strip())
        else:
            logging.error("Error al validar OpenSSL: %s", result.stderr)
            sys.exit(1)
    except FileNotFoundError:
        logging.error("No se encontró el comando 'openssl'. Verifica la instalación y la variable PATH.")
        sys.exit(1)

# Función principal
def main():
    setup_logging()
    logging.info("Iniciando instalación de OpenSSL...")

    # Verificar permisos de administrador
    if not check_admin_permissions():
        logging.error("Este script requiere permisos de administrador.")
        print("Este script requiere permisos de administrador. Ejecútalo como administrador.")
        sys.exit(1)

    # Parsear argumentos
    parser = ArgumentParser(description="Instalar y configurar OpenSSL automáticamente.")
    parser.add_argument(
        "--url",
        default="https://slproweb.com/download/Win64OpenSSL_Light-3_4_1.exe",
        help="URL del instalador de OpenSSL"
    )
    args = parser.parse_args()

    # Verificar si OpenSSL ya está instalado
    if is_openssl_installed():
        logging.info("OpenSSL ya está instalado.")
        print("OpenSSL ya está instalado.")
        return

    # Descargar e instalar OpenSSL
    installer_path = download_openssl(args.url)
    install_openssl(installer_path)
    configure_path()
    validate_openssl()


print("\n[!] AVISO LEGAL: Use solo con autorizacion. / LEGAL NOTICE: Authorized use only.\n")
if __name__ == "__main__":
    main()