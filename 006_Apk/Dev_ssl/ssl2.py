import os
import sys
import subprocess
import shutil
import argparse

# Configuración inicial
APKTOOL = "herramientas\\apktool\\apktool.jar"  # Ruta relativa o absoluta al archivo apktool.jar
APKSIGNER = "herramientas\\uber-apk-signer\\uber-apk-signer.jar"  # Ruta relativa o absoluta al archivo uber-apk-signer.jar
KEYSTORE = "my-release-key.jks"  # Clave de firma personalizada
KEY_ALIAS = "alias_name"
KEY_PASSWORD = "apuromafo"

def log(message):
    """Función para registrar mensajes."""
    print(f"[LOG] {message}")

def validate_arguments():
    """Validar argumentos del script."""
    parser = argparse.ArgumentParser(description="Herramienta para auditorías móviles: quitar SSL pinning y anti-root.")
    parser.add_argument("apk", help="Ruta al archivo APK a modificar.")
    parser.add_argument("--ssl", action="store_true", help="Quitar SSL pinning.")
    parser.add_argument("--antiroot", action="store_true", help="Quitar anti-root.")
    parser.add_argument("--all", action="store_true", help="Quitar tanto SSL pinning como anti-root.")
    args = parser.parse_args()

    if not any([args.ssl, args.antiroot, args.all]):
        parser.error("Debe especificar al menos una opción: --ssl, --antiroot o --all.")

    apk_path = args.apk
    if not os.path.isfile(apk_path):
        log(f"Error: El archivo '{apk_path}' no existe.")
        sys.exit(1)

    return args

def run_command(command, error_message="Error al ejecutar el comando"):
    """Ejecutar un comando en la terminal."""
    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        if result.stdout:
            log(result.stdout)
        if result.stderr:
            log(result.stderr)
    except subprocess.CalledProcessError as e:
        log(f"{error_message}: {e.stderr}")
        sys.exit(1)

def decompile_apk(apk_path):
    """Descompilar el APK usando apktool."""
    log("Descompilando APK...")
    output_dir = r"output\decompiled"
    
    # Eliminar el directorio de salida si ya existe
    if os.path.exists(output_dir):
        log(f"Eliminando directorio existente: {output_dir}")
        shutil.rmtree(output_dir)
    
    # Crear el directorio de salida
    os.makedirs(output_dir, exist_ok=True)
    
    # Agregar la opción '-f' para forzar la sobrescritura
    run_command(["java", "-jar", APKTOOL, "d", apk_path, "-o", output_dir, "-f"], "Error al descompilar el APK")
    log(f"APK descompilado en: {output_dir}")
    return output_dir

def modify_ssl_pinning(decompiled_dir):
    """Modificar el código para quitar SSL pinning."""
    log("Quitando SSL pinning...")
    network_security_config = os.path.join(decompiled_dir, "res\\xml\\network_security_config.xml")
    if os.path.exists(network_security_config):
        log("Bypassing SSL pinning en network_security_config.xml...")
        with open(network_security_config, "r", encoding="utf-8") as file:
            content = file.read()
        content = content.replace('<pin-set>', '<!-- <pin-set> -->')  # Comentar certificados
        with open(network_security_config, "w", encoding="utf-8") as file:
            file.write(content)

    smali_dir = os.path.join(decompiled_dir, "smali")
    for root, dirs, files in os.walk(smali_dir):
        for file in files:
            if file.endswith(".smali"):
                smali_file = os.path.join(root, file)
                with open(smali_file, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                with open(smali_file, "w", encoding="utf-8") as f:
                    for line in lines:
                        if "javax/net/ssl/TrustManager" in line or "okhttp3/CertificatePinner" in line:
                            log(f"Bypassing SSL pinning en: {smali_file}")
                            line = line.replace("invoke-virtual", "# invoke-virtual")  # Desactivar llamadas
                        f.write(line)


def modify_antiroot(decompiled_dir):
    """Modificar el código para quitar anti-root."""
    log("Quitando anti-root...")
    smali_dir = os.path.join(decompiled_dir, "smali")
    common_paths = [
        "/data/local/bin/su", "/data/local/su", "/data/local/xbin/su", "/sbin/su",
        "/system/bin/su", "/system/xbin/su", "/su/bin/su", "/data/adb/magisk",
        "/init.magisk.rc", "/data/adb/ksu", "/data/adb/ksud"
    ]
    root_packages = [
        "com.noshufou.android.su", "eu.chainfire.supersu", "com.koushikdutta.superuser",
        "com.topjohnwu.magisk", "me.weishu.kernelsu"
    ]

    for root, dirs, files in os.walk(smali_dir):
        for file in files:
            if file.endswith(".smali"):
                smali_file = os.path.join(root, file)
                with open(smali_file, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                with open(smali_file, "w", encoding="utf-8") as f:
                    for line_number, line in enumerate(lines, start=1):
                        # Bypass file checks
                        if any(path in line for path in common_paths):
                            log(f"Bypassed file check en: {smali_file} (Línea {line_number}): {line.strip()}")
                            line = "# BYPASSED BY SCRIPT: " + line  # Añadir comentario
                        # Bypass package checks
                        if any(pkg in line for pkg in root_packages):
                            log(f"Bypassed package check en: {smali_file} (Línea {line_number}): {line.strip()}")
                            line = "# BYPASSED BY SCRIPT: " + line  # Añadir comentario
                        f.write(line)

def recompile_apk(decompiled_dir):
    """Recompilar el APK usando apktool."""
    log("Recompilando APK...")
    output_apk = "output\\repackaged.apk"
    run_command(["java", "-jar", APKTOOL, "b", decompiled_dir, "-o", output_apk], "Error al recompilar el APK")
    log(f"APK recompilado en: {output_apk}")
    return output_apk

def sign_apk(apk_path):
    """Firmar el APK usando apksigner."""
    log("Firmando APK...")
    signed_apk = "output\\signed.apk"
    run_command([
        "java", "-jar", APKSIGNER,
        "-a", apk_path,
        "--ks", KEYSTORE,
        "--ksAlias", KEY_ALIAS,
        "--ksPass", KEY_PASSWORD,
        "--ksKeyPass", KEY_PASSWORD,
        "-o", signed_apk
    ], "Error al firmar el APK")
    log(f"APK firmado en: {signed_apk}")
    return signed_apk

def clean_up(decompiled_dir):
    """Limpiar archivos temporales."""
    log("Limpiando archivos temporales...")
    if os.path.exists(decompiled_dir):
        shutil.rmtree(decompiled_dir)

def main():
    """Función principal."""
    args = validate_arguments()

    # Validar la existencia del APK
    apk_path = args.apk
    if not os.path.isfile(apk_path):
        log(f"Error: El archivo '{apk_path}' no existe.")
        sys.exit(1)

    # Descompilar el APK
    decompiled_dir = decompile_apk(apk_path)

    # Modificar según los argumentos
    if args.ssl or args.all:
        modify_ssl_pinning(decompiled_dir)
    if args.antiroot or args.all:
        modify_antiroot(decompiled_dir)

    # Recompilar el APK
    repackaged_apk = recompile_apk(decompiled_dir)

    # Firmar el APK
    signed_apk = sign_apk(repackaged_apk)

    # Limpiar archivos temporales
    clean_up(decompiled_dir)

    log(f"Auditoría completada. APK modificado disponible en: {signed_apk}")

if __name__ == "__main__":
    main()