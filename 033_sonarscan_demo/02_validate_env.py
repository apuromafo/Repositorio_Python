# 02_validate_env.py
# Versión: 1.3.5 (ESTABLE - SIN BUCLES)
# Objetivo: Validar el PATH, limpiar rutas muertas y asegurar sincronización.

import os
import winreg
import ctypes
import subprocess
from pathlib import Path

def refrescar_sistema():
    """Avisa a Windows del cambio en las variables de entorno."""
    HWND_BROADCAST = 0xFFFF
    WM_SETTINGCHANGE = 0x001A
    ctypes.windll.user32.SendMessageTimeoutW(
        HWND_BROADCAST, WM_SETTINGCHANGE, 0, 'Environment', 0x0002, 1000, None
    )

def limpiar_y_actualizar_registro(nueva_ruta_bin):
    """Sincroniza el registro eliminando duplicados o rutas de sonar viejas."""
    try:
        reg_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Environment', 0, winreg.KEY_ALL_ACCESS)
        path_actual, _ = winreg.QueryValueEx(reg_key, 'Path')
        
        lista_paths = [p.strip() for p in path_actual.split(';') if p.strip()]
        lista_final = []
        
        # Saneamiento: Mantener rutas normales y solo la de sonar actual
        for p in lista_paths:
            if 'sonar' in p.lower():
                # Si la ruta existe y es la que queremos, la mantenemos
                if os.path.exists(p) and Path(p).resolve() == Path(nueva_ruta_bin).resolve():
                    if p not in lista_final: lista_final.append(p)
            else:
                if p not in lista_final: lista_final.append(p)

        # Asegurar que la nueva esté
        nueva_ruta_str = str(Path(nueva_ruta_bin).resolve())
        if nueva_ruta_str not in lista_final:
            lista_final.append(nueva_ruta_str)

        nuevo_path_str = ";".join(lista_final)
        winreg.SetValueEx(reg_key, 'Path', 0, winreg.REG_EXPAND_SZ, nuevo_path_str)
        winreg.CloseKey(reg_key)
        
        # Actualizar memoria del proceso actual
        os.environ["PATH"] = nuevo_path_str
        refrescar_sistema()
        return True
    except Exception as e:
        print(f"[❌] Error actualizando registro: {e}")
        return False

def main():
    print(f"\n{'='*60}\n🔍 PASO 02: VALIDACIÓN DE ENTORNO\n{'='*60}")
    
    # 1. Ruta local esperada
    base_dir = Path(os.getcwd())
    ruta_local = None
    folder_scan = base_dir / "sonarscan"
    if folder_scan.exists():
        for item in folder_scan.iterdir():
            if item.is_dir() and "sonar-scanner-" in item.name:
                bin_p = item / "bin"
                if bin_p.exists(): 
                    ruta_local = bin_p.resolve()
                    break

    # 2. Rutas actuales en memoria
    path_memoria = os.environ.get('PATH', '')
    sonar_memoria = [p for p in path_memoria.split(os.pathsep) if 'sonar' in p.lower()]
    
    # 3. Lógica de decisión
    if not ruta_local:
        print("[❌] No se detectó SonarScanner en ./sonarscan/. Ejecuta el paso 03.")
        return

    # Verificar si la ruta en memoria es la correcta
    esta_ok = False
    if sonar_memoria:
        for p in sonar_memoria:
            if Path(p).resolve() == Path(ruta_local).resolve():
                esta_ok = True
                break

    if esta_ok and len(sonar_memoria) == 1:
        print(f"[✅] El entorno ya está correctamente configurado.")
        print(f"    -> {ruta_local}")
    else:
        print(f"[!] Se requiere sincronización.")
        print(f"    Scanner local: {ruta_local}")
        if input("[?] ¿Sincronizar ahora? (s/N): ").lower() == 's':
            if limpiar_y_actualizar_registro(ruta_local):
                print("[✓] Registro saneado.")
                # Intentar test de comando
                try:
                    subprocess.run(["sonar-scanner", "-v"], shell=True, check=True)
                except:
                    print("[i] Sincronización completa. Si el comando falla en esta ventana,")
                    print("    ejecuta: $env:Path = [System.Environment]::GetEnvironmentVariable('Path','User')")

if __name__ == "__main__":
    main()