@echo off
rem Visor de redaccion de evidencias (PII) - Apuromafo
cd /d "%~dp0"
where python >nul 2>nul
if errorlevel 1 (
    echo Python no encontrado. Instala Python 3 y vuelve a intentar.
    pause
    exit /b 1
)
python visor_redaccion.py
if errorlevel 1 pause