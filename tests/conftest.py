#!/usr/bin/env python3
"""
Configuración de pytest para el Repositorio Python
===================================================

Configuración global de fixtures y configuración de pytest
para tests de herramientas de seguridad.
"""

import pytest
import sys
import os

# Agregar directorios de scripts al path para importación
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS_DIRS = [
    os.path.join(BASE_DIR, '001_Analisis_header_eml'),
    os.path.join(BASE_DIR, '002_Download'),
    os.path.join(BASE_DIR, '003_retos_Script_python'),
    os.path.join(BASE_DIR, '004_juego_adivinanza'),
    os.path.join(BASE_DIR, '005_extrae_correo'),
    os.path.join(BASE_DIR, '006_Móvil', 'Android'),
    os.path.join(BASE_DIR, '008_Cabeceras_Seguridad'),
    os.path.join(BASE_DIR, '009_Rut_Chileno'),
    os.path.join(BASE_DIR, '010_malapi_json'),
    os.path.join(BASE_DIR, '012_B64'),
    os.path.join(BASE_DIR, '013_passwd'),
    os.path.join(BASE_DIR, '014_Banner_Art'),
    os.path.join(BASE_DIR, '019_Luhn'),
    os.path.join(BASE_DIR, '020_wget'),
    os.path.join(BASE_DIR, '021_sha256'),
    os.path.join(BASE_DIR, '022_rotacion'),
    os.path.join(BASE_DIR, '023_vigenere'),
    os.path.join(BASE_DIR, '037_owasp_vulns'),
    os.path.join(BASE_DIR, '068_SCA_Grype_scan'),
    os.path.join(BASE_DIR, '069_SSL_Scan'),
]

for d in SCRIPTS_DIRS:
    if os.path.isdir(d):
        sys.path.insert(0, d)


@pytest.fixture(scope="session")
def base_dir():
    """Directorio base del repositorio"""
    return BASE_DIR


@pytest.fixture(scope="function")
def temp_dir(tmp_path):
    """Directorio temporal para tests"""
    return tmp_path


@pytest.fixture(scope="function")
def mock_email_message():
    """Fixture para crear un mensaje de email mock"""
    import email
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    
    def _create_email(subject="Test", from_addr="test@example.com", 
                      to_addr="target@example.com", body="Test body",
                      headers=None, multipart=False):
        if multipart:
            msg = MIMEMultipart()
            msg.attach(MIMEText(body, "plain"))
        else:
            msg = MIMEText(body, "plain")
        
        msg["Subject"] = subject
        msg["From"] = from_addr
        msg["To"] = to_addr
        
        if headers:
            for k, v in headers.items():
                msg[k] = v
        
        return msg
    
    return _create_email


@pytest.fixture(scope="function")
def sample_eml_content():
    """Contenido de ejemplo para un archivo EML"""
    return b"""From: sender@example.com
To: recipient@example.com
Subject: Test Email
Date: Mon, 1 Jan 2024 12:00:00 +0000
Message-ID: <test@example.com>

This is a test email body.
"""


@pytest.fixture(scope="function")
def mock_http_response():
    """Fixture para mock de respuesta HTTP"""
    from unittest.mock import MagicMock
    
    def _create_response(status=200, json_data=None, text_data=None):
        response = MagicMock()
        response.status = status
        if json_data:
            import json
            response.read.return_value = json.dumps(json_data).encode()
        elif text_data:
            response.read.return_value = text_data.encode()
        else:
            response.read.return_value = b""
        return response
    
    return _create_response


@pytest.fixture(autouse=True)
def reset_modules():
    """Limpia módulos importados entre tests para evitar contaminación"""
    yield
    # Limpiar módulos que puedan haber sido importados durante tests
    modules_to_remove = [k for k in sys.modules.keys() 
                         if k.startswith(('analisisheader', 'apk_tool', 'adb_setup'))]
    for mod in modules_to_remove:
        del sys.modules[mod]


# Configuración de pytest
def pytest_configure(config):
    """Configuración global de pytest"""
    config.addinivalue_line(
        "markers", "unit: marca tests unitarios"
    )
    config.addinivalue_line(
        "markers", "integration: marca tests de integración"
    )
    config.addinivalue_line(
        "markers", "network: marca tests que requieren red (mocked)"
    )
    config.addinivalue_line(
        "markers", "slow: marca tests lentos"
    )
    config.addinivalue_line(
        "markers", "security: marca tests de herramientas de seguridad"
    )