#!/usr/bin/env python3
"""
Tests unitarios para analisisheader.py
======================================

Estos tests utilizan mocks para evitar llamadas de red reales.
No modifican la lógica original del script.
"""

import pytest
from unittest.mock import patch, MagicMock, mock_open, call
import sys
import os

# Agregar el directorio del script al path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '001_Analisis_header_eml'))

from analisisheader import (
    calcular_hash_sha256,
    obtener_cuerpo,
    extraer_mtas,
    detectar_phishing,
    obtener_direccion_ip,
    validar_ip,
    validar_mtas,
    cargar_configuracion,
    analizar_correo,
)


class TestCalcularHashSHA256:
    """Tests para calcular_hash_sha256"""
    
    def test_calcular_hash_sha256_archivo_valido(self, tmp_path):
        """Test hash SHA-256 de archivo válido"""
        archivo = tmp_path / "test.txt"
        archivo.write_text("Hola mundo")
        
        resultado = calcular_hash_sha256(str(archivo))
        
        # SHA-256 de "Hola mundo"
        esperado = "d1a2b3c4e5f6..."  # Se calculará dinámicamente
        assert len(resultado) == 64  # SHA-256 produce 64 caracteres hex
        assert all(c in '0123456789abcdef' for c in resultado)
    
    def test_calcular_hash_sha256_archivo_vacio(self, tmp_path):
        """Test hash SHA-256 de archivo vacío"""
        archivo = tmp_path / "vacio.txt"
        archivo.write_text("")
        
        resultado = calcular_hash_sha256(str(archivo))
        
        # SHA-256 de string vacío
        assert resultado == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


class TestObtenerCuerpo:
    """Tests para obtener_cuerpo"""
    
    def test_obtener_cuerpo_multipart_texto_plano(self):
        """Test extracción de cuerpo en correo multipart"""
        import email
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText
        
        msg = MIMEMultipart()
        msg.attach(MIMEText("Cuerpo de prueba", "plain"))
        
        resultado = obtener_cuerpo(msg)
        
        assert "Cuerpo de prueba" in resultado
    
    def test_obtener_cuerpo_no_multipart(self):
        """Test extracción de cuerpo en correo no multipart"""
        import email
        from email.mime.text import MIMEText
        
        msg = MIMEText("Cuerpo simple", "plain")
        
        resultado = obtener_cuerpo(msg)
        
        assert "Cuerpo simple" in resultado


class TestExtraerMTAs:
    """Tests para extraer_mtas"""
    
    def test_extraer_mtas_basico(self):
        """Test extracción de MTAs de encabezados Received"""
        import email
        from email.mime.text import MIMEText
        
        msg = MIMEText("Test")
        msg["Received"] = "from mail.example.com (192.168.1.1) by server.com"
        
        resultado = extraer_mtas(msg)
        
        assert "mail.example.com" in resultado
    
    def test_extraer_mtas_multiples(self):
        """Test extracción de múltiples MTAs"""
        import email
        from email.mime.text import MIMEText
        
        msg = MIMEText("Test")
        msg.add_header("Received", "from server1.com by server2.com")
        msg.add_header("Received", "from server3.com by server4.com")
        
        resultado = extraer_mtas(msg)
        
        assert "server1.com" in resultado
        assert "server3.com" in resultado


class TestDetectarPhishing:
    """Tests para detectar_phishing"""
    
    def test_detectar_phishing_trend_micro(self):
        """Test detección de cabecera Trend Micro"""
        import email
        from email.mime.text import MIMEText
        
        msg = MIMEText("Test")
        msg["X-TrendMicro-Phishing"] = "detected"
        
        resultado = detectar_phishing(msg)
        
        assert any("X-TrendMicro-Phishing" in r for r in resultado)
    
    def test_detectar_phishing_spam_flag(self):
        """Test detección de spam flag"""
        import email
        from email.mime.text import MIMEText
        
        msg = MIMEText("Test")
        msg["X-Spam-Flag"] = "YES"
        
        resultado = detectar_phishing(msg)
        
        assert any("X-Spam-Flag" in r for r in resultado)


class TestObtenerDireccionIP:
    """Tests para obtener_direccion_ip"""
    
    @patch('socket.gethostbyname')
    def test_obtener_direccion_ip_valida(self, mock_gethostbyname):
        """Test resolución de dominio válido"""
        mock_gethostbyname.return_value = "192.168.1.1"
        
        resultado = obtener_direccion_ip("example.com")
        
        assert resultado == "192.168.1.1"
        mock_gethostbyname.assert_called_once_with("example.com")
    
    @patch('socket.gethostbyname')
    def test_obtener_direccion_ip_invalida(self, mock_gethostbyname):
        """Test resolución de dominio inválido"""
        import socket
        mock_gethostbyname.side_effect = socket.gaierror("Name or service not known")
        
        resultado = obtener_direccion_ip("dominio.inexistente.invalid")
        
        assert resultado is None


class TestValidarIP:
    """Tests para validar_ip"""
    
    @patch('http.client.HTTPSConnection')
    def test_validar_ip_fail_high_confidence(self, mock_https):
        """Test IP con alta confianza de abuso"""
        mock_conn = MagicMock()
        mock_https.return_value = mock_conn
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = b'{"data": {"abuseConfidenceScore": 90}}'
        mock_conn.getresponse.return_value = mock_response
        
        resultado = validar_ip("1.2.3.4", "test_api_key")
        
        assert resultado == "fail"
    
    @patch('http.client.HTTPSConnection')
    def test_validar_ip_pass_low_confidence(self, mock_https):
        """Test IP con baja confianza de abuso"""
        mock_conn = MagicMock()
        mock_https.return_value = mock_conn
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = b'{"data": {"abuseConfidenceScore": 25}}'
        mock_conn.getresponse.return_value = mock_response
        
        resultado = validar_ip("1.2.3.4", "test_api_key")
        
        assert resultado == "pass"
    
    @patch('http.client.HTTPSConnection')
    def test_validar_ip_error_conexion(self, mock_https):
        """Test error de conexión a API"""
        mock_conn = MagicMock()
        mock_https.return_value = mock_conn
        mock_conn.request.side_effect = Exception("Connection refused")
        
        resultado = validar_ip("1.2.3.4", "test_api_key")
        
        assert "Error al validar IP" in resultado


class TestValidarMTAs:
    """Tests para validar_mtas"""
    
    @patch('analisisheader.obtener_direccion_ip')
    @patch('analisisheader.validar_ip')
    def test_validar_mtas_ip_directa(self, mock_validar_ip, mock_obtener_ip):
        """Test validación de MTA que es una IP directa"""
        mock_validar_ip.return_value = "pass"
        
        mtas = ["192.168.1.1", "10.0.0.1"]
        resultado = validar_mtas(mtas, "test_key")
        
        assert resultado["192.168.1.1"] == "pass"
        assert resultado["10.0.0.1"] == "pass"
        mock_obtener_ip.assert_not_called()
    
    @patch('analisisheader.obtener_direccion_ip')
    @patch('analisisheader.validar_ip')
    def test_validar_mtas_dominio(self, mock_validar_ip, mock_obtener_ip):
        """Test validación de MTA que es un dominio"""
        mock_obtener_ip.return_value = "192.168.1.1"
        mock_validar_ip.return_value = "fail"
        
        mtas = ["mail.example.com"]
        resultado = validar_mtas(mtas, "test_key")
        
        assert resultado["mail.example.com"] == "fail"
        mock_obtener_ip.assert_called_once_with("mail.example.com")


class TestCargarConfiguracion:
    """Tests para cargar_configuracion"""
    
    def test_cargar_configuracion_exitosa(self, tmp_path):
        """Test carga exitosa de configuración"""
        config_file = tmp_path / "config.api"
        config_file.write_text("""
[abuseipdb]
api_key = test_abuse_key

[virustotal]
api_key = test_vt_key
""")
        
        original_cwd = os.getcwd()
        os.chdir(tmp_path)
        try:
            resultado = cargar_configuracion()
            assert resultado["abuseipdb"] == "test_abuse_key"
            assert resultado["virustotal"] == "test_vt_key"
        finally:
            os.chdir(original_cwd)
    
    def test_cargar_configuracion_archivo_no_existe(self, tmp_path):
        """Test error cuando no existe archivo de configuración"""
        original_cwd = os.getcwd()
        os.chdir(tmp_path)
        try:
            with pytest.raises(SystemExit):
                cargar_configuracion()
        finally:
            os.chdir(original_cwd)


class TestAnalizarCorreo:
    """Tests para analizar_correo"""
    
    def test_analizar_correo_completo(self):
        """Test análisis completo de correo"""
        import email
        from email.mime.text import MIMEText
        
        msg = MIMEText("Cuerpo del mensaje")
        msg["Subject"] = "Test Subject"
        msg["From"] = "sender@example.com"
        msg["To"] = "recipient@example.com"
        
        resultado = analizar_correo(msg)
        
        assert resultado["asunto"] == "Test Subject"
        assert resultado["remitente"] == "sender@example.com"
        assert resultado["destinatario"] == "recipient@example.com"
        assert "Cuerpo del mensaje" in resultado["cuerpo"]
        assert isinstance(resultado["mtas"], list)
        assert isinstance(resultado["cabeceras_phishing"], list)


class TestCalcularHashSHA256Integracion:
    """Tests de integración para calcular_hash_sha256"""
    
    def test_hash_consistente(self, tmp_path):
        """Test que el hash es consistente entre ejecuciones"""
        archivo = tmp_path / "consistente.txt"
        archivo.write_text("Contenido consistente para test")
        
        hash1 = calcular_hash_sha256(str(archivo))
        hash2 = calcular_hash_sha256(str(archivo))
        
        assert hash1 == hash2
    
    def test_hash_diferente_contenido(self, tmp_path):
        """Test que contenido diferente produce hash diferente"""
        archivo1 = tmp_path / "a.txt"
        archivo2 = tmp_path / "b.txt"
        archivo1.write_text("Contenido A")
        archivo2.write_text("Contenido B")
        
        hash1 = calcular_hash_sha256(str(archivo1))
        hash2 = calcular_hash_sha256(str(archivo2))
        
        assert hash1 != hash2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])