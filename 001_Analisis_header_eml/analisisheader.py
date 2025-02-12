#!/usr/bin/env python3
# Descripción: Herramienta para análisis de encabezados EML, validación de MTAs y análisis de archivos con VirusTotal
# Autor: Apuromafo
# Versión: 0.0.6
# Fecha: 28.11.2024

import email
import re
import socket
import http.client
import json
import os
import argparse
import hashlib
import configparser
from datetime import datetime

def cargar_configuracion():
    """Carga la configuración desde el archivo config.api."""
    config = configparser.ConfigParser()
    if not os.path.isfile("config.api"):
        print("Error: No se encontró el archivo 'config.api'.")
        print("Asegúrate de crear un archivo 'config.api' con el siguiente formato:")
        print("""
[abuseipdb]
api_key = tu_clave_de_api_abuseipdb_aqui

[virustotal]
api_key = tu_clave_de_api_virustotal_aqui
""")
        exit(1)
    
    config.read("config.api")
    return {
        "abuseipdb": config.get("abuseipdb", "api_key", fallback=None),
        "virustotal": config.get("virustotal", "api_key", fallback=None)
    }

def calcular_hash_sha256(archivo):
    """Calcula el hash SHA-256 de un archivo."""
    sha256_hash = hashlib.sha256()
    with open(archivo, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def analizar_correo(correo):
    """Analiza un correo electrónico en formato EML."""
    asunto = correo.get("Subject", "Sin asunto")
    remitente = correo.get("From", "Desconocido")
    destinatario = correo.get("To", "Desconocido")
    cuerpo = obtener_cuerpo(correo)
    mtas = extraer_mtas(correo)
    cabeceras_phishing = detectar_phishing(correo)
    return {
        "asunto": asunto,
        "remitente": remitente,
        "destinatario": destinatario,
        "cuerpo": cuerpo,
        "mtas": mtas,
        "cabeceras_phishing": cabeceras_phishing
    }

def obtener_cuerpo(correo):
    """Obtiene el cuerpo del correo, decodificando si es necesario."""
    if correo.is_multipart():
        for parte in correo.walk():
            tipo_contenido = parte.get_content_type()
            if tipo_contenido == "text/plain":
                contenido = parte.get_payload(decode=True)
                return contenido.decode(errors="ignore") if contenido else ""
    else:
        contenido = correo.get_payload(decode=True)
        return contenido.decode(errors="ignore") if contenido else ""
    return ""

def extraer_mtas(correo):
    """Extrae los MTAs (Mail Transfer Agents) de los encabezados del correo."""
    encabezado = correo.as_string()
    patron = r"Received:.*?from\s+([\w.-]+)"
    coincidencias = re.findall(patron, encabezado, re.IGNORECASE)
    return list(set(coincidencias))

def detectar_phishing(correo):
    """Detecta cabeceras relacionadas con phishing o Trend Micro."""
    encabezado = correo.as_string()
    patrones_phishing = [
        r"X-TrendMicro-Phishing",  # Cabecera específica de Trend Micro
        r"X-Spam-Flag:\s*YES",     # Indicador general de spam
        r"X-Virus-Scanned",        # Escaneo antivirus
        r"X-Spam-Score",           # Puntuación de spam
        r"X-Spam-Level"            # Nivel de spam
    ]
    resultados = []
    for patron in patrones_phishing:
        if re.search(patron, encabezado, re.IGNORECASE):
            resultados.append(patron)
    return resultados

def obtener_direccion_ip(dominio):
    """Obtiene la dirección IP de un dominio."""
    try:
        return socket.gethostbyname(dominio)
    except socket.gaierror:
        return None

def validar_ip(ip, api_key):
    """Valida una dirección IP utilizando la API de AbuseIPDB."""
    if not api_key:
        return "No API key provided"
    
    conn = http.client.HTTPSConnection("api.abuseipdb.com")
    url = f"/api/v2/check?ipAddress={ip}"
    headers = {'Key': api_key, 'Accept': 'application/json'}
    
    try:
        conn.request("GET", url, headers=headers)
        response = conn.getresponse()
        data = response.read()
        conn.close()
        
        if response.status == 200:
            result = json.loads(data)
            if 'data' in result:
                confianza = result['data']['abuseConfidenceScore']
                return "fail" if confianza >= 75 else "pass"
        return "unknown"
    except Exception as e:
        return f"Error al validar IP: {e}"

def validar_mtas(mtas, api_key):
    """Valida los MTAs utilizando la API de AbuseIPDB."""
    resultados = {}
    for mta in mtas:
        if re.match(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", mta):  # Si es una IP
            resultados[mta] = validar_ip(mta, api_key)
        else:  # Si es un dominio
            direccion_ip = obtener_direccion_ip(mta)
            if direccion_ip:
                resultados[mta] = validar_ip(direccion_ip, api_key)
            else:
                resultados[mta] = "Invalid IP"
    return resultados

def analizar_con_virustotal(hash_archivo, api_key):
    """Analiza un hash de archivo con la API de VirusTotal."""
    if not api_key:
        return "No API key provided"
    
    conn = http.client.HTTPSConnection("www.virustotal.com")
    url = f"/api/v3/files/{hash_archivo}"
    headers = {'x-apikey': api_key}
    
    try:
        conn.request("GET", url, headers=headers)
        response = conn.getresponse()
        data = response.read()
        conn.close()
        
        if response.status == 200:
            result = json.loads(data)
            if 'data' in result and 'attributes' in result['data']:
                stats = result['data']['attributes']['last_analysis_stats']
                return stats
        elif response.status == 404:
            return "Archivo no encontrado en VirusTotal"
        return "Error desconocido"
    except Exception as e:
        return f"Error al analizar con VirusTotal: {e}"

def main():
    # Mensaje inicial con instrucciones
    print("""
    ==================== INSTRUCCIONES ====================
    Este script analiza archivos EML para extraer información relevante.
    - Asegúrate de tener un archivo 'config.api' en el mismo directorio.
    - El archivo 'config.api' debe tener el siguiente formato:
      [abuseipdb]
      api_key = tu_clave_de_api_abuseipdb_aqui

      [virustotal]
      api_key = tu_clave_de_api_virustotal_aqui

    - Ejemplo de uso:
      python analisisheader.py correo.eml
    =======================================================
    """)
    
    # Cargar configuración
    config = cargar_configuracion()
    api_key_abuseipdb = config["abuseipdb"]
    api_key_virustotal = config["virustotal"]

    # Argumentos de línea de comandos
    parser = argparse.ArgumentParser(description="Analiza correos electrónicos EML y valida MTAs.")
    parser.add_argument("archivo", nargs='?', help="Ruta del archivo EML a analizar")
    args = parser.parse_args()

    if args.archivo:
        tiempo_inicio = datetime.now()
        procesar_archivo(args.archivo, api_key_abuseipdb, api_key_virustotal)
        tiempo_fin = datetime.now()
        print(f"\nTiempo transcurrido: {tiempo_fin - tiempo_inicio}")
    else:
        modo_interactivo(api_key_abuseipdb, api_key_virustotal)

def procesar_archivo(archivo_correo, api_key_abuseipdb, api_key_virustotal):
    """Procesa un archivo EML dado."""
    try:
        with open(archivo_correo, "rb") as f:
            correo = email.message_from_bytes(f.read())
        correo_analizado = analizar_correo(correo)
        resultados_mtas = validar_mtas(correo_analizado["mtas"], api_key_abuseipdb)
        hash_archivo = calcular_hash_sha256(archivo_correo)
        resultado_virustotal = analizar_con_virustotal(hash_archivo, api_key_virustotal)
        mostrar_resultados(correo_analizado, resultados_mtas, hash_archivo, resultado_virustotal)
    except FileNotFoundError:
        print(f"Error: El archivo {archivo_correo} no existe.")
    except Exception as e:
        print(f"Error al procesar el correo: {e}")

def modo_interactivo(api_key_abuseipdb, api_key_virustotal):
    """Modo interactivo para ingresar archivos EML."""
    while True:
        archivo_correo = input("Ingrese la ruta del archivo EML (o 'salir' para terminar): ").strip()
        if archivo_correo.lower() == 'salir':
            break
        tiempo_inicio = datetime.now()
        procesar_archivo(archivo_correo, api_key_abuseipdb, api_key_virustotal)
        tiempo_fin = datetime.now()
        print(f"\nTiempo transcurrido: {tiempo_fin - tiempo_inicio}")

def mostrar_resultados(correo_analizado, resultados_mtas, hash_archivo, resultado_virustotal):
    """Muestra los resultados del análisis."""
    print("\nInformación del correo:")
    print(f"Asunto: {correo_analizado['asunto']}")
    print(f"Remitente: {correo_analizado['remitente']}")
    print(f"Destinatario: {correo_analizado['destinatario']}")
    print(f"Cuerpo:\n{correo_analizado['cuerpo']}")
    print("\nCabeceras relacionadas con phishing:")
    if correo_analizado["cabeceras_phishing"]:
        for cabecera in correo_analizado["cabeceras_phishing"]:
            print(f"- {cabecera}")
    else:
        print("- Ninguna cabecera sospechosa encontrada.")
    print("\nResultados de la validación de los MTAs:")
    for mta, resultado in resultados_mtas.items():
        print(f"{mta}: {resultado}")
    print("\nAnálisis de VirusTotal:")
    if isinstance(resultado_virustotal, dict):
        print(f"Hash SHA-256: {hash_archivo}")
        print(f"Resultados: {json.dumps(resultado_virustotal, indent=2)}")
    else:
        print(f"Hash SHA-256: {hash_archivo}")
        print(f"Resultado: {resultado_virustotal}")

if __name__ == "__main__":
    main()