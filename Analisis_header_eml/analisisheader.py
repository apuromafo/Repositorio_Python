import email
import re
import socket
import http.client
import json
import os
import argparse

def cargar_clave_api():
    """Carga la clave de API desde el archivo de configuración, si existe."""
    if os.path.isfile("config.api"):
        with open("config.api", "r") as f:
            return f.read().strip()
    return None  # Retorna None si el archivo no existe

def analizar_correo(correo):
    """Analiza un correo electrónico en formato EML."""
    asunto = correo["Subject"]
    remitente = correo["From"]
    destinatario = correo["To"]
    cuerpo = obtener_cuerpo(correo)

    mtas = extraer_mtas(correo)

    return {
        "asunto": asunto,
        "remitente": remitente,
        "destinatario": destinatario,
        "cuerpo": cuerpo,
        "mtas": mtas
    }

def obtener_cuerpo(correo):
    """Obtiene el cuerpo del correo, decodificando si es necesario."""
    if correo.is_multipart():
        for parte in correo.walk():
            tipo_contenido = parte.get_content_type()
            if tipo_contenido == "text/plain":
                contenido = parte.get_payload(decode=True)
                if contenido:
                    return contenido.decode()
    else:
        contenido = correo.get_payload(decode=True)
        if contenido:
            return contenido.decode()
    return ""

def extraer_mtas(correo):
    """Extrae los MTAs de los encabezados del correo."""
    encabezado = correo.as_string()
    patron = r"Received:.*?from\s+([\w.-]+)"
    coincidencias = re.findall(patron, encabezado)
    return list(set(coincidencias))

def obtener_direccion_ip(dominio):
    """Obtiene la dirección IP de un dominio."""
    try:
        return socket.gethostbyname(dominio)
    except socket.gaierror:
        return None

def validar_ip(ip, api_key):
    """Valida una dirección IP utilizando la API de AbuseIPDB."""
    conn = http.client.HTTPSConnection("api.abuseipdb.com")
    url = f"/api/v2/check?ipAddress={ip}"
    headers = {'Key': api_key, 'Accept': 'application/json'}
    
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

def validar_mtas(mtas, api_key):
    """Valida los MTAs utilizando la API de AbuseIPDB."""
    resultados = {}
    for mta in mtas:
        if re.match(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", mta):
            resultados[mta] = validar_ip(mta, api_key) if api_key else "No API key provided"
        else:
            direccion_ip = obtener_direccion_ip(mta)
            if direccion_ip:
                resultados[mta] = validar_ip(direccion_ip, api_key) if api_key else "No API key provided"
            else:
                resultados[mta] = "Invalid IP"
    return resultados

def main():
    parser = argparse.ArgumentParser(description="Analiza correos electrónicos EML y valida MTAs.")
    parser.add_argument("archivo", nargs='?', help="Ruta del archivo EML a analizar")
    api_key = cargar_clave_api()

    # Si se proporciona un archivo, analizarlo
    if parser.parse_args().archivo:
        archivo_correo = parser.parse_args().archivo
        try:
            with open(archivo_correo, "rb") as f:
                correo = email.message_from_bytes(f.read())
            correo_analizado = analizar_correo(correo)
            resultados_mtas = validar_mtas(correo_analizado["mtas"], api_key)

            print("Información del correo:")
            print(f"Asunto: {correo_analizado['asunto']}")
            print(f"Remitente: {correo_analizado['remitente']}")
            print(f"Destinatario: {correo_analizado['destinatario']}")
            print(f"Cuerpo:\n{correo_analizado['cuerpo']}")
            print("\nResultados de la validación de los MTAs:")
            for mta, resultado in resultados_mtas.items():
                print(f"{mta}: {resultado}")

        except FileNotFoundError:
            print(f"Error: El archivo {archivo_correo} no existe.")
        except Exception as e:
            print(f"Error al procesar el correo: {e}")
    else:
        # Modo interactivo
        while True:
            archivo_correo = input("Ingrese la ruta del archivo EML (o 'salir' para terminar): ").strip()
            if archivo_correo.lower() == 'salir':
                break
            
            try:
                with open(archivo_correo, "rb") as f:
                    correo = email.message_from_bytes(f.read())
                correo_analizado = analizar_correo(correo)
                resultados_mtas = validar_mtas(correo_analizado["mtas"], api_key)

                print("Información del correo:")
                print(f"Asunto: {correo_analizado['asunto']}")
                print(f"Remitente: {correo_analizado['remitente']}")
                print(f"Destinatario: {correo_analizado['destinatario']}")
                print(f"Cuerpo:\n{correo_analizado['cuerpo']}")
                print("\nResultados de la validación de los MTAs:")
                for mta, resultado in resultados_mtas.items():
                    print(f"{mta}: {resultado}")
            except FileNotFoundError:
                print(f"Error: El archivo {archivo_correo} no existe.")
            except Exception as e:
                print(f"Error al procesar el correo: {e}")

if __name__ == "__main__":
    main()