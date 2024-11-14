import argparse
import email
import re
import requests
import socket

def cargar_clave_api():
    """
    Carga la clave de API desde el archivo de configuración.

    Returns:
        La clave de API cargada desde el archivo de configuración (es el apikey en el archivo config.api)
    """
    with open("config.api", "r") as f:
        clave_api = f.read().strip()
    return clave_api

def analizar_correo(archivo_correo, api_key):
    """
    Analiza un correo electrónico en formato eml y valida los MTAs encontrados utilizando la API de AbuseIPDB.

    Args:
        archivo_correo: El archivo de correo electrónico en formato eml.
        api_key: La clave de API de AbuseIPDB.

    Returns:
        Un diccionario con la información del correo electrónico y los resultados de la validación de los MTAs.
    """
    with open(archivo_correo, "rb") as f:
        correo = email.message_from_bytes(f.read())

    asunto = correo["Subject"]
    remitente = correo["From"]
    destinatario = correo["To"]

    cuerpo = obtener_cuerpo(correo)

    mtas = extraer_mtas(correo)

    resultados_mtas = validar_mtas(mtas, api_key)

    return {
        "asunto": asunto,
        "remitente": remitente,
        "destinatario": destinatario,
        "cuerpo": cuerpo,
        "mtas": resultados_mtas
    }

def obtener_cuerpo(correo):
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
    encabezado = correo.as_string()
    patron = r"Received:.*?from\s+([\w.-]+)"
    coincidencias = re.findall(patron, encabezado)
    return list(set(coincidencias))

    
def validar_mtas(mtas, api_key):
  """
  Valida los MTAs utilizando la API de AbuseIPDB.

  Args:
    mtas: Una lista de MTAs a validar.
    api_key: La clave de API de AbuseIPDB.

  Returns:
    Un diccionario con los resultados de la validación de los MTAs.
  """
  resultados = {}

  for mta in mtas:
    # Verificar si es una dirección IP o un dominio
    if re.match(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", mta):
      # Es una dirección IP
      resultados[mta] = validar_ip(mta, api_key)
      resultados[mta] += f" (IP de host: {mta})"
    else:
      # Es un dominio, obtener la dirección IP
      direccion_ip = obtener_direccion_ip(mta)
      if direccion_ip is not None:
        resultados[mta] = validar_ip(direccion_ip, api_key)
        resultados[mta] += f" (IP de host: {direccion_ip})"
      else:
        resultados[mta] = "Invalid IP"

  return resultados


  
    
    
    

def obtener_direccion_ip(dominio):
    try:
        direccion_ip = socket.gethostbyname(dominio)
        return direccion_ip
    except socket.gaierror:
        return None

def validar_ip(ip, api_key):
    """
    Valida una dirección IP utilizando la API de AbuseIPDB.

    Args:
        ip: La dirección IP a validar.
        api_key: La clave de API de AbuseIPDB.

    Returns:
        "pass" si la dirección IP es confiable, "fail" si no es confiable,
        o "unknown" si no se puede determinar.
    """
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
    headers = {'Key': api_key, 'Accept': 'application/json'}
    response = requests.get(url, headers=headers)
    data = response.json()
    if 'data' in data:
        confidence = data['data']['abuseConfidenceScore']
        if confidence >= 75:
            return "fail"
        else:
            return "pass"
    else:
        return "unknown"

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("archivo", help="El archivo de correo electrónico que deseas analizar")
    args = parser.parse_args()

    archivo_correo = args.archivo

    api_key = cargar_clave_api()
    resultado_analisis = analizar_correo(archivo_correo, api_key)

    print("Información del correo:")
    print(f"Asunto: {resultado_analisis['asunto']}")
    print(f"Remitente: {resultado_analisis['remitente']}")
    print(f"Destinatario: {resultado_analisis['destinatario']}")
    print(f"Cuerpo:\n{resultado_analisis['cuerpo']}")

    print("\nResultados de la validación de los MTAs:")
    for mta, resultado in resultado_analisis['mtas'].items():
        print(f"{mta}: {resultado}")
        
if __name__ == "__main__":
    main()        