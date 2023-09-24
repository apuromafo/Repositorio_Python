import argparse
import email
import re

def analizar_correo(archivo_correo):
    """
    Analiza un correo electrónico en formato eml.

    Args:
        archivo_correo: El archivo de correo electrónico en formato eml.

    Returns:
        Un diccionario con la información del correo electrónico.
    """
    with open(archivo_correo, "rb") as f:
        correo = email.message_from_bytes(f.read())

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

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("archivo", help="El archivo de correo electrónico que deseas analizar")
    args = parser.parse_args()

    archivo_correo = args.archivo

    correo_analizado = analizar_correo(archivo_correo)

    print("Asunto:", correo_analizado["asunto"])
    print("Remitente:", correo_analizado["remitente"])
    print("Destinatario:", correo_analizado["destinatario"])
    print("Cuerpo:", correo_analizado["cuerpo"])
    print("MTAs encontrados:")
    for mta in correo_analizado["mtas"]:
        print(mta)

if __name__ == "__main__":
    main()