#!/usr/bin/env python3

import argparse
import requests
import json
import re
import os

# Colores ANSI
COLORS = {
    "info": "\033[32m[+]\033[0m",
    "error": "\033[31m[-]\033[0m",
    "warn": "\033[33m[!]\033[0m",
    "bold": "\033[1m",
    "reset": "\033[0m"
}

# Banner
def banner():
    print(f"""{COLORS["bold"]}
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      ..| buscar crt.sh v 2.0 |..    |
+    Autor: Apuromafo                 +
+    Sitio : crt.sh Búsqueda SSL/TLS  +
| Inspirado en repositorio de az7rb |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+{COLORS["reset"]}
""")

def limpiar_resultados(resultados):
    """
    Limpia y filtra los resultados, eliminando caracteres no deseados y duplicados.
    - Convierte saltos de línea escapados a saltos de línea reales.
    - Elimina caracteres comodín (*).
    - Filtra direcciones de correo electrónico.
    - Ordena los resultados y elimina duplicados.
    """
    resultados_limpios = set()
    for item in resultados:
        if item:
            item = item.replace("\\n", "\n").replace("*.", "")
            if not re.match(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,4}", item):
                resultados_limpios.add(item.strip())
    return sorted(list(resultados_limpios))

def realizar_peticion_con_proxy(url, proxies=None):
    """Realiza una petición GET con soporte para proxies."""
    try:
        response = requests.get(url, proxies=proxies)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        raise requests.exceptions.RequestException(f"Error durante la petición: {e}")
    except json.JSONDecodeError:
        raise json.JSONDecodeError("Error al decodificar la respuesta JSON", "", 0)

def buscar_dominio(dominio, formato_salida="txt", proxies=None):
    """Busca certificados para un dominio usando proxies."""
    if not dominio:
        print(f"{COLORS['error']} Error: Se requiere un nombre de dominio.{COLORS['reset']}")
        return

    url = f"https://crt.sh?q=%.{dominio}&output=json"
    try:
        data = realizar_peticion_con_proxy(url, proxies)
    except requests.exceptions.RequestException as e:
        print(f"{COLORS['error']} {e}{COLORS['reset']}")
        return
    except json.JSONDecodeError as e:
        print(f"{COLORS['error']} {e}{COLORS['reset']}")
        return

    if not data:
        print(f"{COLORS['warn']} No se encontraron resultados para el dominio {dominio}{COLORS['reset']}")
        return

    resultados = []
    for entrada in data:
        if 'common_name' in entrada:
            resultados.append(entrada['common_name'])
        if 'name_value' in entrada:
            resultados.append(entrada['name_value'])

    resultados_limpios = limpiar_resultados(resultados)

    if not resultados_limpios:
        print(f"{COLORS['warn']} No se encontraron resultados válidos.{COLORS['reset']}")
        return

    resultados_finales = sorted(list(set(resultados_limpios)))

    os.makedirs("output", exist_ok=True)
    nombre_archivo_base = f"output/dominio.{dominio}"

    if formato_salida.lower() == "json":
        nombre_archivo_salida = f"{nombre_archivo_base}.json"
        datos_json = {"dominios": resultados_finales}
        try:
            with open(nombre_archivo_salida, "w") as f:
                json.dump(datos_json, f, indent=4)
            print(json.dumps(datos_json, indent=4))
            print(f"\n{COLORS['info']} Total guardado será {COLORS['bold']}{COLORS['error']}{len(resultados_finales)}{COLORS['reset']} dominios.")
            print(f"{COLORS['info']} Resultados guardados en {COLORS['bold']}{nombre_archivo_salida}{COLORS['reset']}")
        except IOError as e:
            print(f"{COLORS['error']} Error al escribir en el archivo de salida {nombre_archivo_salida}: {e}{COLORS['reset']}")
            return
    else:  # Formato TXT por defecto
        nombre_archivo_salida = f"{nombre_archivo_base}.txt"
        try:
            with open(nombre_archivo_salida, "w") as f:
                for resultado in resultados_finales:
                    f.write(resultado + "\n")
            print("\n".join(resultados_finales))
            print(f"\n{COLORS['info']} Total guardado será {COLORS['bold']}{COLORS['error']}{len(resultados_finales)}{COLORS['reset']} dominios.")
            print(f"{COLORS['info']} Resultados guardados en {COLORS['bold']}{nombre_archivo_salida}{COLORS['reset']}")
        except IOError as e:
            print(f"{COLORS['error']} Error al escribir en el archivo de salida {nombre_archivo_salida}: {e}{COLORS['reset']}")
            return

def buscar_organizacion(organizacion, formato_salida="txt", proxies=None):
    """Busca certificados para una organización usando proxies."""
    if not organizacion:
        print(f"{COLORS['error']} Error: Se requiere un nombre de organización.{COLORS['reset']}")
        return

    url = f"https://crt.sh?q={organizacion}&output=json"
    try:
        data = realizar_peticion_con_proxy(url, proxies)
    except requests.exceptions.RequestException as e:
        print(f"{COLORS['error']} {e}{COLORS['reset']}")
        return
    except json.JSONDecodeError as e:
        print(f"{COLORS['error']} {e}{COLORS['reset']}")
        return

    if not data:
        print(f"{COLORS['warn']} No se encontraron resultados para la organización {organizacion}{COLORS['reset']}")
        return

    resultados = [entrada['common_name'] for entrada in data if 'common_name' in entrada]
    resultados_limpios = limpiar_resultados(resultados)

    if not resultados_limpios:
        print(f"{COLORS['warn']} No se encontraron resultados válidos.{COLORS['reset']}")
        return

    resultados_finales = sorted(list(set(resultados_limpios)))

    os.makedirs("output", exist_ok=True)
    nombre_archivo_base = f"output/organizacion.{organizacion}"

    if formato_salida.lower() == "json":
        nombre_archivo_salida = f"{nombre_archivo_base}.json"
        datos_json = {"dominios": resultados_finales}
        try:
            with open(nombre_archivo_salida, "w") as f:
                json.dump(datos_json, f, indent=4)
            print(json.dumps(datos_json, indent=4))
            print(f"\n{COLORS['info']} Total guardado será {COLORS['bold']}{COLORS['error']}{len(resultados_finales)}{COLORS['reset']} dominios.")
            print(f"{COLORS['info']} Resultados guardados en {COLORS['bold']}{nombre_archivo_salida}{COLORS['reset']}")
        except IOError as e:
            print(f"{COLORS['error']} Error al escribir en el archivo de salida {nombre_archivo_salida}: {e}{COLORS['reset']}")
            return
    else:  # Formato TXT por defecto
        nombre_archivo_salida = f"{nombre_archivo_base}.txt"
        try:
            with open(nombre_archivo_salida, "w") as f:
                for resultado in resultados_finales:
                    f.write(resultado + "\n")
            print("\n".join(resultados_finales))
            print(f"\n{COLORS['info']} Total guardado será {COLORS['bold']}{COLORS['error']}{len(resultados_finales)}{COLORS['reset']} dominios.")
            print(f"{COLORS['info']} Resultados guardados en {COLORS['bold']}{nombre_archivo_salida}{COLORS['reset']}")
        except IOError as e:
            print(f"{COLORS['error']} Error al escribir en el archivo de salida {nombre_archivo_salida}: {e}{COLORS['reset']}")
            return

def main():
    """Lógica principal del script con soporte para proxy."""
    banner()
    parser = argparse.ArgumentParser(description="Busca certificados en crt.sh usando proxies.")
    parser.add_argument("-d", "--dominio", help="Buscar por Nombre de Dominio (ej: hackerone.com)")
    parser.add_argument("-o", "--organizacion", help="Buscar por Nombre de Organización (ej: Cloudflare, Inc.)")
    parser.add_argument("-f", "--formato", choices=['txt', 'json'], default='txt', help="Formato de salida (txt o json). Por defecto es txt.")
    parser.add_argument("--proxy", help="Dirección del proxy a usar (ej: http://usuario:contraseña@ip:puerto o http://ip:puerto)")
    args = parser.parse_args()

    proxies = None
    if args.proxy:
        proxies = {"http": args.proxy, "https": args.proxy}
        print(f"{COLORS['info']} Usando proxy: {COLORS['bold']}{args.proxy}{COLORS['reset']}")

    if args.dominio:
        buscar_dominio(args.dominio, args.formato, proxies)
    elif args.organizacion:
        buscar_organizacion(args.organizacion, args.formato, proxies)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()