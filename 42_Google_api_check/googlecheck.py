import requests
import warnings
import sys
import os
import json
import subprocess

# Intenta importar tabulate, si falla, lo instala
try:
    from tabulate import tabulate
except ImportError:
    print("La biblioteca 'tabulate' no está instalada. Intentando instalarla...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "tabulate"])
        from tabulate import tabulate
        print("Instalación de 'tabulate' completada.")
    except Exception as e:
        print(f"Error al instalar 'tabulate': {e}")
        print("La visualización de la tabla no estará disponible. Por favor, instálala manualmente con 'pip install tabulate'")
        tabulate = None

# Desactiva las advertencias de SSL
warnings.filterwarnings("ignore")

# Define las APIs a probar, sus URLs y otros datos relevantes en un diccionario.
APIS = {
    'Staticmap': {
        'url': 'https://maps.googleapis.com/maps/api/staticmap?center=45%2C10&zoom=7&size=400x400&key=',
        'costo': '$2 por 1000 solicitudes',
        'metodo': 'GET',
        'check': lambda resp: resp.status_code == 200,
        'razon': 'Revisa el motivo manualmente en la URL.'
    },
    'Streetview': {
        'url': 'https://maps.googleapis.com/maps/api/streetview?size=400x400&location=40.720032,-73.988354&fov=90&heading=235&pitch=10&key=',
        'costo': '$7 por 1000 solicitudes',
        'metodo': 'GET',
        'check': lambda resp: resp.status_code == 200,
        'razon': 'Revisa el motivo manualmente en la URL.'
    },
    'Directions': {
        'url': 'https://maps.googleapis.com/maps/api/directions/json?origin=Disneyland&destination=Universal+Studios+Hollywood4&key=',
        'costo': '$5/$10 por 1000 solicitudes',
        'metodo': 'GET',
        'check': lambda resp: 'error_message' not in resp.text,
        'razon': lambda resp: f'Razón: {resp.json()["error_message"]}'
    },
    'Geocode': {
        'url': 'https://maps.googleapis.com/maps/api/geocode/json?latlng=40,30&key=',
        'costo': '$5 por 1000 solicitudes',
        'metodo': 'GET',
        'check': lambda resp: 'error_message' not in resp.text,
        'razon': lambda resp: f'Razón: {resp.json()["error_message"]}'
    },
    'Distance Matrix': {
        'url': 'https://maps.googleapis.com/maps/api/distancematrix/json?units=imperial&origins=40.6655101,-73.89188969999998&destinations=40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.659569%2C-73.933783%7C40.729029%2C-73.851524%7C40.6860072%2C-73.6334271%7C40.598566%2C-73.7527626%7C40.659569%2C-73.933783%7C40.729029%2C-73.851524%7C40.6860072%2C-73.6334271%7C40.598566%2C-73.7527626&key=',
        'costo': '$5/$10 por 1000 elementos',
        'metodo': 'GET',
        'check': lambda resp: 'error_message' not in resp.text,
        'razon': lambda resp: f'Razón: {resp.json()["error_message"]}'
    },
    'Find Place From Text': {
        'url': 'https://maps.googleapis.com/maps/api/place/findplacefromtext/json?input=Museum%20of%20Contemporary%20Art%20Australia&inputtype=textquery&fields=photos,formatted_address,name,rating,opening_hours,geometry&key=',
        'costo': '$17 por 1000 elementos',
        'metodo': 'GET',
        'check': lambda resp: 'error_message' not in resp.text,
        'razon': lambda resp: f'Razón: {resp.json()["error_message"]}'
    },
    'Autocomplete': {
        'url': 'https://maps.googleapis.com/maps/api/place/autocomplete/json?input=Bingh&types=%28cities%29&key=',
        'costo': '$2.83/$17 por 1000 solicitudes',
        'metodo': 'GET',
        'check': lambda resp: 'error_message' not in resp.text,
        'razon': lambda resp: f'Razón: {resp.json()["error_message"]}'
    },
    'Elevation': {
        'url': 'https://maps.googleapis.com/maps/api/elevation/json?locations=39.7391536,-104.9847034&key=',
        'costo': '$5 por 1000 solicitudes',
        'metodo': 'GET',
        'check': lambda resp: 'error_message' not in resp.text,
        'razon': lambda resp: f'Razón: {resp.json()["error_message"]}'
    },
    'Timezone': {
        'url': 'https://maps.googleapis.com/maps/api/timezone/json?location=39.6034810,-119.6822510&timestamp=1331161200&key=',
        'costo': '$5 por 1000 solicitudes',
        'metodo': 'GET',
        'check': lambda resp: 'errorMessage' not in resp.text,
        'razon': lambda resp: f'Razón: {resp.json()["errorMessage"]}'
    },
    'Nearest Roads': {
        'url': 'https://roads.googleapis.com/v1/nearestRoads?points=60.170880,24.942795|60.170879,24.942796|60.170877,24.942796&key=',
        'costo': '$10 por 1000 solicitudes',
        'metodo': 'GET',
        'check': lambda resp: 'error' not in resp.text,
        'razon': lambda resp: f'Razón: {resp.json()["error"]["message"]}'
    },
    'Geolocation': {
        'url': 'https://www.googleapis.com/geolocation/v1/geolocate?key=',
        'costo': '$5 por 1000 solicitudes',
        'metodo': 'POST',
        'data': {'considerIp': 'true'},
        'check': lambda resp: 'error' not in resp.text,
        'razon': lambda resp: f'Razón: {resp.json()["error"]["message"]}'
    },
    'Route to Traveled': {
        'url': 'https://roads.googleapis.com/v1/snapToRoads?path=-35.27801,149.12958|-35.28032,149.12907&interpolate=true&key=',
        'costo': '$10 por 1000 solicitudes',
        'metodo': 'GET',
        'check': lambda resp: 'error' not in resp.text,
        'razon': lambda resp: f'Razón: {resp.json()["error"]["message"]}'
    },
    'Speed Limit-Roads': {
        'url': 'https://roads.googleapis.com/v1/speedLimits?path=38.75807927603043,-9.03741754643809&key=',
        'costo': '$20 por 1000 solicitudes',
        'metodo': 'GET',
        'check': lambda resp: 'error' not in resp.text,
        'razon': lambda resp: f'Razón: {resp.json()["error"]["message"]}'
    },
    'Place Details': {
        'url': 'https://maps.googleapis.com/maps/api/place/details/json?place_id=ChIJN1t_tDeuEmsRUsoyG83frY4&fields=name,rating,formatted_phone_number&key=',
        'costo': '$17 por 1000 solicitudes',
        'metodo': 'GET',
        'check': lambda resp: 'error_message' not in resp.text,
        'razon': lambda resp: f'Razón: {resp.json()["error_message"]}'
    },
    'Nearby Search-Places': {
        'url': 'https://maps.googleapis.com/maps/api/place/nearbysearch/json?location=-33.8670522,151.1957362&radius=100&types=food&name=harbour&key=',
        'costo': '$32 por 1000 solicitudes',
        'metodo': 'GET',
        'check': lambda resp: 'error_message' not in resp.text,
        'razon': lambda resp: f'Razón: {resp.json()["error_message"]}'
    },
    'Text Search-Places': {
        'url': 'https://maps.googleapis.com/maps/api/place/textsearch/json?query=restaurants+in+Sydney&key=',
        'costo': '$32 por 1000 solicitudes',
        'metodo': 'GET',
        'check': lambda resp: 'error_message' not in resp.text,
        'razon': lambda resp: f'Razón: {resp.json()["error_message"]}'
    },
    'Places Photo': {
        'url': 'https://maps.googleapis.com/maps/api/place/photo?maxwidth=400&photoreference=CnRtAAAATLZNl354RwP_9UKbQ_5Psy40texXePv4oAlgP4qNEkdIrkyse7rPXYGd9D_Uj1rVsQdWT4oRz4QrYAJNpFX7rzqqMlZw2h2E2y5IKMUZ7ouD_SlcHxYq1yL4KbKUv3qtWgTK0A6QbGh87GB3sscrHRIQiG2RrmU_jF4tENr9wGS_YxoUSSDrYjWmrNfeEHSGSc3FyhNLlBU&key=',
        'costo': '$7 por 1000 solicitudes',
        'metodo': 'GET',
        'check': lambda resp: resp.status_code == 302,
        'razon': 'Las respuestas detalladas no están habilitadas para esta API.'
    },
    'FCM': {
        'url': 'https://fcm.googleapis.com/fcm/send',
        'costo': 'FCM Takeover || https://abss.me/posts/fcm-takeover/',
        'metodo': 'POST',
        'data': "{'registration_ids':['ABC']}",
        'headers': {'Content-Type': 'application/json'},
        'check': lambda resp: resp.status_code == 200,
        'razon': 'No vulnerable.'
    }
}

def check_api(nombre, api_data, apikey):
    """
    Función genérica para probar una API y devolver un dict de resultados.
    """
    try:
        url_completa = api_data['url'] + apikey
        if api_data['metodo'] == 'GET':
            response = requests.get(url_completa, verify=False, allow_redirects=False, timeout=10)
        elif api_data['metodo'] == 'POST':
            headers = api_data.get('headers', {})
            headers['Authorization'] = f'key={apikey}'
            response = requests.post(api_data['url'], data=api_data.get('data'), headers=headers, verify=False, timeout=10)
    except requests.exceptions.RequestException as e:
        return {'api': nombre, 'status': 'Error', 'details': f"Error de conexión: {e}"}
    
    if api_data['check'](response):
        return {'api': nombre, 'status': 'Vulnerable', 'costo': api_data['costo'], 'url': url_completa}
    else:
        if callable(api_data['razon']):
            try:
                razon_mensaje = api_data['razon'](response)
            except (json.JSONDecodeError, KeyError):
                razon_mensaje = "No vulnerable. Error al parsear JSON o clave no encontrada."
        else:
            razon_mensaje = api_data['razon']
        return {'api': nombre, 'status': 'No Vulnerable', 'details': razon_mensaje}

def scan_gmaps(apikey):
    """
    Escanea la clave API y muestra los resultados en un formato claro.
    """
    print("\nIniciando escaneo de la clave API...")
    print("Esto puede tomar unos minutos...\n")
    
    all_results = []
    
    for nombre, datos in APIS.items():
        all_results.append(check_api(nombre, datos, apikey))

    # Formatear datos para la tabla
    tabla_data = []
    vulnerable_apis_details = []
    
    for res in all_results:
        if res['status'] == 'Vulnerable':
            tabla_data.append([res['api'], f"\033[1;31;40mVulnerable\033[0m"])
            vulnerable_apis_details.append(res)
        elif res['status'] == 'No Vulnerable':
            tabla_data.append([res['api'], f"\033[1;32mNo Vulnerable\033[0m"])
        else:
            tabla_data.append([res['api'], f"\033[1;33mError\033[0m"])

    # Imprimir la tabla de resumen
    print("-" * 50)
    print("Resumen del estado de las APIs")
    print("-" * 50)
    if tabulate:
        print(tabulate(tabla_data, headers=["API", "Estado"], tablefmt="grid"))
    else:
        for api, status in tabla_data:
            print(f"- {api}: {status}")

    # Imprimir detalles de las APIs vulnerables
    print("\n" + "=" * 50)
    if vulnerable_apis_details:
        print("Detalles de vulnerabilidad (Acceso sin restricción de clave)")
        print("=" * 50)
        for api in vulnerable_apis_details:
            print(f"[*] **{api['api']}**")
            print(f"    Costo: {api['costo']}")
            if api['api'] in ['Geolocation', 'FCM']:
                print(f"    PoC: {api['url']}")
            else:
                print(f"    PoC URL: {api['url']}")
            print("")
    else:
        print("¡Excelente! La clave API no parece ser vulnerable a ninguna de las APIs probadas.")
    
    print("=" * 50)
    print("\nReferencia de precios actualizados: https://cloud.google.com/maps-platform/pricing/sheet/")

    # Prueba manual de la API de JavaScript
    print("\n---")
    jsapi_choice = input("¿Deseas realizar pruebas para la API de Javascript? (Requiere confirmación manual + creación de archivo) (Y/N): ")
    if jsapi_choice.lower() == 'y':
        file_name = "jsapi_test.html"
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <script src="https://maps.googleapis.com/maps/api/js?key={apikey}&callback=initMap&libraries=&v=weekly" defer></script>
    <style type="text/css">
        #map {{ height: 100%; }}
        html, body {{ height: 100%; margin: 0; padding: 0; }}
    </style>
    <script>
        let map;
        function initMap() {{
            map = new google.maps.Map(document.getElementById("map"), {{
                center: {{lat: -34.397, lng: 150.644}},
                zoom: 8,
            }});
        }}
    </script>
</head>
<body>
    <div id="map"></div>
</body>
</html>
"""
        try:
            with open(file_name, "w") as f:
                f.write(html_content)
            
            print(f"\nSe ha creado el archivo '{file_name}'. Ábrelo en tu navegador y observa si el mapa se carga correctamente.")
            print("Si ves un mapa, la clave es vulnerable. Si ves un error, está restringida por dominio.")
            input("Presiona 'Enter' para continuar y eliminar el archivo...")
            os.remove(file_name)
        except Exception as e:
            print(f"Error al crear el archivo: {e}")
    
    print("\nOperación finalizada. ¡Gracias por usar el Escáner de API de Google Maps!")
    return True

def main():
    """
    Función principal para manejar la ejecución del script.
    """
    if len(sys.argv) > 1:
        if sys.argv[1] in ["--api-key", "-a"]:
            if len(sys.argv) > 2:
                scan_gmaps(sys.argv[2])
            else:
                print("Falta la clave API. Usa: `python script.py -a TU_CLAVE_API`")
        elif sys.argv[1] in ["--help", "-h"]:
            print("Uso:")
            print("  - Para pasar la clave API como argumento: `python script.py --api-key TU_CLAVE_API` o `python script.py -a TU_CLAVE_API`")
            print("  - Para introducir la clave API de forma interactiva: `python script.py`")
        else:
            print("Argumento no válido. Usa `--help` para ver las opciones.")
    else:
        apikey = input("Por favor, introduce la clave API de Google Maps que deseas probar: ")
        scan_gmaps(apikey)

if __name__ == "__main__":
    main()