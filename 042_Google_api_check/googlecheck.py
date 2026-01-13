import requests
import warnings
import sys
import os
import json
from time import sleep
from datetime import datetime # Nueva importación para la fecha

# Desactiva las advertencias de SSL para entornos de prueba.
warnings.filterwarnings("ignore")

# ------------------------------------------------------------------------
## NUEVAS FUNCIONES DE GESTIÓN DE REPORTES
# ------------------------------------------------------------------------

def get_report_dir():
    """
    Construye y devuelve la ruta absoluta del directorio de reportes:
    ./Reporte/YYYY-MM-DD/
    Crea el directorio si no existe.
    """
    # Obtener la fecha actual en formato YYYY-MM-DD
    fecha_actual = datetime.now().strftime("%Y-%m-%d")
    # Construir la ruta de la carpeta de reportes (ej: Reporte/2025-10-06)
    report_dir = os.path.join("Reporte", fecha_actual)
    
    # Crear el directorio si no existe
    if not os.path.exists(report_dir):
        try:
            os.makedirs(report_dir)
            print(f"[+] Directorio de Reporte Creado: {report_dir}")
        except OSError as e:
            print(f"[CRÍTICO] Error al crear el directorio de reporte '{report_dir}': {e}")
            # En caso de error crítico, salimos para evitar fallos de escritura posteriores
            sys.exit(1)
            
    return report_dir

def get_report_filepath(filename):
    """
    Devuelve la ruta completa para un archivo dentro del directorio de reportes.
    """
    report_dir = get_report_dir()
    return os.path.join(report_dir, filename)

def save_vulnerable_details(details, apikey, jsapi_result):
    """
    Guarda los detalles de las APIs vulnerables y el resultado de la JS API 
    en un archivo JSON dentro de la carpeta de reportes.
    """
    # Preparar el resultado de la API de JavaScript
    js_api_name = jsapi_result['api']
    js_api_status = jsapi_result['status']
    js_api_costo = jsapi_result['costo']
    js_api_details = jsapi_result['details']

    # Unificar todos los resultados vulnerables
    report_data = {
        'timestamp': datetime.now().isoformat(),
        'api_key': apikey,
        'vulnerable_apis': details,
        js_api_name: {
            'status': js_api_status,
            'costo': js_api_costo,
            'details': js_api_details
        }
    }

    # Definir el nombre del archivo JSON
    file_name_short = apikey[:8] if len(apikey) >= 8 else apikey
    json_filename = f"Vulnerabilities_{file_name_short}.json"
    full_path = get_report_filepath(json_filename)

    try:
        with open(full_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=4)
        print(f"\n[+] Detalles de Vulnerabilidad GUARDADOS en JSON: {full_path}")
    except Exception as e:
        print(f"[ERROR] No se pudo guardar el archivo JSON de vulnerabilidades: {e}")

# ------------------------------------------------------------------------
## CONSTANTES Y FUNCIONES DE ESCANEO
# ------------------------------------------------------------------------

# Define las APIs a probar, sus URLs y otros datos relevantes en un diccionario.
# Los costos se han escrito de forma explícita, sin abreviaciones.
APIS = {
    'Staticmap': {
        'url': 'https://maps.googleapis.com/maps/api/staticmap?center=45%2C10&zoom=7&size=400x400&key=',
        'costo': 'Aproximadamente $2 por 1000 llamadas',
        'metodo': 'GET',
        'check': lambda resp: resp.status_code == 200,
        'razon': 'Revisa el motivo manualmente en la URL.'
    },
    'Streetview': {
        'url': 'https://maps.googleapis.com/maps/api/streetview?size=400x400&location=40.720032,-73.988354&fov=90&heading=235&pitch=10&key=',
        'costo': 'Aproximadamente $7 por 1000 llamadas',
        'metodo': 'GET',
        'check': lambda resp: resp.status_code == 200,
        'razon': 'Revisa el motivo manualmente en la URL.'
    },
    'Directions': {
        'url': 'https://maps.googleapis.com/maps/api/directions/json?origin=Disneyland&destination=Universal+Studios+Hollywood4&key=',
        'costo': 'Aproximadamente $5 por 1000 llamadas',
        'metodo': 'GET',
        'check': lambda resp: 'error_message' not in resp.text,
        'razon': lambda resp: f'Razón: {resp.json().get("error_message", "Respuesta sin campo de error.")}'
    },
    'Geocode': {
        'url': 'https://maps.googleapis.com/maps/api/geocode/json?latlng=40,30&key=',
        'costo': 'Aproximadamente $5 por 1000 llamadas',
        'metodo': 'GET',
        'check': lambda resp: 'error_message' not in resp.text,
        'razon': lambda resp: f'Razón: {resp.json().get("error_message", "Respuesta sin campo de error.")}'
    },
    'Distance Matrix': {
        'url': 'https://maps.googleapis.com/maps/api/distancematrix/json?units=imperial&origins=40.6655101,-73.89188969999998&destinations=40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.659569%2C-73.933783%7C40.729029%2C-73.851524%7C40.6860072%2C-73.6334271%7C40.598566%2C-73.7527626%7C40.659569%2C-73.933783%7C40.729029%2C-73.851524%7C40.6860072%2C-73.6334271%7C40.598566%2C-73.7527626&key=',
        'costo': 'Aproximadamente $5 por 1000 llamadas',
        'metodo': 'GET',
        'check': lambda resp: 'error_message' not in resp.text,
        'razon': lambda resp: f'Razón: {resp.json().get("error_message", "Respuesta sin campo de error.")}'
    },
    'Find Place From Text': {
        'url': 'https://maps.googleapis.com/maps/api/place/findplacefromtext/json?input=Museum%20of%20Contemporary%20Art%20Australia&inputtype=textquery&fields=photos,formatted_address,name,rating,opening_hours,geometry&key=',
        'costo': 'Aproximadamente $17 por 1000 llamadas',
        'metodo': 'GET',
        'check': lambda resp: 'error_message' not in resp.text,
        'razon': lambda resp: f'Razón: {resp.json().get("error_message", "Respuesta sin campo de error.")}'
    },
    'Autocomplete': {
        'url': 'https://maps.googleapis.com/maps/api/place/autocomplete/json?input=Bingh&types=%28cities%29&key=',
        'costo': 'Aproximadamente $2.83 por 1000 llamadas',
        'metodo': 'GET',
        'check': lambda resp: 'error_message' not in resp.text,
        'razon': lambda resp: f'Razón: {resp.json().get("error_message", "Respuesta sin campo de error.")}'
    },
    'Elevation': {
        'url': 'https://maps.googleapis.com/maps/api/elevation/json?locations=39.7391536,-104.9847034&key=',
        'costo': 'Aproximadamente $5 por 1000 llamadas',
        'metodo': 'GET',
        'check': lambda resp: 'error_message' not in resp.text,
        'razon': lambda resp: f'Razón: {resp.json().get("error_message", "Respuesta sin campo de error.")}'
    },
    'Timezone': {
        'url': 'https://maps.googleapis.com/maps/api/timezone/json?location=39.6034810,-119.6822510&timestamp=1331161200&key=',
        'costo': 'Aproximadamente $5 por 1000 llamadas',
        'metodo': 'GET',
        'check': lambda resp: 'errorMessage' not in resp.text,
        'razon': lambda resp: f'Razón: {resp.json().get("errorMessage", "Respuesta sin campo de error.")}'
    },
    'Nearest Roads': {
        'url': 'https://roads.googleapis.com/v1/nearestRoads?points=60.170880,24.942795|60.170879,24.942796|60.170877,24.942796&key=',
        'costo': 'Aproximadamente $10 por 1000 llamadas',
        'metodo': 'GET',
        'check': lambda resp: 'error' not in resp.text,
        'razon': lambda resp: f'Razón: {resp.json().get("error", {}).get("message", "Respuesta sin campo de error.")}'
    },
    'Geolocation': {
        'url': 'https://www.googleapis.com/geolocation/v1/geolocate?key=',
        'costo': 'Aproximadamente $5 por 1000 llamadas',
        'metodo': 'POST',
        'data': json.dumps({'considerIp': 'true'}),
        'headers': {'Content-Type': 'application/json'},
        'check': lambda resp: 'error' not in resp.text,
        'razon': lambda resp: f'Razón: {resp.json().get("error", {}).get("message", "Respuesta sin campo de error.")}'
    },
    'Route to Traveled': {
        'url': 'https://roads.googleapis.com/v1/snapToRoads?path=-35.27801,149.12958|-35.28032,149.12907&interpolate=true&key=',
        'costo': 'Aproximadamente $10 por 1000 llamadas',
        'metodo': 'GET',
        'check': lambda resp: 'error' not in resp.text,
        'razon': lambda resp: f'Razón: {resp.json().get("error", {}).get("message", "Respuesta sin campo de error.")}'
    },
    'Speed Limit-Roads': {
        'url': 'https://roads.googleapis.com/v1/speedLimits?path=38.75807927603043,-9.03741754643809&key=',
        'costo': 'Aproximadamente $20 por 1000 llamadas',
        'metodo': 'GET',
        'check': lambda resp: 'error' not in resp.text,
        'razon': lambda resp: f'Razón: {resp.json().get("error", {}).get("message", "Respuesta sin campo de error.")}'
    },
    'Place Details': {
        'url': 'https://maps.googleapis.com/maps/api/place/details/json?place_id=ChIJN1t_tDeuEmsRUsoyG83frY4&fields=name,rating,formatted_phone_number&key=',
        'costo': 'Aproximadamente $17 por 1000 llamadas',
        'metodo': 'GET',
        'check': lambda resp: 'error_message' not in resp.text,
        'razon': lambda resp: f'Razón: {resp.json().get("error_message", "Respuesta sin campo de error.")}'
    },
    'Nearby Search-Places': {
        'url': 'https://maps.googleapis.com/maps/api/place/nearbysearch/json?location=-33.8670522,151.1957362&radius=100&types=food&name=harbour&key=',
        'costo': 'Aproximadamente $32 por 1000 llamadas',
        'metodo': 'GET',
        'check': lambda resp: 'error_message' not in resp.text,
        'razon': lambda resp: f'Razón: {resp.json().get("error_message", "Respuesta sin campo de error.")}'
    },
    'Text Search-Places': {
        'url': 'https://maps.googleapis.com/maps/api/place/textsearch/json?query=restaurants+in+Sydney&key=',
        'costo': 'Aproximadamente $32 por 1000 llamadas',
        'metodo': 'GET',
        'check': lambda resp: 'error_message' not in resp.text,
        'razon': lambda resp: f'Razón: {resp.json().get("error_message", "Respuesta sin campo de error.")}'
    },
    'Places Photo': {
        'url': 'https://maps.googleapis.com/maps/api/place/photo?maxwidth=400&photoreference=CnRtAAAATLZNl354RwP_9UKbQ_5Psy40texXePv4oAlgP4qNEkdIrkyse7rPXYGd9D_Uj1rVsQdWT4oRz4QrYAJNpFX7rzqqMlZw2h2E2y5IKMUZ7ouD_SlcHxYq1yL4KbKUv3qtWgTK0A6QbGh87GB3sscrHRIQiG2RrmU_jF4tENr9wGS_YxoUSSDrYjWmrNfeEHSGSc3FyhNLlBU&key=',
        'costo': 'Aproximadamente $7 por 1000 llamadas',
        'metodo': 'GET',
        'check': lambda resp: resp.status_code == 302,
        'razon': 'Las respuestas detalladas no están habilitadas para esta API.'
    },
    'FCM': {
        'url': 'https://fcm.googleapis.com/fcm/send',
        'costo': 'Vulnerable: FCM Takeover',
        'metodo': 'POST',
        'data': json.dumps({'registration_ids':['ABC']}),
        'headers': {'Content-Type': 'application/json'},
        'check': lambda resp: resp.status_code == 200,
        'razon': 'No vulnerable.'
    }
}

def check_api(nombre, api_data, apikey):
    """
    Función genérica para probar una API y devolver un dict de resultados.
    Incluye manejo de errores para peticiones HTTP y parsing JSON.
    """
    try:
        # Lógica de construcción de URL y solicitud HTTP (GET/POST)
        url_completa = api_data['url'] + apikey
        headers = api_data.get('headers', {})

        if api_data['metodo'] == 'GET':
            response = requests.get(url_completa, verify=False, allow_redirects=False, timeout=10)
        
        elif api_data['metodo'] == 'POST':
            # Manejo específico para FCM (clave en header) o Geolocation (clave en URL)
            if nombre == 'FCM':
                # FCM espera una Server Key, pero probamos la exposición con la API key proporcionada
                headers['Authorization'] = f'key={apikey}'
                response = requests.post(api_data['url'], data=api_data.get('data'), headers=headers, verify=False, timeout=10)
            else:
                # Otros POST con clave en URL (ej. Geolocation)
                response = requests.post(url_completa, data=api_data.get('data'), headers=headers, verify=False, timeout=10)

    except requests.exceptions.RequestException as e:
        # Error de conexión, timeout, DNS, etc.
        return {'api': nombre, 'status': 'Error', 'details': f"Error de conexión HTTP: {e}", 'costo': api_data['costo']}
    except Exception as e:
        # Error general inesperado
        return {'api': nombre, 'status': 'Error', 'details': f"Error inesperado al ejecutar: {e}", 'costo': api_data['costo']}

    # Comprobación de la vulnerabilidad/acceso
    if api_data['check'](response):
        # API Vulnerable/Explotable
        return {'api': nombre, 'status': 'Vulnerable', 'costo': api_data['costo'], 'url': url_completa}
    else:
        # API No Vulnerable: intenta obtener la razón del error
        if callable(api_data['razon']):
            try:
                # Intentar parsear la respuesta JSON para obtener el mensaje de error
                if response.text:
                    razon_mensaje = api_data['razon'](response)
                else:
                    razon_mensaje = f"No vulnerable. Código de estado: {response.status_code}. Respuesta vacía."
            except (json.JSONDecodeError, KeyError, AttributeError):
                razon_mensaje = f"No vulnerable. Código de estado: {response.status_code}. (No se pudo parsear la razón)."
        else:
            razon_mensaje = api_data['razon']
        
        return {'api': nombre, 'status': 'No Vulnerable', 'details': razon_mensaje, 'costo': api_data['costo']}

def print_simple_table(header, data):
    """
    Imprime una tabla en formato de texto simple, corrigiendo la alineación
    cuando se usan códigos de color ANSI.
    """
    col_width_api = 30
    col_width_status = 25
    col_width_costo = 35 # Aumentado para costos explícitos
    
    # Define la longitud total para la línea divisoria
    total_width = col_width_api + col_width_status + col_width_costo + 4
    
    # Imprimir encabezado
    print("-" * total_width)
    print(f"{header[0]:<{col_width_api}} | {header[1]:<{col_width_status}} | {header[2]:<{col_width_costo}}")
    print("-" * total_width)
    
    # Imprimir filas
    for api, raw_status, status_color, costo in data:
        # Cálculo del padding: (Ancho deseado) - (Longitud del texto sin color)
        padding_needed = col_width_status - len(raw_status)
        padding_str = " " * padding_needed

        # Imprimir la línea: API (alineada) | Colorized Status + Padding | Costo (alineado)
        print(f"{api:<{col_width_api}} | {status_color}{padding_str} | {costo:<{col_width_costo}}")
    print("-" * total_width)

def print_key_banner(apikey):
    """Imprime el banner de identificación de la clave API, mostrando la clave completa."""
    key_display = apikey # Muestra la clave completa
    
    # Ajusta el ancho del banner: mínimo 80, o suficiente para contener la clave más el texto
    banner_width = max(80, len(key_display) + len("[*] Clave API bajo auditoría: ") + 10)
    
    print("=" * banner_width)
    print(f"[*] Clave API bajo auditoría: \033[1;36m{key_display}\033[0m")
    print("=" * banner_width)


def scan_gmaps(apikey):
    """
    Ejecuta el escaneo de APIs, muestra la tabla inicial, realiza la prueba
    manual, y luego muestra el resumen final de auditoría.
    
    MODIFICADA: Usa get_report_filepath para el archivo HTML.
    MODIFICADA: Llama a save_vulnerable_details al final.
    """
    
    # 1. CREAR DIRECTORIO DE REPORTE (Se hace implícitamente en get_report_filepath)
    report_directory = get_report_dir() 
    print(f"[*] Toda la evidencia se guardará en: {report_directory}")

    print("\nIniciando escaneo de la clave API...")
    print("Esto puede tomar unos minutos...\n")
    
    all_results = []
    
    # 1. Escaneo de APIs de Servicios (Automático)
    for nombre, datos in APIS.items():
        all_results.append(check_api(nombre, datos, apikey))
        sleep(0.1) # Pausa ligera para evitar bloqueos

    # Formatear datos para la TABLA DE RESUMEN INICIAL (SOLO AUTOMÁTICAS)
    initial_summary_data = []
    vulnerable_apis_details = []
    
    for res in all_results:
        status_text = res['status'] # Texto sin color
        if status_text == 'Vulnerable':
            status_color = f"\033[1;31;40mVulnerable\033[0m" # Rojo
            vulnerable_apis_details.append(res)
        elif status_text == 'No Vulnerable':
            status_color = f"\033[1;32mNo Vulnerable\033[0m" # Verde
        else:
            status_color = f"\033[1;33mError\033[0m" # Amarillo

        # Añadir al resumen inicial: [API, RAW_Status, Color_Status, Costo]
        initial_summary_data.append([res['api'], status_text, status_color, res['costo']])
    
    # ----------------------------------------------------
    # 2. Impresión de la TABLA DE RESUMEN PRELIMINAR
    # ----------------------------------------------------
    print("\n" + "=" * 80)
    print("--- RESUMEN PRELIMINAR DE APIs AUDITADAS (SERVICIOS WEB) ---")
    print("======================================================================")

    # IMPRESION DEL BANNER DE LA CLAVE API
    print_key_banner(apikey)
    
    print_simple_table(
        header=["API Auditada", "Estado", "Costo Estimado"],
        data=initial_summary_data
    )
    
    # ----------------------------------------------------
    # 3. Prueba manual de la API de JavaScript (Host Restriction)
    # ----------------------------------------------------
    jsapi_costo = 'Aproximadamente $7 por 1000 llamadas'
    jsapi_api_name = 'JavaScript API (Host)'
    jsapi_raw_status = 'Omitida'
    # Resultado inicial para la prueba manual si se omite
    jsapi_result = {'api': jsapi_api_name, 'status': jsapi_raw_status, 'details': 'El usuario omitió la prueba.', 'costo': jsapi_costo}
    
    print("\n" + "=" * 80)
    print("--- PRUEBA MANUAL: API de JavaScript (Exposición en Host) ---")
    print("======================================================================")
    
    jsapi_choice = input("¿Deseas realizar pruebas para la API de Javascript? (Y/N): ")
    
    # El bloque de prueba manual para la API de JavaScript
    if jsapi_choice.lower() == 'y':
        # Nombre de archivo para la PoC
        file_name_short = apikey[:8] if len(apikey) >= 8 else apikey
        file_name = f"PoC_JS_API_TEST_{file_name_short}.html"
        
        # Usar la nueva función para obtener la ruta completa del archivo
        full_file_path = get_report_filepath(file_name) 
        
        # --- Lógica de la PoC: CORREGIDA y más fiable ---
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>PoC Mejorada: Exposición de Google Maps JS API - Clave: {apikey}</title>
    <meta name="description" content="Prueba de concepto generada por el Escáner de API de Google Maps.">
    
    <script 
        src="https://maps.googleapis.com/maps/api/js?key={apikey}&callback=initMap&v=weekly" 
        async defer>
    </script>
    
    <style type="text/css">
        #map {{ height: 400px; width: 600px; margin: 20px auto; text-align: center; padding-top: 50px; background-color: #f0f0f0; }}
        body {{ font-family: Arial, sans-serif; background-color: #f4f4f4; text-align: center; }}
        .disclaimer {{ background-color: #ffe5e5; border: 1px solid #d9534f; padding: 15px; margin: 20px auto; max-width: 600px; border-radius: 5px; color: #333; text-align: left; }}
        h2 {{ margin-top: 0; }}
        
        /* Estilos de retroalimentación */
        .success {{ border: 5px solid green !important; background-color: #e6ffe6; }} /* Carga Exitosa (VULNERABLE) */
        .blocked {{ border: 5px solid blue !important; background-color: #e6f0ff; }} /* Bloqueada (SEGURO) */
        .failure {{ border: 5px solid orange !important; background-color: #fff8e6; }} /* Fallo de red/URL */
    </style>
    
    <script>
        // Esta variable se establece a 'true' SÓLO si el script de Google Maps se ejecuta con éxito.
        let initMapCalled = false;
        
        // 1. Manejo de carga EXITOSA (Se llama SOLO si la clave es válida Y no está restringida al dominio)
        function initMap() {{
            const mapElement = document.getElementById("map");
            initMapCalled = true;
            
            if (mapElement) {{
                mapElement.classList.add('success'); // ✅ VERDE: Éxito (VULNERABLE)
                mapElement.innerHTML = '<h2>✅ CARGA EXITOSA (VULNERABLE)</h2><p>La clave API es USABLE en este dominio.</p><p><strong>CRÍTICO: No está restringida por dominio!</strong></p><p>Mapa Renderizado (o error si Maps no está habilitado, pero la vulnerabilidad es la carga exitosa).</p>';
                
                // Intenta dibujar el mapa
                try {{
                    new google.maps.Map(mapElement, {{
                        center: {{lat: -34.397, lng: 150.644}},
                        zoom: 8,
                    }});
                }} catch (e) {{
                    // Esto maneja errores de inicialización *después* de que initMap es llamado (ej. Maps no habilitado)
                    mapElement.innerHTML += '<p style="color:red;">El mapa falló al renderizarse, pero la vulnerabilidad de la clave ha sido confirmada.</p>';
                }}
            }}
        }}

        // 2. Mecanismo de respaldo robusto (Comprueba después de un tiempo si initMap fue llamado)
        window.onload = function() {{
            setTimeout(() => {{
                const mapElement = document.getElementById("map");
                
                if (mapElement && !initMapCalled) {{
                    // Si initMap NO fue llamado, la carga fue bloqueada (restricción de referer) o la clave es inválida.
                    mapElement.classList.add('blocked'); // 🔵 AZUL: Bloqueado/Fallido (SEGURO)
                    mapElement.innerHTML = '<h2>🔵 CARGA BLOQUEADA/FALLIDA (SEGURO)</h2><p>El callback <code>initMap</code> **no se ejecutó**.</p><p>Esto significa que la clave está **restringida a otro dominio** (¡Buena señal de seguridad!) o es inválida/expirada.</p><p><strong>ACCION:</strong> Revisa la consola (F12) para el error oficial (KeyNotRestricted/InvalidKey).</p>';
                }}
            }}, 3000); // Espera 3 segundos para el callback
        }};
        
    </script>
</head>
<body>
    <div class="disclaimer">
        <h2>⚠️ PRUEBA DE CONCEPTO: EXPOSICIÓN DE CLAVE API (JS)</h2>
        <p><strong>Clave API en prueba:</strong> <code>{apikey}</code></p>
        <p><strong>Instrucción:</strong></p>
        <ul>
            <li>Si el borde se vuelve **VERDE** (✅): La clave es **vulnerable** (la función <code>initMap</code> se ejecutó exitosamente).</li>
            <li>Si el borde se vuelve **AZUL** (🔵): La clave está **restringida** o es inválida (seguro, la función <code>initMap</code> fue bloqueada).</li>
        </ul>
        <p><strong>Vulnerabilidad:</strong> Falta de restricción de referencia HTTP (HTTP Referer).</p>
    </div>
    <div id="map">Esperando la carga de Google Maps...</div>
</body>
</html>
"""
        # --- Fin de la Lógica de la PoC CORREGIDA ---
        try:
            # Escribir el archivo en la ruta completa
            with open(full_file_path, "w", encoding="utf-8") as f:
                f.write(html_content)
            
            print(f"\n[+] **ARCHIVO DE EVIDENCIA CREADO:** **{full_file_path}**") # Muestra la ruta completa
            print("    1. Ábrelo en tu navegador y evalúa el resultado visualmente (VERDE o AZUL).")
            
            input("\nPresiona 'Enter' una vez que hayas realizado la prueba visual...")
            
            vulnerable_input = input("¿El borde se volvió VERDE y mostró 'CARGA EXITOSA (VULNERABLE)'? (Y/N): ")
            
            if vulnerable_input.lower() == 'y':
                jsapi_raw_status = 'Vulnerable'
                jsapi_status_color = f'\033[1;31;40mVulnerable\033[0m'
                jsapi_result['status'] = jsapi_raw_status
                jsapi_result['details'] = f'Clave expuesta a uso en cualquier host. **PoC: {full_file_path}**'
                print(f"\n[!] ¡VULNERABLE! Evidencia guardada en '{full_file_path}'.")
                
                # AÑADIR A LA LISTA DE VULNERABLES
                vulnerable_apis_details.append({
                    'api': jsapi_api_name,
                    'costo': jsapi_costo,
                    'url': f'Ver archivo PoC: {full_file_path}', # Guarda la ruta completa
                    'status': jsapi_raw_status
                })
            else:
                jsapi_raw_status = 'No Vulnerable'
                jsapi_status_color = f'\033[1;32mNo Vulnerable\033[0m'
                jsapi_result['status'] = jsapi_raw_status
                jsapi_result['details'] = f'Restringida correctamente por HTTP Referer. Evidencia de prueba: {full_file_path}'
                print("\n[+] No Vulnerable. Restricción por dominio detectada. Evidencia guardada.")
                
        except Exception as e:
            jsapi_raw_status = 'Error'
            jsapi_status_color = f'\033[1;33mError\033[0m'
            jsapi_result['status'] = jsapi_raw_status
            jsapi_result['details'] = f"Error al crear/procesar el archivo: {e}. Evidencia parcial: {full_file_path}"
            print(f"\n[X] Error crítico en prueba manual: {e}")
    
    # 4. Consolidar todos los resultados (Automático + Manual)
    final_summary_data = []
    
    # Agregar resultados automáticos primero
    for res in all_results:
        status_text = res['status']
        # Buscar el color generado previamente
        status_color = next((item[2] for item in initial_summary_data if item[0] == res['api']), f"\033[1;33m{status_text}\033[0m")
        final_summary_data.append([res['api'], status_text, status_color, res['costo']])

    # Agregar resultado manual al final
    if jsapi_raw_status == 'Vulnerable':
        jsapi_status_color = f'\033[1;31;40mVulnerable\033[0m'
    elif jsapi_raw_status == 'No Vulnerable':
        jsapi_status_color = f'\033[1;32mNo Vulnerable\033[0m'
    else:
        jsapi_status_color = f'\033[1;33m{jsapi_raw_status}\033[0m' # 'Omitida' o 'Error'

    final_summary_data.append([jsapi_api_name, jsapi_raw_status, jsapi_status_color, jsapi_costo])

    # ----------------------------------------------------
    # 5. Impresión de la TABLA FINAL UNIFICADA 
    # ----------------------------------------------------
    print("\n\n" + "#" * 80)
    print("--- RESULTADO FINAL CONSOLIDADO DE AUDITORÍA ---")
    print("#" * 80)

    # IMPRESION DEL BANNER DE LA CLAVE API
    print_key_banner(apikey)
    
    print_simple_table(
        header=["API Auditada", "Estado", "Costo Estimado"],
        data=final_summary_data
    )
    
    # ----------------------------------------------------
    # 6. Guardar y Imprimir DETALLES DE VULNERABILIDAD
    # ----------------------------------------------------
    
    # Guardar los detalles de vulnerabilidad en un JSON
    save_vulnerable_details(vulnerable_apis_details, apikey, jsapi_result)
    
    print("\n" + "=" * 80)
    if vulnerable_apis_details:
        print("--- DETALLES Y EVIDENCIA DE VULNERABILIDAD (PoC) ---")
        print("= Estos son los resultados críticos que requieren mitigación =")
        print("=" * 80)
        for api in vulnerable_apis_details:
            print(f"[*] **{api['api']}**")
            print(f"    Costo/Impacto: {api.get('costo', 'N/A')}")
            
            if api['api'] == 'FCM':
                print(f"    Evidencia: La clave es vulnerable a FCM Takeover. Endpoint (POST): {api['url']}")
                print("    Referencia: https://abss.me/posts/fcm-takeover/")
            elif api['api'] == jsapi_api_name:
                print(f"    Evidencia (Archivo): {api.get('url', 'PoC no generado')}")
            else:
                print(f"    PoC URL: {api['url']}")
            print("")
    else:
        print("¡Excelente! No se detectaron vulnerabilidades en las APIs probadas (Servicios y Host).")
    print("=" * 80)

    print("\nReferencia de precios: https://cloud.google.com/maps-platform/pricing/sheet/")
    print("Operación finalizada. ¡Toda la evidencia de prueba ha sido guardada!")
    return True

def main():
    """
    Función principal para manejar la ejecución del script.
    Realiza la sanitización y validación de la clave API.
    """
    try:
        # Sanitización de la clave API
        apikey = ""
        # Manejo de argumentos de línea de comandos
        if len(sys.argv) > 1 and sys.argv[1] in ["--api-key", "-a"]:
            if len(sys.argv) > 2:
                apikey = sys.argv[2].strip() # Sanitización de argumento
            else:
                print("Falta la clave API. Usa: `python script.py -a TU_CLAVE_API`")
                sys.exit(1)
        # Manejo de ayuda
        elif len(sys.argv) > 1 and sys.argv[1] in ["--help", "-h"]:
            print("Uso:")
            print("  - Para pasar la clave API como argumento: `python script.py --api-key TU_CLAVE_API` o `python script.py -a TU_CLAVE_API`")
            print("  - Para introducir la clave API de forma interactiva: `python script.py`")
            sys.exit(0)
        # Manejo de entrada interactiva
        else:
            apikey = input("Por favor, introduce la clave API de Google Maps que deseas probar: ").strip() # Sanitización de input interactivo

        # Validación de la clave API
        if not apikey or len(apikey) < 20: # Las claves de Google API suelen tener ~39 caracteres
            print("\n[ERROR] La clave API proporcionada es inválida o demasiado corta. Por favor, verifica el valor e inténtalo de nuevo.")
            sys.exit(1)
            
        # Si la clave es válida, inicia el escaneo
        scan_gmaps(apikey)

    except KeyboardInterrupt:
        print("\n[!] Escaneo interrumpido por el usuario.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[ERROR CRÍTICO] Ocurrió un error inesperado durante la ejecución: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()