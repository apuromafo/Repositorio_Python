import requests
from bs4 import BeautifulSoup
import os
import time
from urllib.parse import urljoin, urlparse

# Importar la librería para convertir HTML a Markdown
import html2text

# Base URL para la PortSwigger Academy
BASE_URL = "https://portswigger.net"
ACADEMY_INDEX_URL = f"{BASE_URL}/web-security/" 

# Directorio para guardar el contenido (ahora también contendrá las imágenes)
OUTPUT_DIR = "portswigger_academy_content_md_cleaned_final_v4" # Nuevo directorio para esta versión
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Cabeceras para simular un navegador
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Accept-Language': 'en-US,en;q=0.9',
    'Accept-Encoding': 'gzip, deflate, br',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,application/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'Connection': 'keep-alive'
}

# Configuración de html2text
h = html2text.HTML2Text()
h.body_width = 0
h.ignore_links = False
h.ignore_images = False 
h.images_as_html = False 
h.skip_internal_links = False
h.unicode_snob = True
h.google_doc = True
h.wrap_links = False
h.pad_alt_text = True

# Conjunto para llevar un registro de los activos descargados y evitar duplicados
downloaded_assets = set()

def get_html_content_from_url(url):
    """Fetches a URL and returns its raw HTML content."""
    try:
        print(f"Fetching raw HTML for: {url}")
        response = requests.get(url, headers=HEADERS, timeout=15)
        response.raise_for_status()
        return response.text
    except requests.exceptions.RequestException as e:
        print(f"Error fetching {url}: {e}")
        return None

def download_asset(asset_url, target_directory):
    """
    Downloads an asset (e.g., image) and saves it to the specified target_directory.
    Only downloads assets whose URL path starts with '/web-security/images/'.
    """
    global downloaded_assets

    # Filtrar las URLs de los activos aquí
    parsed_asset_url = urlparse(asset_url)
    if not parsed_asset_url.path.startswith('/web-security/images/'):
        print(f"  Skipping asset (not content image): {asset_url}")
        return "" # No descargar, y no devolver una ruta para que no se reescriba

    # Usa la URL completa como clave para evitar duplicados, incluso si se guardan en directorios diferentes
    if asset_url in downloaded_assets:
        local_filename = os.path.basename(parsed_asset_url.path)
        print(f"  Asset already downloaded (returning filename): {local_filename}")
        return local_filename 
    
    try:
        local_filename = os.path.basename(parsed_asset_url.path)
        local_path = os.path.join(target_directory, local_filename)
        
        os.makedirs(os.path.dirname(local_path), exist_ok=True)
        
        response = requests.get(asset_url, headers=HEADERS, timeout=10, stream=True)
        response.raise_for_status()

        with open(local_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        
        downloaded_assets.add(asset_url) 
        print(f"  Downloaded asset: {asset_url} to {local_path}")
        
        return local_filename 
        
    except requests.exceptions.RequestException as e:
        print(f"  Error downloading asset {asset_url}: {e}")
        return "" 

def extract_main_content(html_content, current_page_url, md_save_path_base):
    """
    Parses the full HTML content, extracts the main content section,
    removes unwanted footer-like elements, and downloads/rewrites asset URLs.
    md_save_path_base: La ruta base donde se guardará el MD, para que las imágenes se guarden allí.
    """
    soup = BeautifulSoup(html_content, 'html.parser')

    for tag in soup.find_all(['header', 'footer', 'nav']):
        if tag.get('class') and ('header-container' in tag.get('class') or 
                                 'main-navigation' in tag.get('class') or
                                 'footer-container' in tag.get('class')):
            tag.decompose()
    
    for script_tag in soup.find_all('script'):
        script_tag.decompose()
    for style_tag in soup.find_all('style'):
        style_tag.decompose()
    
    main_content_div = soup.find('div', class_='container-main')
    
    if not main_content_div:
        main_content_div = soup.find('main')
    if not main_content_div:
        main_content_div = soup.find('div', class_='text-block')

    if not main_content_div:
        main_content_div = soup.find('body')
        if not main_content_div:
            return ""

    # --- Lógica de eliminación de "Read more" (pie de página general de la academia) ---
    # Este es el bloque que puede contener el "Register for free to track..."
    # Lo eliminamos primero, porque si está aquí, el otro "REGISTER" es redundante.
    register_header_general = main_content_div.find('h2', string=lambda text: text and "Register for free to track your learning progress" in text)
    if register_header_general:
        current_element = register_header_general
        while current_element:
            next_element = current_element.next_sibling
            current_element.decompose()
            current_element = next_element
            if next_element and (next_element.name == 'h2' or next_element.name == 'h3' or next_element.name == 'div' and 'container-section' in next_element.get('class', [])):
                break # Stop at next major section or header

    read_more_header = main_content_div.find('h3', string=lambda text: text and "Read more" in text)
    if read_more_header:
        current_element = read_more_header
        while current_element:
            # Aseguramos no eliminar el bloque de "Register for free" si está después de "Read more"
            # y es el general. Ya debería haber sido manejado por la lógica anterior.
            if register_header_general and current_element.name == 'h2' and "Register for free" in current_element.get_text(strip=True):
                 break
            next_element = current_element.next_sibling
            current_element.decompose()
            current_element = next_element
            if next_element and (next_element.name == 'h2' or next_element.name == 'h3' or next_element.name == 'div' and 'container-section' in next_element.get('class', [])):
                break # Stop at next major section or header

    # --- NUEVA LÓGICA: Eliminar bloques de registro/publicidad de Burp Suite que aparecen en el medio del contenido ---
    # Esta es una estrategia más general para el bloque "REGISTER" y la lista de progresión.
    # Buscamos elementos que contengan la palabra "REGISTER" o "reCAPTCHA"
    # y luego eliminamos ese elemento y sus hermanos subsiguientes que parezcan parte del bloque.
    
    # Primero, buscar el bloque de "Practise exploiting vulnerabilities" (la lista de 3 puntos)
    ul_to_remove = None
    for ul_tag in main_content_div.find_all('ul'):
        li_texts = [li.get_text(strip=True) for li in ul_tag.find_all('li')]
        if any("Practise exploiting vulnerabilities" in li for li in li_texts) and \
           any("Record your progression" in li for li in li_texts) and \
           any("See where you rank" in li for li in li_texts):
            ul_to_remove = ul_tag
            break
    
    if ul_to_remove:
        print(f"  Removing specific progress UL block: {ul_to_remove.get_text(strip=True)[:100]}...")
        # Guardamos el siguiente hermano antes de descomponerlo para continuar la búsqueda
        next_sibling_after_ul = ul_to_remove.next_sibling
        ul_to_remove.decompose()

        # Ahora, desde el punto donde estaba el UL, buscamos el "REGISTER" que le sigue
        # Usamos una variable auxiliar para iterar
        current_element_to_check = next_sibling_after_ul
        while current_element_to_check:
            text_content = current_element_to_check.get_text(strip=True)
            # Buscar el inicio del bloque "REGISTER" o elementos relacionados
            if "REGISTER" in text_content or \
               "As we use reCAPTCHA" in text_content or \
               "Already got an account?" in text_content or \
               "Want to track your progress" in text_content or \
               "Sign up" in text_content or \
               "Login" in text_content: # Añadimos "Sign up" y "Login" al texto
                print(f"  Removing associated REGISTER element: {current_element_to_check.name} with content: {current_element_to_check.get_text(strip=True)[:50]}...")
                temp_next = current_element_to_check.next_sibling # Guardar el siguiente antes de eliminar
                current_element_to_check.decompose()
                current_element_to_check = temp_next
            else:
                # Si encontramos un elemento que no contiene texto de registro, paramos.
                # Esto es crucial para no eliminar contenido legítimo.
                # Consideramos parar si es otro encabezado o un div/section sin texto de registro.
                if current_element_to_check.name in ['h4', 'h3', 'h2'] or \
                   (current_element_to_check.name in ['div', 'section'] and 
                    not ("REGISTER" in text_content or "reCAPTCHA" in text_content or "Login" in text_content or "Sign up" in text_content)):
                    break
                current_element_to_check = current_element_to_check.next_sibling
    
    # También manejar el bloque "REGISTER" que aparece sin la lista de progresión UL antes
    # Esto es para el caso del CORS que nos mostraste, donde "REGISTER" está después de una OL legítima.
    # Recorre todos los elementos y busca "REGISTER" o "reCAPTCHA"
    elements_in_main_content = list(main_content_div.children) # Convertir a lista para poder iterar de forma segura
    i = 0
    while i < len(elements_in_main_content):
        element = elements_in_main_content[i]
        # Asegurarse de que el elemento no haya sido ya descompuesto
        if not element or not element.parent: # `element.parent` verifica si sigue en el árbol
            i += 1
            continue

        text_content = element.get_text(strip=True)
        if "REGISTER" in text_content or \
           "As we use reCAPTCHA" in text_content or \
           "Already got an account?" in text_content or \
           "Want to track your progress" in text_content:

            print(f"  Removing general REGISTER block starting with: {element.name} with content: {element.get_text(strip=True)[:50]}...")
            
            # Recopilar todos los elementos del bloque de registro
            temp_elements_to_decompose = []
            current_candidate = element
            while current_candidate:
                # Asegurarse de que el elemento no haya sido ya descompuesto
                if not current_candidate.parent:
                    break

                candidate_text = current_candidate.get_text(strip=True)
                if "REGISTER" in candidate_text or \
                   "reCAPTCHA" in candidate_text or \
                   "Login here" in candidate_text or \
                   "Sign up" in candidate_text or \
                   "Login" in candidate_text or \
                   "Want to track your progress" in candidate_text or \
                   (current_candidate.name == 'a' and ('Try for free' in candidate_text or 'Login' in candidate_text or 'Sign up' in candidate_text)):
                    temp_elements_to_decompose.append(current_candidate)
                    current_candidate = current_candidate.next_sibling
                else:
                    # Si encontramos un h4 con "Burp Suite" justo después de este bloque,
                    # probablemente sea el bloque de "Test X APIs using Burp Suite", que también queremos eliminar
                    if current_candidate.name == 'h4' and "Burp Suite" in candidate_text:
                        temp_elements_to_decompose.append(current_candidate)
                        # También buscar su enlace "Try for free" asociado
                        next_sibling_a = current_candidate.find_next_sibling('a', string=lambda t: t and "Try for free" in t)
                        if next_sibling_a:
                            temp_elements_to_decompose.append(next_sibling_a)
                        current_candidate = next_sibling_a.next_sibling if next_sibling_a else current_candidate.next_sibling
                    else:
                        break # No es parte del bloque de registro/promoción
            
            # Decomponer todos los elementos recolectados
            for elem_to_remove in temp_elements_to_decompose:
                if elem_to_remove.parent: # Asegurarse de que no haya sido ya removido
                    elem_to_remove.decompose()
            
            # Ajustar el índice para que no procese elementos ya eliminados
            # Reconstruir la lista de children después de la eliminación
            elements_in_main_content = list(main_content_div.children)
            i = 0 # Reiniciar la búsqueda para estar seguros, o ajustar el índice con cuidado.
                  # Para simplicidad y robustez, reiniciar la búsqueda desde el inicio de main_content_div
                  # después de una eliminación grande es a menudo más seguro.
                  # Aunque para esto, el while i < len(elements_in_main_content)
                  # y el continue en el if not element.parent ya ayuda.
            
            # Dado que estamos modificando la lista mientras iteramos,
            # es más seguro reiniciar la iteración o ajustar el índice con más cuidado.
            # Aquí, solo avanzamos el índice por si acaso, ya que el 'decompose' los sacará.
            # Una estrategia más segura sería volver a obtener `main_content_div.children`
            # después de cada gran bloque de eliminación, o marcar para eliminar y luego hacer una pasada final.
            # Por ahora, simplemente avanzamos. Si un elemento fue descompuesto, su parent será None.
            # La verificación `if not element or not element.parent:` al inicio del bucle `while i < len(elements_in_main_content)`
            # se encargará de esto.
            i += 1 # Avanzar para no quedarse en un bucle infinito si el elemento fue el último.
                   # La lista `elements_in_main_content` se actualiza al inicio del while, si se desea una eliminación precisa.
        else:
            i += 1 # Avanzar al siguiente elemento si no es un bloque de registro


    # --- Descarga y reescritura de URLs de imágenes ---
    target_img_dir = os.path.dirname(md_save_path_base)

    for img_tag in main_content_div.find_all('img'):
        img_src = img_tag.get('src')
        if img_src:
            full_img_url = urljoin(current_page_url, img_src)
            if full_img_url.startswith('http') and not full_img_url.startswith('data:'):
                asset_filename = download_asset(full_img_url, target_img_dir)
                
                if asset_filename:
                    img_tag['src'] = asset_filename
                else:
                    img_tag.decompose()
            else:
                img_tag.decompose() 

    return str(main_content_div)

def save_markdown_content(markdown_text, save_path):
    """Saves Markdown content to a file."""
    try:
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        with open(save_path, "w", encoding="utf-8") as f:
            f.write(markdown_text)
        print(f"Successfully saved Markdown to: {save_path}")
    except IOError as e:
        print(f"Error saving Markdown to {save_path}: {e}")

def get_soup(html_content):
    """Returns a BeautifulSoup object from HTML content."""
    return BeautifulSoup(html_content, 'html.parser')

def extract_topic_links(soup):
    """Extracts main topic links from the academy index page."""
    topic_links = []
    topics_div = soup.find('div', class_='container-academy-topics')
    if topics_div:
        for a_tag in topics_div.find_all('a', href=True):
            href = a_tag['href']
            if href.startswith('/web-security/') and '/web-security/academy' not in href and '#' not in href and not href.endswith('/'):
                full_url = urljoin(BASE_URL, href)
                topic_links.append(full_url)
    
    if not topic_links:
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            parsed_href = urlparse(href)
            if parsed_href.path.startswith('/web-security/') and \
               parsed_href.path.count('/') == 2 and \
               not parsed_href.path.endswith('/') and \
               'academy' not in parsed_href.path and \
               'lab-' not in parsed_href.path and \
               'all-topics' not in parsed_href.path:
                full_url = urljoin(BASE_URL, href)
                topic_links.append(full_url)

    return sorted(list(set(topic_links)))

def extract_lesson_links(soup, base_topic_url):
    """
    Extracts links to individual lessons/labs from a topic page.
    """
    lesson_links = []
    
    possible_content_containers = soup.find_all('div', class_=['container-main', 'container-section', 'container-labs', 'text-block'])

    for container in possible_content_containers:
        for a_tag in container.find_all('a', href=True):
            href = a_tag['href']
            if href.startswith(urlparse(base_topic_url).path + '/') and \
               '/academy/' in href and \
               '#' not in href and \
               not href.endswith('/') and \
               'javascript:' not in href and \
               'all-topics' not in href and \
               'all-labs' not in href and \
               'index.html' not in href:
                
                full_url = urljoin(BASE_URL, href)
                if full_url != base_topic_url and full_url != ACADEMY_INDEX_URL:
                    lesson_links.append(full_url)
                
    return sorted(list(set(lesson_links)))

def create_sanitized_filename(url, extension=".md"):
    """Creates a basic sanitized filename from a URL path."""
    parsed_url = urlparse(url)
    path = parsed_url.path
    
    if path.startswith('/web-security/academy/'):
        path = path[len('/web-security/academy/'):]
    elif path.startswith('/web-security/'):
        path = path[len('/web-security/'):]
        
    filename = path.replace('/', '-').strip('-')
    
    if not filename:
        filename = "index"
        
    if '.' in filename and len(filename.split('.')) > 1:
        filename = filename.rsplit('.', 1)[0]

    return f"{filename}{extension}"

def create_directory_for_url(url_path, base_output_dir):
    """Creates a directory structure mimicking the URL path, simplified for cleanliness."""
    if url_path.startswith('/web-security/academy/'):
        url_path = url_path[len('/web-security/academy/'):]
    elif url_path.startswith('/web-security/'):
        url_path = url_path[len('/web-security/'):]

    path_parts = [part for part in url_path.split('/') if part]
    
    if not path_parts:
        dir_path = base_output_dir
    else:
        if '.' in path_parts[-1] and len(path_parts[-1].split('.')) > 1:
            dir_path = os.path.join(base_output_dir, *path_parts[:-1])
        else:
            dir_path = os.path.join(base_output_dir, *path_parts)
        
    os.makedirs(dir_path, exist_ok=True)
    return dir_path

if __name__ == "__main__":
    print(f"Iniciando descarga desde {ACADEMY_INDEX_URL} a formato Markdown (contenido limpio, activos filtrados con rutas simplificadas y bloques no deseados eliminados).")

    raw_academy_html = get_html_content_from_url(ACADEMY_INDEX_URL)
    if not raw_academy_html:
        print("No se pudo obtener el índice principal de la academia. Saliendo.")
        exit()

    academy_soup = get_soup(raw_academy_html)
    
    academy_md_path = os.path.join(OUTPUT_DIR, "academy_index.md")
    academy_main_content_html = extract_main_content(raw_academy_html, ACADEMY_INDEX_URL, academy_md_path)
    save_markdown_content(h.handle(academy_main_content_html), academy_md_path)
    time.sleep(1)

    main_topic_urls = extract_topic_links(academy_soup)
    print(f"\nSe encontraron {len(main_topic_urls)} temas principales:")
    for url in main_topic_urls:
        print(f"- {url}")

    all_downloaded_urls = set()

    for topic_url in main_topic_urls:
        if topic_url in all_downloaded_urls:
            continue
            
        parsed_topic_url = urlparse(topic_url)
        topic_dir = create_directory_for_url(parsed_topic_url.path, OUTPUT_DIR)
        topic_filename_md = os.path.join(topic_dir, f"{create_sanitized_filename(topic_url)}")
        
        print(f"\n--- Procesando tema: {topic_url} ---")
        raw_topic_html_content = get_html_content_from_url(topic_url)
        all_downloaded_urls.add(topic_url)
        time.sleep(1)

        if raw_topic_html_content:
            topic_main_content_html = extract_main_content(raw_topic_html_content, topic_url, topic_filename_md)
            save_markdown_content(h.handle(topic_main_content_html), topic_filename_md)
            
            topic_soup = get_soup(raw_topic_html_content)
            lesson_urls = extract_lesson_links(topic_soup, topic_url)
            print(f"  Se encontraron {len(lesson_urls)} lecciones/labs para {parsed_topic_url.path.split('/')[-1]}:")

            for lesson_url in lesson_urls:
                if lesson_url not in all_downloaded_urls:
                    print(f"  - Descargando lección/lab: {lesson_url}")
                    parsed_lesson_url = urlparse(lesson_url)
                    
                    lesson_dir = create_directory_for_url(parsed_lesson_url.path, OUTPUT_DIR)
                    lesson_filename_md = os.path.join(lesson_dir, f"{create_sanitized_filename(lesson_url)}")
                    
                    raw_lesson_html_content = get_html_content_from_url(lesson_url)
                    if raw_lesson_html_content:
                        lesson_main_content_html = extract_main_content(raw_lesson_html_content, lesson_url, lesson_filename_md)
                        save_markdown_content(h.handle(lesson_main_content_html), lesson_filename_md)
                        all_downloaded_urls.add(lesson_url)
                    time.sleep(0.7)

    print("\n--- Proceso de descarga a Markdown terminado ---")
    print(f"Total de URLs únicas intentadas descargar: {len(all_downloaded_urls)}")