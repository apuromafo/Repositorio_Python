# ------------------------------------------------------------
# DISCLAIMER: Este script es parte del repositorio de herramientas de pruebas de penetración.
# Su uso está sujeto a los términos de la licencia MIT y al aviso legal presente en el README.
# ------------------------------------------------------------

import logging
logger = logging.getLogger(__name__)
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
logger.addHandler(handler)
logger.setLevel(logging.INFO)

__version__ = "3.0.0"

# =============================================================================
# AVISO LEGAL / LEGAL NOTICE
# -----------------------------------------------------------------------------
# Esta herramienta es unicamente para fines educativos y de auditoria de
# seguridad autorizada. El uso no autorizado contra sistemas sin el
# consentimiento explicito del propietario es ilegal.
# El usuario asume toda responsabilidad por el uso indebido.
#
# This tool is for educational and authorized security auditing purposes only.
# Unauthorized use against systems without the owner's explicit consent is
# illegal. The user assumes all responsibility for misuse.
# =============================================================================

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from bs4 import BeautifulSoup
import os
import sys
import time
import json
import hashlib
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse
from datetime import date
from markitdown import MarkItDown
import re
import argparse as __ap

# ─── ARGPARSE (patrón del repositorio) ─────────────────────
__ap_l = "es"

# ─── CONSTANTES ─────────────────────────────────────────────
BASE_URL = "https://portswigger.net"
ACADEMY_INDEX_URL = f"{BASE_URL}/web-security/all-topics"
IMAGES_DIR_NAME = "images"
HTML_DIR_NAME = "content"
MD_DIR_NAME = "content_md"
ESP_DIR_NAME = "ESP"


def _slugify(text):
    """Convierte texto a slug seguro: lowercase, guiones, sin caracteres especiales."""
    text = text.lower().strip()
    text = re.sub(r'[^\w\s-]', '', text)
    text = re.sub(r'[-\s]+', '-', text)
    return text.strip('-')

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                  'AppleWebKit/537.36 (KHTML, like Gecko) '
                  'Chrome/125.0.0.0 Safari/537.36',
    'Accept-Language': 'en-US,en;q=0.9',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,'
              'image/avif,image/webp,image/apng,*/*;q=0.8',
    'Accept-Encoding': 'gzip, deflate',
    'Connection': 'keep-alive',
}

# ─── SESION CON RETRY ──────────────────────────────────────
_session = requests.Session()
_retries = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
_session.mount('https://', HTTPAdapter(max_retries=_retries))
_session.mount('http://', HTTPAdapter(max_retries=_retries))
_session.headers.update(HEADERS)

# ─── LOCK para estado compartido en multihilo ─────────────
_lock = threading.Lock()

# ─── TEXTOS DE PUBLICIDAD / REGISTRO (para eliminación) ────
_SPAM_PATTERNS = [
    "REGISTER", "reCAPTCHA", "Already got an account?",
    "Want to track your progress", "Sign up", "Login here",
    "Register for free to track your learning progress",
]
_PROGRESS_UL_MARKERS = [
    "Practise exploiting vulnerabilities",
    "Record your progression",
    "See where you rank",
]


# ═══════════════════════════════════════════════════════════
#  FUNCIONES DE RED
# ═══════════════════════════════════════════════════════════

def fetch(url, retries=3, delay=1.0):
    """Descarga una URL con retry y manejo de rate-limit (429)."""
    for attempt in range(1, retries + 1):
        try:
            logger.info(f"[{attempt}/{retries}] GET {url}")
            resp = _session.get(url, timeout=20)
            if resp.status_code == 429:
                wait = int(resp.headers.get('Retry-After', 10))
                logger.warning(f"  429 Rate-limited, esperando {wait}s ...")
                time.sleep(wait)
                continue
            resp.raise_for_status()
            return resp.text
        except requests.exceptions.RequestException as exc:
            logger.error(f"  Error: {exc}")
            if attempt < retries:
                time.sleep(delay * attempt)
    logger.error(f"FALLÓ tras {retries} intentos: {url}")
    return None


def download_file(url, dest_path, retries=3):
    """Descarga un archivo binario (imagen) con retry."""
    if os.path.exists(dest_path) and os.path.getsize(dest_path) > 0:
        logger.debug(f"  Ya existe: {dest_path}")
        return True
    for attempt in range(1, retries + 1):
        try:
            resp = _session.get(url, timeout=15, stream=True)
            if resp.status_code == 429:
                wait = int(resp.headers.get('Retry-After', 10))
                logger.warning(f"  429 en imagen, esperando {wait}s ...")
                time.sleep(wait)
                continue
            resp.raise_for_status()
            os.makedirs(os.path.dirname(dest_path), exist_ok=True)
            with open(dest_path, 'wb') as f:
                for chunk in resp.iter_content(8192):
                    f.write(chunk)
            logger.debug(f"  Descargada: {url} -> {dest_path}")
            return True
        except requests.exceptions.RequestException as exc:
            logger.error(f"  Error descargando imagen ({attempt}/{retries}): {exc}")
            if attempt < retries:
                time.sleep(1.0 * attempt)
    return False


# ═══════════════════════════════════════════════════════════
#  IMÁGENES (multihilo)
# ═══════════════════════════════════════════════════════════

def _resolve_image_url(img_tag, page_url):
    """Resuelve la URL real de una etiqueta <img>, incluyendo lazy-load."""
    for attr in ('src', 'data-src', 'data-original', 'data-lazy-src'):
        val = img_tag.get(attr)
        if val and not val.startswith('data:'):
            return urljoin(page_url, val)
    srcset = img_tag.get('srcset')
    if srcset:
        first = srcset.split(',')[0].strip().split(' ')[0]
        if first and not first.startswith('data:'):
            return urljoin(page_url, first)
    return None


def _is_content_image(url):
    """Determina si una imagen es contenido relevante (no tracking/favicon)."""
    parsed = urlparse(url)
    path = parsed.path.lower()
    if path.endswith('.ico'):
        return False
    skip_parts = ('favicon', 'tracking', 'pixel')
    if any(p in path for p in skip_parts):
        return False
    return True


def _download_one_image(args_tuple):
    """Descarga una imagen (para usar con ThreadPoolExecutor). Retorna (url, local_name, ok)."""
    img_url, local_path, local_name = args_tuple
    ok = download_file(img_url, local_path)
    return (img_url, local_name, ok)


def process_images(soup, page_url, images_dir, threads=4):
    """Descarga imágenes en paralelo y reescribe src a rutas locales."""
    download_tasks = []
    img_tags = []

    for img in soup.find_all('img'):
        img_url = _resolve_image_url(img, page_url)
        if not img_url:
            img.decompose()
            continue
        if not _is_content_image(img_url):
            img.decompose()
            continue

        parsed = urlparse(img_url)
        ext = os.path.splitext(parsed.path)[1] or '.png'
        name_hash = hashlib.md5(img_url.encode()).hexdigest()[:10]
        basename = os.path.basename(parsed.path)
        if not basename or basename == '/':
            basename = f"img{ext}"
        base_no_ext = os.path.splitext(basename)[0]
        local_name = f"{name_hash}_{base_no_ext}{ext}"
        local_path = os.path.join(images_dir, local_name)

        download_tasks.append((img_url, local_path, local_name))
        img_tags.append(img)

    if not download_tasks:
        return

    results = {}
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(_download_one_image, t): t for t in download_tasks}
        for future in as_completed(futures):
            url, name, ok = future.result()
            results[url] = (name, ok)

    for img, (img_url, local_path, local_name) in zip(img_tags, download_tasks):
        name, ok = results.get(img_url, ("", False))
        if ok:
            img['src'] = f"{IMAGES_DIR_NAME}/{name}"
        else:
            img.decompose()


# ═══════════════════════════════════════════════════════════
#  LIMPIEZA DE HTML
# ═══════════════════════════════════════════════════════════

def _is_spam_element(el):
    """Verifica si un elemento es contenido de registro/publicidad."""
    txt = el.get_text(strip=True)
    return any(p in txt for p in _SPAM_PATTERNS)


def _remove_promo_blocks(main_div):
    """Elimina bloques de registro, publicidad y progreso de Burp Suite."""
    for tag in main_div.find_all(['header', 'footer', 'nav', 'aside']):
        tag.decompose()

    for tag in main_div.find_all('div', class_='sidebar-content'):
        tag.decompose()

    for tag in main_div.find_all('div', class_='sidebar-trial-advert'):
        tag.decompose()

    for tag in main_div.find_all(['script', 'style', 'noscript']):
        tag.decompose()

    for h2 in main_div.find_all('h2', string=lambda t: t and "Register for free" in t):
        current = h2
        while current:
            nxt = current.next_sibling
            current.decompose()
            current = nxt
            if nxt and nxt.name in ('h2', 'h3', 'div'):
                classes = nxt.get('class', []) if hasattr(nxt, 'get') else []
                if nxt.name in ('h2', 'h3') or 'container-section' in classes:
                    break

    for h3 in main_div.find_all('h3', string=lambda t: t and "Read more" in t):
        current = h3
        while current:
            nxt = current.next_sibling
            current.decompose()
            current = nxt
            if nxt and nxt.name in ('h2', 'h3', 'div'):
                classes = nxt.get('class', []) if hasattr(nxt, 'get') else []
                if nxt.name in ('h2', 'h3') or 'container-section' in classes:
                    break

    for ul in main_div.find_all('ul'):
        li_texts = [li.get_text(strip=True) for li in ul.find_all('li')]
        if all(any(m in t for t in li_texts) for m in _PROGRESS_UL_MARKERS):
            _remove_element_and_register(ul)

    for el in list(main_div.children):
        if hasattr(el, 'get_text') and _is_spam_element(el):
            _remove_spam_cluster(el)


def _remove_element_and_register(ul):
    """Elimina un UL de progreso y el bloque REGISTER que le sigue."""
    nxt = ul.next_sibling
    ul.decompose()
    el = nxt
    while el:
        nxt = el.next_sibling
        if _is_spam_element(el) or (el.name == 'h4' and 'Burp Suite' in el.get_text(strip=True)):
            el.decompose()
            el = nxt
        else:
            break


def _remove_spam_cluster(start_el):
    """Elimina un elemento spam y todos sus hermanos contiguos que también lo sean."""
    to_remove = []
    current = start_el
    while current and hasattr(current, 'get_text'):
        if not current.parent:
            break
        if _is_spam_element(current):
            to_remove.append(current)
            current = current.next_sibling
        else:
            break
    for el in to_remove:
        if el.parent:
            el.decompose()


def extract_and_clean(html, page_url, images_dir, threads=4):
    """Extrae contenido principal, limpia spam, descarga imágenes, retorna HTML limpio."""
    soup = BeautifulSoup(html, 'html.parser')

    main = (soup.find('main')
            or soup.find('div', class_='container-main')
            or soup.find('div', class_='section', attrs={'class': 'theme-white'})
            or soup.find('div', class_='text-block')
            or soup.find('body'))
    if not main:
        return ""

    _remove_promo_blocks(main)
    process_images(main, page_url, images_dir, threads=threads)

    return str(main)


# ═══════════════════════════════════════════════════════════
#  GUARDADO HTML CON FUENTE
# ═══════════════════════════════════════════════════════════

def save_html(clean_html, page_url, html_path):
    """Guarda HTML limpio con comentario de fuente."""
    os.makedirs(os.path.dirname(html_path), exist_ok=True)
    header = (
        f'<!-- Fuente: {page_url} -->\n'
        f'<!-- Descargado: {date.today().isoformat()} -->\n\n'
    )
    with open(html_path, 'w', encoding='utf-8') as f:
        f.write(header + clean_html)
    logger.info(f"  HTML: {html_path}")


_markitdown = MarkItDown()


def convert_to_markdown(html_path, output_dir):
    """Convierte un HTML a MD en content_md/ manteniendo la misma estructura relativa."""
    if not os.path.exists(html_path):
        return None
    rel = os.path.relpath(html_path, output_dir)
    if rel.startswith(HTML_DIR_NAME + os.sep):
        rel = rel[len(HTML_DIR_NAME) + 1:]
    md_path = os.path.join(output_dir, MD_DIR_NAME, os.path.splitext(rel)[0] + '.md')
    os.makedirs(os.path.dirname(md_path), exist_ok=True)
    try:
        result = _markitdown.convert(html_path)
        with open(md_path, 'w', encoding='utf-8') as f:
            f.write(result.text_content)
        logger.info(f"  MD:   {md_path}")
        return md_path
    except Exception as e:
        logger.warning(f"  MD fail: {html_path} -> {e}")
        return None


# ═══════════════════════════════════════════════════════════
#  NAVEGACIÓN (extracción de links)
# ═══════════════════════════════════════════════════════════

_TOPIC_EXCLUDES = (
    '/web-security/all-topics',
    '/web-security/all-labs',
    '/web-security/mystery-lab-challenge',
    '/web-security/dashboard',
    '/web-security/learning-paths',
    '/web-security/hall-of-fame',
    '/web-security/getting-started',
    '/web-security/certification',
)


def _is_topic_path(path):
    """Verifica que la path sea un tema valido de /web-security/."""
    if not path.startswith('/web-security/') or path.count('/') != 2:
        return False
    if path.endswith('/'):
        return False
    return not any(path.startswith(ex) for ex in _TOPIC_EXCLUDES)


def extract_topic_links(soup):
    """Extrae URLs de temas principales desde /web-security/all-topics."""
    links = set()

    for div in soup.find_all('div', class_='container-cards-white-medium-space-between'):
        for a in div.find_all('a', href=True):
            href = a['href']
            p = urlparse(href)
            if p.scheme in ('http', 'https'):
                path = p.path
            elif href.startswith('/'):
                path = href
            else:
                continue
            if _is_topic_path(path):
                links.add(urljoin(BASE_URL, path))

    if not links:
        for a in soup.find_all('a', href=True):
            href = a['href']
            p = urlparse(href)
            path = p.path if p.scheme in ('http', 'https') else href
            if path.startswith('/') and _is_topic_path(path):
                links.add(urljoin(BASE_URL, path))

    return sorted(links)


def extract_lesson_links(soup, topic_url):
    """Extrae URLs de sub-paginas desde el sidebar nav (aside.nav-lhs) de un tema."""
    links = set()
    topic_path = urlparse(topic_url).path.rstrip('/')

    nav = soup.find('aside', class_='nav-lhs')
    if not nav:
        nav = soup.find('nav', class_='nav-lhs-scrollable')
    if not nav:
        return sorted(links)

    for a in nav.find_all('a', href=True):
        href = a['href']
        p = urlparse(href)
        path = p.path if p.scheme in ('http', 'https') else href
        if not path.startswith('/'):
            continue

        if '#' in path:
            path = path.split('#')[0]

        full_path = urljoin(BASE_URL, path)

        if (path.startswith(topic_path + '/')
                and path != topic_path
                and '#' not in href
                and 'javascript:' not in href
                and 'all-topics' not in path
                and 'all-labs' not in path):
            links.add(full_path)

    return sorted(links)


def url_to_filepath(url, base_dir, indices=None):
    """Convierte URL a ruta local. indices: lista de enteros para prefijar cada segmento (001_slug)."""
    p = urlparse(url)
    path = p.path
    for prefix in ('/web-security/academy/', '/web-security/'):
        if path.startswith(prefix):
            path = path[len(prefix):]
            break
    parts = [_slugify(x) for x in path.split('/') if x]
    if not parts:
        return os.path.join(base_dir, HTML_DIR_NAME, 'index.html')
    if '.' in parts[-1]:
        parts[-1] = os.path.splitext(parts[-1])[0]
    if indices:
        for i, idx in enumerate(indices):
            if i < len(parts):
                parts[i] = f"{idx:03d}_{parts[i]}"
    return os.path.join(base_dir, HTML_DIR_NAME, *parts) + '.html'


# ═══════════════════════════════════════════════════════════
#  ÍNDICE MAESTRO
# ═══════════════════════════════════════════════════════════

def generate_index(topics_map, output_dir):
    """Genera un INDEX.html maestro con todos los temas y lecciones."""
    lines = [
        '<!DOCTYPE html>',
        '<html lang="en"><head><meta charset="utf-8">',
        '<title>PortSwigger Academy - Index</title>',
        '<style>body{font-family:sans-serif;max-width:900px;margin:auto;padding:20px}'
        'a{text-decoration:none;color:#0066cc}a:hover{text-decoration:underline}'
        'h2{border-bottom:1px solid #ccc;padding-bottom:4px}'
        '.src{color:#888;font-size:0.85em}</style>',
        '</head><body>',
        f'<h1>PortSwigger Web Security Academy</h1>',
        f'<p class="src">Generado por md_portswigger v{__version__} | {date.today().isoformat()}</p>',
        '<hr>',
    ]

    for t_idx, (topic_name, lessons) in enumerate(sorted(topics_map.items()), 1):
        topic_html = url_to_filepath(
            list(lessons.keys())[0] if lessons else f"/web-security/{topic_name}",
            output_dir, indices=[t_idx],
        )
        topic_html_norm = topic_html.replace('\\', '/')
        topic_md_norm = topic_html_norm.replace(f'/{HTML_DIR_NAME}/', f'/{MD_DIR_NAME}/').replace('.html', '.md')
        topic_md = topic_md_norm.replace('/', os.sep)
        if os.path.exists(topic_html):
            rel_html = os.path.relpath(topic_html, output_dir)
            rel_md = os.path.relpath(topic_md, output_dir)
            md_link = f' | <a href="{rel_md}">[MD]</a>' if os.path.exists(topic_md) else ''
            lines.append(f'<h2><a href="{rel_html}">[{t_idx:03d}] {topic_name}</a>{md_link}</h2>')
        else:
            lines.append(f'<h2>[{t_idx:03d}] {topic_name}</h2>')

        if lessons:
            lines.append('<ul>')
            for l_idx, (lesson_url, lesson_title) in enumerate(sorted(lessons.items()), 1):
                lesson_path = url_to_filepath(lesson_url, output_dir, indices=[t_idx, l_idx])
                lesson_path_norm = lesson_path.replace('\\', '/')
                lesson_md_norm = lesson_path_norm.replace(f'/{HTML_DIR_NAME}/', f'/{MD_DIR_NAME}/').replace('.html', '.md')
                lesson_md = lesson_md_norm.replace('/', os.sep)
                rel_html = os.path.relpath(lesson_path, output_dir)
                rel_md = os.path.relpath(lesson_md, output_dir)
                md_link = f' | <a href="{rel_md}">[MD]</a>' if os.path.exists(lesson_md) else ''
                lines.append(f'  <li><a href="{rel_html}">[{l_idx:03d}] {lesson_title}</a>{md_link}</li>')
            lines.append('</ul>')

    lines.extend(['<hr>', f'<p class="src">Total temas: {len(topics_map)}</p>', '</body></html>'])

    idx_path = os.path.join(output_dir, "INDEX.html")
    with open(idx_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))
    logger.info(f"Indice generado: {idx_path}")


def generate_index_json(topics_map, output_dir):
    """Genera INDEX.json estructurado para busqueda y descarga puntual."""
    index = {
        "version": __version__,
        "generated": date.today().isoformat(),
        "source": BASE_URL,
        "total_topics": len(topics_map),
        "total_lessons": sum(len(v) for v in topics_map.values()),
        "topics": {}
    }

    for t_idx, (topic_name, lessons) in enumerate(sorted(topics_map.items()), 1):
        topic_html = url_to_filepath(
            list(lessons.keys())[0] if lessons else f"/web-security/{topic_name}",
            output_dir, indices=[t_idx],
        )
        topic_html_norm = topic_html.replace('\\', '/')
        topic_md_norm = topic_html_norm.replace(f'/{HTML_DIR_NAME}/', f'/{MD_DIR_NAME}/').replace('.html', '.md')
        topic_md = topic_md_norm.replace('/', os.sep)
        topic_entry = {
            "url": f"{BASE_URL}/web-security/{topic_name}",
            "html_file": os.path.relpath(topic_html, output_dir) if os.path.exists(topic_html) else None,
            "md_file": os.path.relpath(topic_md, output_dir) if os.path.exists(topic_md) else None,
            "lesson_count": len(lessons),
            "lessons": {}
        }

        for l_idx, (lesson_url, lesson_title) in enumerate(sorted(lessons.items()), 1):
            lesson_path = url_to_filepath(lesson_url, output_dir, indices=[t_idx, l_idx])
            lesson_path_norm = lesson_path.replace('\\', '/')
            lesson_md_norm = lesson_path_norm.replace(f'/{HTML_DIR_NAME}/', f'/{MD_DIR_NAME}/').replace('.html', '.md')
            lesson_md = lesson_md_norm.replace('/', os.sep)
            topic_entry["lessons"][lesson_title] = {
                "url": lesson_url,
                "html_file": os.path.relpath(lesson_path, output_dir),
                "md_file": os.path.relpath(lesson_md, output_dir),
            }

        index["topics"][topic_name] = topic_entry

    idx_path = os.path.join(output_dir, "INDEX.json")
    with open(idx_path, 'w', encoding='utf-8') as f:
        json.dump(index, f, indent=2, ensure_ascii=False)
    logger.info(f"Indice JSON generado: {idx_path}")


# ═══════════════════════════════════════════════════════════
#  RESUME (continuar descarga interrumpida)
# ═══════════════════════════════════════════════════════════

def load_progress(output_dir):
    """Carga el progreso de descarga previo."""
    path = os.path.join(output_dir, '.download_progress.json')
    if os.path.exists(path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return set(json.load(f))
        except Exception:
            pass
    return set()


def save_progress(output_dir, urls):
    """Guarda el progreso de descarga."""
    path = os.path.join(output_dir, '.download_progress.json')
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(sorted(urls), f, indent=2)


# ═══════════════════════════════════════════════════════════
#  DESCARGA PARALELA DE LECCIONES
# ═══════════════════════════════════════════════════════════

def _fetch_lesson(args_tuple):
    """Descarga una lección (para ThreadPoolExecutor). Retorna (url, html)."""
    url, retries, delay = args_tuple
    time.sleep(delay)
    html = fetch(url, retries=retries)
    return (url, html)


def _process_one_lesson(args_tuple):
    """Procesa una lección completa: fetch + clean + save + md. Retorna (url, lesson_name, ok)."""
    l_url, topic_name, output_dir, images_dir, retries, delay, threads, do_md, topic_idx, lesson_idx = args_tuple
    lesson_name = urlparse(l_url).path.strip('/').split('/')[-1]

    html = fetch(l_url, retries=retries)
    if not html:
        return (l_url, lesson_name, False)

    l_html_path = url_to_filepath(l_url, output_dir, indices=[topic_idx, lesson_idx])
    l_images = os.path.join(images_dir, topic_name, lesson_name)
    os.makedirs(l_images, exist_ok=True)

    clean = extract_and_clean(html, l_url, l_images, threads=threads)
    save_html(clean, l_url, l_html_path)
    if do_md:
        convert_to_markdown(l_html_path, output_dir)
    return (l_url, lesson_name, True)


# ═══════════════════════════════════════════════════════════
#  TRADUCCIÓN (opcional, requiere --translate)
# ═══════════════════════════════════════════════════════════

CHUNK_SIZE = 4500
MAX_RETRIES = 3

_TECH_TERMS = {
    'web', 'xss', 'xxe', 'csrf', 'ssrf', 'jwt', 'oauth', 'api', 'cors',
    'sql', 'dom', 'xml', 'http', 'https', 'dns', 'json', 'html', 'css',
    'idor', 'ssti', 'nosql', 'rce', 'lfi', 'rfi', 'smtp',
    'jwk', 'jws', 'ocsp', 'saml', 'ldap', 'tls', 'ssl',
}

_TRANSLATABLE_TAGS = ('h1', 'h2', 'h3', 'h4', 'strong', 'b', 'button', 'label')


class RateLimiter:
    def __init__(self, max_per_sec=3):
        self.interval = 1.0 / max_per_sec
        self._lock = threading.Lock()
        self._last = 0

    def wait(self):
        with self._lock:
            now = time.time()
            wait = self.interval - (now - self._last)
            if wait > 0:
                time.sleep(wait)
            self._last = time.time()


_limiter = RateLimiter(max_per_sec=3)


def _safe_translate(translator, text, retries=MAX_RETRIES):
    """Traduce con rate limiter y backoff exponencial."""
    for attempt in range(1, retries + 1):
        try:
            _limiter.wait()
            result = translator.translate(text)
            return result
        except Exception as e:
            wait = 1.0 * (2 ** attempt)
            logger.warning(f"  Reintento {attempt}/{retries}, esperando {wait:.1f}s: {e}")
            time.sleep(wait)
    logger.error(f"  FALLO tras {retries} reintentos")
    return None


def split_into_chunks(text, max_size=CHUNK_SIZE):
    """Divide texto en chunks respetando parrafos."""
    if len(text) <= max_size:
        return [text]
    paragraphs = text.split('\n\n')
    chunks = []
    current = ''
    for para in paragraphs:
        if len(current) + len(para) + 2 > max_size:
            if current:
                chunks.append(current)
            if len(para) > max_size:
                chunks.append(para[:max_size])
                current = para[max_size:]
            else:
                current = para
        else:
            current = current + '\n\n' + para if current else para
    if current:
        chunks.append(current)
    return chunks


def protect_content(text):
    """Protege bloques de codigo, inline code, imagenes y links."""
    protected = {}
    counter = [0]

    def repl(match):
        key = f'§PROT{counter[0]}§'
        protected[key] = match.group(0)
        counter[0] += 1
        return key

    text = re.sub(r'```[\s\S]*?```', repl, text)
    text = re.sub(r'`[^`\n]+`', repl, text)
    text = re.sub(r'!\[[^\]]*\]\([^)]+\)', repl, text)
    text = re.sub(r'\[[^\]]+\]\([^)]+\)', repl, text)
    return text, protected


def restore_content(text, protected):
    """Restaura contenido protegido."""
    for key, value in protected.items():
        text = text.replace(key, value)
    return text


def translate_md_file(md_path, output_path, translator):
    """Traduce un archivo MD, preservando bloques de codigo y formato."""
    with open(md_path, 'r', encoding='utf-8') as f:
        content = f.read()

    text, protected = protect_content(content)
    chunks = split_into_chunks(text)
    translated = []

    for i, chunk in enumerate(chunks):
        if chunk.strip():
            result = _safe_translate(translator, chunk)
            if result:
                translated.append(result)
            else:
                translated.append(chunk)
        else:
            translated.append(chunk)

    result = '\n\n'.join(translated)
    result = restore_content(result, protected)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(result)
    logger.info(f"  MD:   {output_path}")


def _try_add_phrase(phrase_dict, en_p, es_p):
    """Anade par EN->ES solo si pasa filtros de calidad."""
    if not en_p or not es_p or en_p == es_p:
        return
    if en_p.startswith(('#', '*', '!', '[', '|', '>')):
        return
    if len(en_p) < 25 or len(en_p) > 400:
        return
    if len(es_p) < 25 or len(es_p) > 400:
        return

    en_word_count = len(en_p.split())
    if en_word_count < 5:
        return

    en_lower = en_p.lower()
    en_words_lower = set(re.findall(r'\b[a-z]{2,}\b', en_lower))
    tech_in_phrase = en_words_lower & _TECH_TERMS
    if tech_in_phrase and en_word_count <= 8:
        return

    if re.match(r'^[\W\d\s]+$', en_p):
        return

    if en_p.endswith(':') or en_p.endswith('.') or en_p.endswith('!') or en_p.endswith('?'):
        phrase_dict[en_p] = es_p


def _build_mirror_dict(md_source, esp_md_source):
    """Construye diccionario EN->ES alineando pares de MD por parrafo/oracion."""
    phrase_dict = {}

    for root, dirs, files in os.walk(md_source):
        for f in files:
            if not f.endswith('.md'):
                continue
            en_path = os.path.join(root, f)
            rel = os.path.relpath(en_path, md_source)
            es_path = os.path.join(esp_md_source, rel)
            if not os.path.exists(es_path):
                continue

            with open(en_path, 'r', encoding='utf-8') as ef:
                en_text = ef.read()
            with open(es_path, 'r', encoding='utf-8') as sf:
                es_text = sf.read()

            en_paras = [p.strip() for p in en_text.split('\n\n') if p.strip()]
            es_paras = [p.strip() for p in es_text.split('\n\n') if p.strip()]

            for en_p, es_p in zip(en_paras, es_paras):
                if en_p == es_p:
                    continue
                _try_add_phrase(phrase_dict, en_p, es_p)

                en_sentences = re.split(r'(?<=[.!?])\s+', en_p)
                es_sentences = re.split(r'(?<=[.!?])\s+', es_p)
                if len(en_sentences) == len(es_sentences):
                    for en_s, es_s in zip(en_sentences, es_sentences):
                        _try_add_phrase(phrase_dict, en_s.strip(), es_s.strip())

    logger.info(f"Mirror dict: {len(phrase_dict)} frases (filtros estrictos)")
    return {}, phrase_dict


def _apply_mirror_to_html(html_path, output_path, word_dict, phrase_dict):
    """Clona HTML EN y reemplaza texto usando el diccionario mirror. Sin API."""
    with open(html_path, 'r', encoding='utf-8') as f:
        content = f.read()

    soup = BeautifulSoup(content, 'html.parser')

    for node in soup.find_all(string=True):
        text = str(node)
        if not text.strip() or len(text.strip()) < 3:
            continue
        if text.strip().startswith('<!--'):
            continue

        new_text = text
        for en_phrase, es_phrase in sorted(phrase_dict.items(), key=lambda x: -len(x[0])):
            if en_phrase in new_text:
                new_text = new_text.replace(en_phrase, es_phrase)

        if new_text != text:
            node.replace_with(new_text)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(str(soup))


def _load_html_progress(esp_html_dir):
    path = os.path.join(os.path.dirname(esp_html_dir), '.html_progress.json')
    if os.path.exists(path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return set(json.load(f))
        except Exception:
            pass
    return set()


def _save_html_progress(esp_html_dir, rel):
    path = os.path.join(os.path.dirname(esp_html_dir), '.html_progress.json')
    done = _load_html_progress(esp_html_dir)
    done.add(rel)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(sorted(done), f, indent=2)


def translate_html_mirror(html_source, esp_html_dir, word_dict, phrase_dict):
    """Traduce todos los HTML usando mirror dict (sin API calls)."""
    html_files = []
    for root, dirs, files in os.walk(html_source):
        for f in files:
            if f.endswith('.html'):
                html_files.append(os.path.join(root, f))

    pending = [p for p in sorted(html_files)
               if os.path.relpath(p, html_source) not in _load_html_progress(esp_html_dir)]

    for i, html_path in enumerate(pending, 1):
        rel = os.path.relpath(html_path, html_source)
        out = os.path.join(esp_html_dir, rel)
        logger.info(f"[{i}/{len(pending)}] HTML mirror: {rel}")
        _apply_mirror_to_html(html_path, out, word_dict, phrase_dict)
        _save_html_progress(esp_html_dir, rel)

    return len(pending)


def _collect_unique_texts(esp_html_dir, tags):
    """Recopila textos unicos de headers/labels en todos los HTML ESP."""
    texts = set()
    for root, dirs, files in os.walk(esp_html_dir):
        for f in files:
            if not f.endswith('.html'):
                continue
            with open(os.path.join(root, f), 'r', encoding='utf-8') as fh:
                soup = BeautifulSoup(fh.read(), 'html.parser')
            for tag_name in tags:
                for el in soup.find_all(tag_name):
                    t = el.get_text(strip=True)
                    if t and len(t) > 2 and not re.match(r'^[\d\s\W]+$', t):
                        words = t.split()
                        if len(words) <= 2 and t.lower() in _TECH_TERMS:
                            continue
                        texts.add(t)
            for sp in soup.find_all('span', attrs={'itemprop': 'name'}):
                t = sp.get_text(strip=True)
                if t and len(t) > 2:
                    texts.add(t)
    return texts


def _apply_header_translations(esp_html_dir, cache, tags):
    """Reemplaza headers/labels en HTMLs usando el cache."""
    count = 0
    for root, dirs, files in os.walk(esp_html_dir):
        for f in files:
            if not f.endswith('.html'):
                continue
            path = os.path.join(root, f)
            with open(path, 'r', encoding='utf-8') as fh:
                content = fh.read()
            soup = BeautifulSoup(content, 'html.parser')
            changed = False
            for tag_name in tags:
                for el in soup.find_all(tag_name):
                    t = el.get_text(strip=True)
                    if t in cache:
                        el.string = cache[t]
                        changed = True
            for sp in soup.find_all('span', attrs={'itemprop': 'name'}):
                t = sp.get_text(strip=True)
                if t in cache:
                    sp.string = cache[t]
                    changed = True
            if changed:
                with open(path, 'w', encoding='utf-8') as fh:
                    fh.write(str(soup))
                count += 1
    return count


def _load_header_progress(esp_html_dir):
    path = os.path.join(os.path.dirname(esp_html_dir), '.header_progress.json')
    if os.path.exists(path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            pass
    return {"translated_texts": [], "processed_files": []}


def _save_header_progress(esp_html_dir, data):
    path = os.path.join(os.path.dirname(esp_html_dir), '.header_progress.json')
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def post_process_html_headers(esp_html_dir, translator):
    """Traduce headers (h1-h4), labels (strong/b/button), breadcrumbs via Google API."""
    progress = _load_header_progress(esp_html_dir)
    done_texts = set(progress.get("translated_texts", []))

    tags = _TRANSLATABLE_TAGS
    all_texts = _collect_unique_texts(esp_html_dir, tags)
    pending_texts = [t for t in all_texts if t not in done_texts]

    if not pending_texts:
        logger.info("Headers: ya traducidos previamente.")
        return 0

    logger.info(f"Headers: {len(pending_texts)} textos unicos por traducir ({len(done_texts)} ya hechos)")

    cache = {}
    total = len(pending_texts)
    for i, t in enumerate(sorted(pending_texts), 1):
        es = _safe_translate(translator, t)
        if es:
            cache[t] = es
        if i % 25 == 0:
            logger.info(f"  Headers: {i}/{total} traducidos")
            done_texts.update(cache.keys())
            progress["translated_texts"] = sorted(done_texts)
            _save_header_progress(esp_html_dir, progress)

    done_texts.update(cache.keys())
    progress["translated_texts"] = sorted(done_texts)
    _save_header_progress(esp_html_dir, progress)
    logger.info(f"  Header cache: {len(cache)}/{total} textos traducidos")

    n = _apply_header_translations(esp_html_dir, cache, tags)
    logger.info(f"Headers: {n} archivos HTML actualizados")
    return n


def generate_esp_index(md_source, esp_dir):
    """Genera INDEX.html y INDEX.json en ESP/."""
    topics = {}
    for root, dirs, files in os.walk(md_source):
        for f in sorted(files):
            if not f.endswith('.md'):
                continue
            full = os.path.join(root, f)
            rel = os.path.relpath(full, md_source)
            parts = rel.replace('\\', '/').split('/')
            if len(parts) == 1:
                topic = os.path.splitext(f)[0]
                topics.setdefault(topic, {'overview': rel, 'lessons': []})
            else:
                topic = parts[0]
                topics.setdefault(topic, {'overview': None, 'lessons': []})
                topics[topic]['lessons'].append(rel)

    lines = [
        '<!DOCTYPE html>',
        '<html lang="es"><head><meta charset="utf-8">',
        '<title>PortSwigger Academy - Indice ESP</title>',
        '<style>body{font-family:sans-serif;max-width:900px;margin:auto;padding:20px}'
        'a{text-decoration:none;color:#0066cc}a:hover{text-decoration:underline}'
        'h2{border-bottom:1px solid #ccc;padding-bottom:4px}'
        '.src{color:#888;font-size:0.85em}</style>',
        '</head><body>',
        f'<h1>PortSwigger Web Security Academy (ESP)</h1>',
        f'<p class="src">Generado por md_portswigger v{__version__} | {date.today().isoformat()}</p>',
        '<hr>',
    ]

    index_json = {
        "version": __version__,
        "generated": date.today().isoformat(),
        "language": "es",
        "total_topics": len(topics),
        "topics": {}
    }

    for topic_name, data in sorted(topics.items()):
        lines.append(f'<h2>{topic_name}</h2>')
        topic_entry = {"lessons": {}}

        if data['overview']:
            esp_md = os.path.join(ESP_DIR_NAME, 'md', data['overview'])
            esp_html = os.path.join(ESP_DIR_NAME, 'html', data['overview'].replace('.md', '.html'))
            lines.append(f'<ul><li><a href="{esp_md}">MD</a> | <a href="{esp_html}">HTML</a></li>')
            topic_entry['md_file'] = esp_md
            topic_entry['html_file'] = esp_html

        if data['lessons']:
            lines.append('<ul>')
            for lesson_rel in sorted(data['lessons']):
                lesson_name = os.path.splitext(os.path.basename(lesson_rel))[0]
                esp_md = os.path.join(ESP_DIR_NAME, 'md', lesson_rel)
                esp_html = os.path.join(ESP_DIR_NAME, 'html', lesson_rel.replace('.md', '.html'))
                lines.append(f'  <li><a href="{esp_md}">{lesson_name}</a> | <a href="{esp_html}">HTML</a></li>')
                topic_entry['lessons'][lesson_name] = {
                    "md_file": esp_md,
                    "html_file": esp_html,
                }
            lines.append('</ul>')

        lines.append('</ul>' if data['overview'] else '')
        index_json['topics'][topic_name] = topic_entry

    lines.extend(['<hr>', '</body></html>'])

    idx_path = os.path.join(esp_dir, 'INDEX.html')
    with open(idx_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))

    json_path = os.path.join(esp_dir, 'INDEX.json')
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(index_json, f, indent=2, ensure_ascii=False)

    logger.info(f"Indice ESP: {idx_path}")


def _load_translate_progress(esp_dir):
    path = os.path.join(esp_dir, '.translate_progress.json')
    if os.path.exists(path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return set(json.load(f))
        except Exception:
            pass
    return set()


def _save_translate_progress(esp_dir, paths):
    path = os.path.join(esp_dir, '.translate_progress.json')
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(sorted(paths), f, indent=2)


def run_translation(output_dir, rate=3):
    """Ejecuta el pipeline completo de traduccion EN->ES."""
    try:
        from deep_translator import GoogleTranslator
    except ImportError:
        logger.error("deep_translator no instalado. Ejecuta: pip install deep_translator")
        return

    global _limiter
    _limiter = RateLimiter(max_per_sec=min(rate, 5))

    translator = GoogleTranslator(source='en', target='es')
    esp_dir = os.path.join(output_dir, ESP_DIR_NAME)
    md_source = os.path.join(output_dir, MD_DIR_NAME)
    html_source = os.path.join(output_dir, HTML_DIR_NAME)

    if not os.path.exists(md_source) and not os.path.exists(html_source):
        logger.error(f"No se encontro contenido en {output_dir}/")
        return

    done = _load_translate_progress(esp_dir)
    total = 0

    # ─── MD ──────────────────────────────────────────────
    if os.path.exists(md_source):
        md_files = []
        for root, dirs, files in os.walk(md_source):
            for f in files:
                if f.endswith('.md'):
                    md_files.append(os.path.join(root, f))

        pending = [p for p in sorted(md_files)
                   if os.path.relpath(p, md_source) not in done]
        logger.info(f"MD: {len(pending)} pendientes de {len(md_files)}")

        for i, md_path in enumerate(pending, 1):
            rel = os.path.relpath(md_path, md_source)
            out = os.path.join(esp_dir, 'md', os.path.splitext(rel)[0] + '.md')
            logger.info(f"[{i}/{len(pending)}] MD: {rel}")
            translate_md_file(md_path, out, translator)
            done.add(rel)
            _save_translate_progress(esp_dir, done)
            total += 1

    # ─── HTML (mirror: sin API) ──────────────────────────
    if os.path.exists(html_source):
        esp_md_source = os.path.join(esp_dir, 'md')
        esp_html_dir = os.path.join(esp_dir, 'html')

        if not os.path.exists(esp_md_source):
            logger.warning("No hay MD traducidos para construir mirror. Saltando HTML.")
        else:
            logger.info("Construyendo diccionario mirror desde pares MD EN<->ES ...")
            word_dict, phrase_dict = _build_mirror_dict(md_source, esp_md_source)
            n = translate_html_mirror(html_source, esp_html_dir, word_dict, phrase_dict)
            total += n

    # ─── POST-PROCESS: headers/labels via Google API ─────
    esp_html_dir = os.path.join(esp_dir, 'html')
    if os.path.exists(esp_html_dir):
        logger.info("Post-procesando headers/labels en HTML ESP ...")
        post_process_html_headers(esp_html_dir, translator)

    # ─── INDICE ESP ──────────────────────────────────────
    generate_esp_index(md_source, esp_dir)

    logger.info(f"TRADUCCION COMPLETA: {total} archivos")


# ═══════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════

def main():
    parser = __ap.ArgumentParser(
        description="PortSwigger Academy Scraper - descarga HTML + MD para offline"
    )
    parser.add_argument("-l", "--lang", choices=["es", "en"], default="es",
                        help="Idioma de salida (default: es)")
    parser.add_argument("-o", "--output", default="portswigger_academy_content",
                        help="Directorio de salida (default: portswigger_academy_content)")
    parser.add_argument("-d", "--delay", type=float, default=1.0,
                        help="Delay entre requests en segundos (default: 1.0)")
    parser.add_argument("-r", "--retries", type=int, default=3,
                        help="Intentos maximos por URL (default: 3)")
    parser.add_argument("-t", "--threads", type=int, default=4,
                        help="Hilos paralelos para imagenes/lecciones (default: 4)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Salida detallada")
    parser.add_argument("--md", action="store_true", default=True,
                        help="Convertir HTML a Markdown (default: True)")
    parser.add_argument("--no-md", dest="md", action="store_false",
                        help="No convertir a Markdown")
    parser.add_argument("--translate", action="store_true", default=False,
                        help="Traducir contenido a espanol (requiere deep_translator)")
    parser.add_argument("--rate", type=int, default=3,
                        help="Max requests/s a Google Translate para --translate (default: 3)")
    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    global __ap_l
    __ap_l = args.lang

    output_dir = args.output
    os.makedirs(output_dir, exist_ok=True)

    print(f"\n[!] AVISO LEGAL: Use solo con autorizacion. / LEGAL NOTICE: Authorized use only.\n")
    logger.info(f"v{__version__} | Output: {output_dir}/ | Threads: {args.threads} | Delay: {args.delay}s | MD: {args.md} | Translate: {args.translate}")

    downloaded = load_progress(output_dir)
    topics_map = {}
    total = 0

    try:
        # ─── 1) Índice principal ─────────────────────────────
        html = fetch(ACADEMY_INDEX_URL, retries=args.retries)
        if not html:
            logger.error("No se pudo obtener el indice principal.")
            sys.exit(1)

        soup = BeautifulSoup(html, 'html.parser')
        idx_path = os.path.join(output_dir, HTML_DIR_NAME, 'academy_index.html')
        images_dir = os.path.join(output_dir, IMAGES_DIR_NAME, 'academy_index')
        os.makedirs(images_dir, exist_ok=True)
        clean = extract_and_clean(html, ACADEMY_INDEX_URL, images_dir, threads=args.threads)
        save_html(clean, ACADEMY_INDEX_URL, idx_path)
        if args.md:
            convert_to_markdown(idx_path, output_dir)
        downloaded.add(ACADEMY_INDEX_URL)
        total += 1
        time.sleep(args.delay)

        # ─── 2) Temas ───────────────────────────────────────
        topic_urls = extract_topic_links(soup)
        logger.info(f"Temas encontrados: {len(topic_urls)}")

        for t_idx, t_url in enumerate(topic_urls, 1):
            if t_url in downloaded:
                continue

            topic_name = urlparse(t_url).path.strip('/').split('/')[-1]
            topics_map.setdefault(topic_name, {})
            logger.info(f"\n{'='*60}\nTEMA [{t_idx:03d}]: {topic_name}\n{'='*60}")

            html = fetch(t_url, retries=args.retries)
            downloaded.add(t_url)
            total += 1
            time.sleep(args.delay)

            if not html:
                continue

            t_html_path = url_to_filepath(t_url, output_dir, indices=[t_idx])
            t_images = os.path.join(output_dir, IMAGES_DIR_NAME, topic_name)
            os.makedirs(t_images, exist_ok=True)

            soup_t = BeautifulSoup(html, 'html.parser')
            clean = extract_and_clean(html, t_url, t_images, threads=args.threads)
            save_html(clean, t_url, t_html_path)
            if args.md:
                convert_to_markdown(t_html_path, output_dir)

            # ─── 3) Lecciones (paralelas) ───────────────────
            lesson_urls = extract_lesson_links(soup_t, t_url)
            logger.info(f"  Lecciones: {len(lesson_urls)} (paralelas, {args.threads} hilos)")

            pending = []
            for l_idx, l_url in enumerate(lesson_urls, 1):
                if l_url not in downloaded:
                    pending.append((
                        l_url, topic_name, output_dir, os.path.join(output_dir, IMAGES_DIR_NAME),
                        args.retries, args.delay, args.threads, args.md, t_idx, l_idx,
                    ))

            if pending:
                with ThreadPoolExecutor(max_workers=args.threads) as pool:
                    futures = {pool.submit(_process_one_lesson, a): a for a in pending}
                    for future in as_completed(futures):
                        l_url, lesson_name, ok = future.result()
                        with _lock:
                            downloaded.add(l_url)
                            total += 1
                            if ok:
                                topics_map[topic_name][l_url] = lesson_name
                        if ok:
                            logger.info(f"  OK: {lesson_name}")
                        else:
                            logger.warning(f"  FAIL: {lesson_name}")

                save_progress(output_dir, downloaded)

        # ─── 4) Índice maestro ──────────────────────────────
        generate_index(topics_map, output_dir)
        generate_index_json(topics_map, output_dir)
        save_progress(output_dir, downloaded)

        print(f"\n{'='*60}")
        logger.info(f"DESCARGA COMPLETA: {total} URLs")
        logger.info(f"  HTML: {os.path.join(output_dir, HTML_DIR_NAME)}/")
        if args.md:
            logger.info(f"  MD:   {os.path.join(output_dir, MD_DIR_NAME)}/")
        logger.info(f"  IMG:  {os.path.join(output_dir, IMAGES_DIR_NAME)}/")
        logger.info(f"  Indice: {os.path.join(output_dir, 'INDEX.html')}")
        logger.info(f"  JSON:  {os.path.join(output_dir, 'INDEX.json')}")
        print(f"{'='*60}\n")

        # ─── 5) Traduccion (opcional) ───────────────────────
        if args.translate:
            logger.info("Iniciando traduccion EN->ES ...")
            run_translation(output_dir, rate=args.rate)

    except KeyboardInterrupt:
        print("\n\n[!] INTERRUPCION (Ctrl+C). Progreso guardado.")
        save_progress(output_dir, downloaded)
        generate_index(topics_map, output_dir)
        generate_index_json(topics_map, output_dir)
        logger.info(f"URLs descargadas antes de interrupcion: {len(downloaded)}")

    except Exception as exc:
        logger.error(f"ERROR INESPERADO: {exc}", exc_info=True)
        save_progress(output_dir, downloaded)
        generate_index(topics_map, output_dir)
        generate_index_json(topics_map, output_dir)


if __name__ == "__main__":
    main()
