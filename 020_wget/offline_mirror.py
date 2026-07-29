#!/usr/bin/env python3
"""
offline_mirror.py — Descarga un sitio web completo listo para navegar sin internet.

Uso:     python offline_mirror.py https://ejemplo.com C:/destino
         python offline_mirror.py --wget https://ejemplo.com C:/destino    (usa wget.exe)

Sin dependencias externas. Post-procesa todo: remueve analytics, descarga CDN
a local, convierte rutas absolutas a relativas, limpia HTMLs rotos.
"""

import os, re, sys, ssl, hashlib
import html.parser
from urllib.parse import urljoin, urlparse, urldefrag
from urllib.request import Request, urlopen
from collections import deque
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

VERSION = '1.0'
USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
SSL_CONTEXT = ssl.create_default_context()
SSL_CONTEXT.check_hostname = False
SSL_CONTEXT.verify_mode = ssl.CERT_NONE

CDNS = [
    'cdnjs.cloudflare.com', 'unpkg.com', 'cdn.jsdelivr.net',
    'fonts.googleapis.com', 'fonts.gstatic.com', 'code.jquery.com',
    'stackpath.bootstrapcdn.com', 'maxcdn.bootstrapcdn.com',
    'cdn.jsdelivr.net', 'cdn.datatables.net', 'cdn.ckeditor.com',
    'ajax.googleapis.com', 'ajax.aspnetcdn.com', 'cdn.socket.io',
]

TRACKERS = [
    (r'(?s)<!-- Google tag \(gtag\.js\) -->.*?</script>\s*', ''),
    (r'(?s)<script[^>]*googletagmanager\.com[^>]*></script>\s*', ''),
    (r'(?s)<script[^>]*gtag\(.*?</script>\s*', ''),
    (r'(?s)<script[^>]*facebook\.net/[^"]*fbevents[^>]*></script>\s*', ''),
    (r'(?s)<script[^>]*fbq\(.*?</script>\s*', ''),
    (r'(?s)<script[^>]*hotjar[^>]*></script>\s*', ''),
    (r'(?s)<script[^>]*clarity[^>]*></script>\s*', ''),
    (r'(?s)<noscript[^>]*facebook\.net[^>]*>.*?</noscript>\s*', ''),
    (r'(?s)<!-- End .*? -->\s*', ''),
]

IMG_EXTS = ('.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp', '.bmp')
FONT_EXTS = ('.woff', '.woff2', '.ttf', '.eot')
STATIC_EXTS = IMG_EXTS + FONT_EXTS + ('.css', '.js', '.json', '.xml', '.map', '.txt', '.pdf', '.zip', '.webm', '.mp4')
HTML_EXTS = ('.html', '.htm', '.php', '.asp', '.aspx', '.jsp', '')  # '' for extensionless URLs


class LinkExtractor(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = set()

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        for attr, val in [('href', d.get('href')), ('src', d.get('src')),
                          ('srcset', d.get('srcset')), ('data-src', d.get('data-src')),
                          ('data-href', d.get('data-href')), ('poster', d.get('poster'))]:
            if val:
                if attr == 'srcset':
                    for part in val.split(','):
                        url_part = part.strip().split()[0]
                        if url_part:
                            self.links.add(url_part)
                else:
                    self.links.add(val)


class CSSUrlExtractor:
    @staticmethod
    def extract(css_text):
        return re.findall(r'url\(["\']?([^"\'\)]+)["\']?\)', css_text)


def normalizar_url(url):
    url, _ = urldefrag(url)
    url = url.rstrip('/')
    if url.startswith('//'):
        url = 'https:' + url
    return url


def es_mismo_dominio(url, dominio):
    return urlparse(url).netloc == dominio or not urlparse(url).netloc


def ext_de_url(url):
    p = urlparse(url)
    _, ext = os.path.splitext(p.path.split(';')[0].split('?')[0])
    return ext.lower() if ext else ''


def es_recurso_estatico(url):
    ext = ext_de_url(url)
    return ext in STATIC_EXTS


def nombre_archivo(url, base_dir=''):
    p = urlparse(url)
    path = p.path.split(';')[0]
    if not path or path.endswith('/'):
        path += 'index.html'
    name = path.lstrip('/').replace('/', os.sep).replace(':', '_')
    if not name:
        name = 'index.html'
    _, ext = os.path.splitext(name)
    if not ext:
        name += '.html'
    if p.query:
        qs = hashlib.md5(p.query.encode()).hexdigest()[:8]
        base, ext = os.path.splitext(name)
        name = f'{base}_{qs}{ext}'
    return name


def descargar(url, ruta, visto):
    if url in visto:
        return False
    visto.add(url)
    if os.path.exists(ruta) and os.path.getsize(ruta) > 0:
        return False

    os.makedirs(os.path.dirname(ruta), exist_ok=True)
    req = Request(url, headers={'User-Agent': USER_AGENT})
    try:
        with urlopen(req, timeout=20, context=SSL_CONTEXT) as r:
            data = r.read()
        with open(ruta, 'wb') as f:
            f.write(data)
        return True
    except Exception:
        return False


def descargar_cdn(cdn_url, ruta_local):
    if os.path.exists(ruta_local) and os.path.getsize(ruta_local) > 0:
        return True
    os.makedirs(os.path.dirname(ruta_local), exist_ok=True)
    req = Request(cdn_url, headers={'User-Agent': USER_AGENT})
    try:
        with urlopen(req, timeout=20, context=SSL_CONTEXT) as r:
            with open(ruta_local, 'wb') as f:
                f.write(r.read())
        return True
    except Exception:
        return False


def es_cdn(url):
    return any(c in urlparse(url).netloc for c in CDNS)


def es_tracker(url):
    t = url.lower()
    return any(x in t for x in ['googletagmanager', 'google-analytics', 'facebook.net',
                                 'fbq(', 'hotjar', 'clarity', 'doubleclick'])


def procesar_html(ruta, dir_base):
    with open(ruta, 'r', encoding='utf-8', errors='replace') as f:
        html = f.read()
    original = html
    dir_html = os.path.dirname(ruta)
    depth = ruta.replace(dir_base, '').lstrip(os.sep).count(os.sep)
    prefijo = '../' * depth if depth > 0 else ''

    # 1. Quitar trackers/analytics
    for pattern, replacement in TRACKERS:
        html = re.sub(pattern, replacement, html)

    # 2. Detectar y descargar CDN scripts
    for m in re.finditer(r'(?:src|href)="(https?://[^"]+)"', html):
        url = m.group(1)
        if es_cdn(url) and not es_tracker(url):
            nombre = os.path.basename(urlparse(url).path.split('?')[0])
            if not nombre:
                continue
            ruta_local = f'js/{nombre}'
            archivo_local = os.path.join(dir_html, ruta_local)
            if not os.path.exists(archivo_local):
                print(f'    ↓ CDN {nombre[:40]}')
                descargar_cdn(url, archivo_local)
                # CSS links from CDN may reference fonts/images
                if nombre.endswith('.css'):
                    with open(archivo_local, 'r', encoding='utf-8', errors='replace') as cf:
                        css_urls = CSSUrlExtractor.extract(cf.read())
                    for cu in css_urls:
                        cu_full = urljoin(url, cu)
                        if not es_cdn(cu_full):
                            continue
                        cu_nombre = os.path.basename(urlparse(cu_full).path.split('?')[0])
                        if cu_nombre:
                            cu_local = os.path.join(dir_html, 'js', cu_nombre)
                            if not os.path.exists(cu_local):
                                print(f'    ↓ CDN font/img {cu_nombre[:40]}')
                                descargar_cdn(cu_full, cu_local)
            html = html.replace(url, ruta_local)

    # 3. Fix stray closing tags
    html = re.sub(r'</style>(\s*)', r'\1', html)  # remove orphan </style>

    # 4. href/src absolutos → relativos
    for attr in ('href', 'src', 'data-src', 'data-href', 'poster'):
        for m in re.finditer(f'{attr}="(/?)([^"]*?)(#[^"]*)?"', html):
            val = m.group(0)
            slash = m.group(1)
            path = m.group(2)
            fragment = m.group(3) or ''

            if not path:
                continue
            if path.startswith('http') or path.startswith('//') or path.startswith('data:'):
                continue
            if path.startswith('mailto:') or path.startswith('tel:') or path.startswith('javascript:'):
                continue
            if slash == '/':
                rel = path
                if not os.path.splitext(rel)[1] and not rel.endswith('/'):
                    rel += '.html'
                nuevo = f'{attr}="{prefijo}{rel}{fragment}"'
                if nuevo != val:
                    html = html.replace(val, nuevo)

    # 5. CSS inline url() en atributos style
    for m in re.finditer(r'style="([^"]*)"', html):
        style = m.group(1)
        urls = re.findall(r'url\(["\']?([^"\'\)]+)["\']?\)', style)
        for u in urls:
            if u.startswith('data:') or u.startswith('http'):
                continue
            nuevo_style = style.replace(u, f'{prefijo}{u}')
            html = html.replace(f'style="{style}"', f'style="{nuevo_style}"')

    if html != original:
        with open(ruta, 'w', encoding='utf-8') as f:
            f.write(html)
        return True
    return False


def limpiar_nombres_wget(dir_base):
    for root, _, files in os.walk(dir_base):
        for f in files:
            name, ext = os.path.splitext(f)
            parts = name.split('.')
            if len(parts) > 1 and parts[-1].isdigit():
                base = '.'.join(parts[:-1])
                nuevo = f'{base}{ext}'
                ruta_vieja = os.path.join(root, f)
                ruta_nueva = os.path.join(root, nuevo)
                if os.path.exists(ruta_nueva):
                    os.remove(ruta_vieja)
                else:
                    os.rename(ruta_vieja, ruta_nueva)
                # Also rename .1.html references inside files
    # Fix internal references to renamed files
    for root, _, files in os.walk(dir_base):
        for f in files:
            if f.endswith('.html'):
                ruta = os.path.join(root, f)
                with open(ruta, 'r', encoding='utf-8', errors='replace') as fh:
                    html = fh.read()
                original = html
                html = re.sub(r'(\.\d+)\.(html|css|js|png|jpg)', r'\2', html)
                if html != original:
                    with open(ruta, 'w', encoding='utf-8') as fh:
                        fh.write(html)


def compartir_assets(dir_base):
    dirs = [d for d in os.listdir(dir_base) if os.path.isdir(os.path.join(dir_base, d))]
    src_dir = None
    for d in dirs:
        js_dir = os.path.join(dir_base, d, 'js')
        if os.path.exists(os.path.join(js_dir, 'app.js')):
            src_dir = os.path.join(dir_base, d)
            break
    if not src_dir:
        return

    src_js = os.path.join(src_dir, 'js')
    for d in dirs:
        dst_js = os.path.join(dir_base, d, 'js')
        if not os.path.exists(dst_js):
            continue
        for f in os.listdir(src_js):
            src_f = os.path.join(src_js, f)
            dst_f = os.path.join(dst_js, f)
            if os.path.isfile(src_f) and not os.path.exists(dst_f):
                os.makedirs(os.path.dirname(dst_f), exist_ok=True)
                with open(src_f, 'rb') as sf:
                    with open(dst_f, 'wb') as df:
                        df.write(sf.read())

    src_css = os.path.join(src_dir, 'css')
    for d in dirs:
        dst_css = os.path.join(dir_base, d, 'css')
        if not os.path.exists(dst_css):
            continue
        for f in os.listdir(src_css):
            src_f = os.path.join(src_css, f)
            dst_f = os.path.join(dst_css, f)
            if os.path.isfile(src_f) and not os.path.exists(dst_f):
                os.makedirs(os.path.dirname(dst_f), exist_ok=True)
                with open(src_f, 'rb') as sf:
                    with open(dst_f, 'wb') as df:
                        df.write(sf.read())


def mirror_con_wget(url, dir_base):
    os.makedirs(dir_base, exist_ok=True)
    cmd = (
        f'wget --mirror --page-requisites --adjust-extension '
        f'--no-parent --recursive --level=inf --no-check-certificate '
        f'--user-agent="{USER_AGENT}" -e robots=off '
        f'-P "{dir_base}" "{url}"'
    )
    print(f'    wget mirror...')
    ret = os.system(cmd)
    if ret != 0:
        print('    ⚠ wget returned non-zero, continuing anyway')

    # Move files up from domain subdirectory
    items = os.listdir(dir_base)
    if len(items) == 1:
        sub = os.path.join(dir_base, items[0])
        if os.path.isdir(sub):
            print('    Aplanando estructura...')
            for root, dirs, files in os.walk(sub):
                for f in files:
                    src = os.path.join(root, f)
                    rel = os.path.relpath(src, sub)
                    dst = os.path.join(dir_base, rel)
                    os.makedirs(os.path.dirname(dst), exist_ok=True)
                    os.rename(src, dst)
            for root, dirs, files in os.walk(sub, topdown=False):
                try:
                    os.rmdir(root)
                except:
                    pass

    limpiar_nombres_wget(dir_base)


def mirror_con_python(url, dir_base):
    os.makedirs(dir_base, exist_ok=True)
    dominio = urlparse(url).netloc
    visitadas = set()
    pendientes = deque([normalizar_url(url)])
    descargadas = set()

    print(f'    Rastreando {dominio}...')
    with ThreadPoolExecutor(max_workers=8) as pool:
        while pendientes:
            lote = []
            for _ in range(min(16, len(pendientes))):
                u = pendientes.popleft()
                if u in visitadas:
                    continue
                if not u.startswith('http'):
                    continue
                if not es_mismo_dominio(u, dominio):
                    continue
                visitadas.add(u)

                ruta = os.path.join(dir_base, nombre_archivo(u))
                lote.append((u, ruta))

            futuros = {pool.submit(descargar, u, r, descargadas): (u, r) for u, r in lote}
            for futuro in as_completed(futuros):
                u, r = futuros[futuro]
                if futuro.result():
                    print(f'    ↓ {urlparse(u).path[:55]:55s} {os.path.getsize(r)//1024:>5d} KB')
                # Extraer enlaces si es HTML
                if not es_recurso_estatico(u) and os.path.exists(r) and os.path.getsize(r) > 0:
                    try:
                        with open(r, 'r', encoding='utf-8', errors='replace') as fh:
                            content = fh.read()
                        extractor = LinkExtractor()
                        extractor.feed(content)
                        for enlace in extractor.links:
                            completa = normalizar_url(urljoin(u, enlace))
                            if (completa.startswith('http') and
                                es_mismo_dominio(completa, dominio) and
                                completa not in visitadas):
                                pendientes.append(completa)
                        # CSS urls in <link> and <style>
                        for m in re.finditer(r'<link[^>]*href="([^"]+\.css[^"]*)"', content):
                            css_url = urljoin(u, m.group(1))
                            if es_mismo_dominio(css_url, dominio) and css_url not in visitadas:
                                pendientes.append(css_url)
                        for m in re.finditer(r'<style[^>]*>(.*?)</style>', content, re.DOTALL):
                            for cu in CSSUrlExtractor.extract(m.group(1)):
                                cu_full = normalizar_url(urljoin(u, cu))
                                if (cu_full.startswith('http') and
                                    cu_full not in visitadas):
                                    pendientes.append(cu_full)
                    except:
                        pass

    # CSS url() downloads for all downloaded CSS files
    print('    Descargando recursos desde CSS...')
    for root, _, files in os.walk(dir_base):
        for f in files:
            if f.endswith('.css'):
                css_path = os.path.join(root, f)
                with open(css_path, 'r', encoding='utf-8', errors='replace') as fh:
                    css_text = fh.read()
                for cu in CSSUrlExtractor.extract(css_text):
                    if cu.startswith('data:') or '?' in cu:
                        continue
                    cu_full = urljoin(url, cu)
                    if not es_mismo_dominio(cu_full, dominio):
                        continue
                    cu_ruta = os.path.join(dir_base, nombre_archivo(cu_full))
                    if descargar(cu_full, cu_ruta, descargadas):
                        print(f'    ↓ {urlparse(cu_full).path[:55]:55s}')


def main():
    if len(sys.argv) < 3:
        print(f'''
offline_mirror.py v{VERSION} — sitio web completo para ver sin internet

Uso:
  python {os.path.basename(sys.argv[0])} https://ejemplo.com C:\\destino
  python {os.path.basename(sys.argv[0])} --wget https://ejemplo.com C:\\destino

  --wget    usa wget.exe para descargar (más rápido si tienes wget)
  --no-cdn  no descargar CDN scripts localmente
  --no-ga   no eliminar Google Analytics
''')
        sys.exit(1)

    usar_wget = '--wget' in sys.argv
    skip_cdn = '--no-cdn' in sys.argv
    skip_ga = '--no-ga' in sys.argv
    args = [a for a in sys.argv[1:] if not a.startswith('--')]

    if len(args) < 2:
        print('Error: necesito URL y directorio destino')
        sys.exit(1)

    url = args[0].rstrip('/')
    dir_base = os.path.abspath(args[1])

    print(f'''
╔══════════════════════════════════════════╗
║     offline_mirror.py v{VERSION}             ║
║     Sitio completo sin internet           ║
╚══════════════════════════════════════════╝
  URL:   {url}
  Dest:  {dir_base}
  Modo:  {"wget" if usar_wget else "Python nativo"}
''')

    t0 = datetime.now()

    # Fase 1: Descargar
    if usar_wget:
        mirror_con_wget(url, dir_base)
    else:
        mirror_con_python(url, dir_base)

    # Fase 2: Post-procesar HTMLs
    print(f'\n  Post-procesando HTMLs...')
    html_count = 0
    fixed_count = 0
    for root, _, files in os.walk(dir_base):
        for f in files:
            if f.endswith('.html'):
                html_count += 1
                if procesar_html(os.path.join(root, f), dir_base):
                    fixed_count += 1

    # Fase 3: Compartir assets entre subdirectorios
    print(f'  Compartiendo assets...')
    compartir_assets(dir_base)

    # Estadísticas
    total_files = sum(len(files) for _, _, files in os.walk(dir_base))
    total_size = sum(os.path.getsize(os.path.join(r, f))
                     for r, _, files in os.walk(dir_base) for f in files)
    elapsed = (datetime.now() - t0).total_seconds()

    print(f'''
╔══════════════════════════════════════════╗
║  LISTO                                     ║
║  Archivos:  {total_files:>5d}   ({total_size//1024:>5d} KB)       ║
║  HTMLs:     {html_count:>5d}   ({fixed_count} reparados)      ║
║  Tiempo:    {elapsed:>5.1f} s                       ║
║                                           ║
║  Abre: {os.path.join(dir_base, "index.html")}  ║
╚══════════════════════════════════════════╝
''')


if __name__ == '__main__':
    print('[!] Solo para fines educativos / For educational purposes only.\n')
    main()
