import re
import sys
import argparse
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, unquote, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

LINKEDIN_HOSTS = {"lnkd.in", "linkedin.com", "www.linkedin.com"}

def is_linkedin_domain(url: str) -> bool:
    try:
        netloc = urlparse(url).netloc.lower()
        return any(netloc == h or netloc.endswith("." + h) for h in LINKEDIN_HOSTS)
    except Exception:
        return False

def extract_url_param(url: str) -> str | None:
    try:
        p = urlparse(url)
        if p.netloc.endswith("linkedin.com"):
            qs = parse_qs(p.query)
            if "url" in qs and qs["url"]:
                return unquote(qs["url"][0])
    except Exception:
        pass
    return None

def parse_html_for_next(html: str) -> str | None:
    soup = BeautifulSoup(html, "html.parser")
    for a in soup.find_all("a", href=True):
        href = a["href"]
        ext = extract_url_param(href)
        if ext:
            return ext
        if href.startswith("http") and not is_linkedin_domain(href):
            return href
    canonical = soup.find("link", rel="canonical", href=True)
    if canonical:
        href = canonical["href"]
        ext = extract_url_param(href)
        if ext:
            return ext
        if href.startswith("http") and not is_linkedin_domain(href):
            return href
    meta = soup.find("meta", attrs={"http-equiv": lambda v: v and v.lower() == "refresh"})
    if meta:
        content = meta.get("content", "")
        match = re.search(r"url=(['\"]?)(.*?)\1", content, re.I)
        if match:
            ext = extract_url_param(match.group(2))
            if ext:
                return ext
            if match.group(2).startswith("http") and not is_linkedin_domain(match.group(2)):
                return match.group(2)
    return None

def hosts_different(url1: str, url2: str) -> bool:
    try:
        return urlparse(url1).netloc.lower() != urlparse(url2).netloc.lower()
    except Exception:
        return True

def follow_redirect_chain(session: requests.Session, url: str, max_hops=10, max_external_hosts=2) -> list[str]:
    chain = [url]
    current = url
    external_hosts_count = 0  # Contador de hosts externos diferentes al inicial

    # Host inicial para comparar
    initial_host = urlparse(url).netloc.lower()

    for _ in range(max_hops):
        try:
            r = session.head(current, allow_redirects=False, timeout=10)
            loc = r.headers.get("Location")
            next_url = None
            if loc:
                loc = urljoin(current, loc)
                next_url = loc
            else:
                r = session.get(current, timeout=15)
                extracted = extract_url_param(r.url) or parse_html_for_next(r.text) or r.url
                next_url = extracted

            if next_url is None:
                return chain

            next_host = urlparse(next_url).netloc.lower()

            # Contar host externo si diferente y no lnkd.in ni linkedin.com
            if next_host != initial_host and not any(next_host.endswith(h) for h in ["lnkd.in", "linkedin.com"]):
                external_hosts_count += 1
                if external_hosts_count > max_external_hosts:
                    # Ya superó límite de hosts externos, cortar cadena
                    return chain

            if not hosts_different(current, next_url):
                return chain

            if next_url in chain:
                return chain

            chain.append(next_url)
            current = next_url

        except requests.RequestException:
            return chain

    return chain


def resolve_urls_in_text(text: str, workers: int = 8) -> tuple[str, dict[str, list[str]], list[str]]:
    pattern = r"https://lnkd\.in/[A-Za-z0-9_-]+"
    urls = sorted(set(re.findall(pattern, text)))
    cache = {}
    unresolved = []
    result_text = text

    def task(u):
        with requests.Session() as session:
            return u, follow_redirect_chain(session, u)

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(task, u): u for u in urls}
        for f in as_completed(futures):
            original_url, chain = f.result()
            if len(chain) <= 1:
                unresolved.append(original_url)
                continue
            cache[original_url] = chain
            # Construir cadena para reemplazo, separando con flechas
            chain_str = " -> ".join(chain)
            # Reemplazo en texto original con paréntesis para claridad
            result_text = result_text.replace(original_url, f"({chain_str})")

    return result_text, cache, unresolved

def main():
    parser = argparse.ArgumentParser(description="Resolver lnkd.in mostrando cadena completa de redirecciones con saltos de host distintos.")
    parser.add_argument("-a", "--archivo", help="Archivo de entrada con texto.")
    parser.add_argument("-o", "--output", help="Archivo para guardar texto procesado.")
    parser.add_argument("-w", "--workers", type=int, default=8, help="Número de hilos para resolución concurrente.")
    args = parser.parse_args()

    if args.archivo:
        try:
            with open(args.archivo, "r", encoding="utf-8") as f:
                input_text = f.read()
            print(f"Leyendo texto desde: {args.archivo}")
        except FileNotFoundError:
            print(f"Error: El archivo '{args.archivo}' no encontrado.", file=sys.stderr)
            sys.exit(1)
    else:
        print("Pega el texto con enlaces lnkd.in y termina con doble Enter:")
        lines = []
        while True:
            try:
                line = input()
                if not line:
                    break
                lines.append(line)
            except EOFError:
                break
        input_text = "\n".join(lines)

    if not input_text.strip():
        print("\nNo se ingresó texto para procesar.")
        return

    print("Resolviendo URLs y construyendo cadena completa de hosts...\n")
    resolved_text, chains, unresolved = resolve_urls_in_text(input_text, workers=args.workers)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(resolved_text)
            print(f"Texto procesado guardado en: {args.output}")
        except Exception as e:
            print(f"Error al guardar en '{args.output}': {e}", file=sys.stderr)
            sys.exit(1)
    else:
        print("--- Texto Procesado ---")
        print(resolved_text)
        print("----------------------\n")

    if unresolved:
        print("URLs no resueltas:")
        for u in unresolved:
            print(f" - {u}")

    print("\nDetalle completo de cadenas por URL:")
    for orig, chain in chains.items():
        print(f"{orig} : {' -> '.join(chain)}")

if __name__ == "__main__":
    main()
