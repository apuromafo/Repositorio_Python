# PortSwigger Academy Scraper

Descarga automatica del contenido de la PortSwigger Web Security Academy para trabajo offline. Opcionalmente traduce a espanol.

Version: 3.0.0

## Que hace

- Descarga el indice principal, temas y lecciones de la academia
- Guarda cada pagina como HTML limpio (sin scripts, nav, publicidad)
- Convierte automaticamente cada pagina a Markdown (`.md`) para lectura offline
- Descarga todas las imagenes (PNG, SVG, GIF, WebP, etc.)
- Genera un INDEX.html maestro con links a HTML y MD
- Soporte multihilo para descargas paralelas
- Resume: continua desde donde se quedo si se interrumpe (Ctrl+C)
- Cada archivo incluye la URL fuente original
- **Opcional**: traduccion EN->ES de MD, HTML y headers/labels (`--translate`)

## Estructura de salida

```
portswigger_academy_content/
  INDEX.html              # Indice maestro con links (HTML + MD)
  INDEX.json              # Indice estructurado para busqueda
  content/                # HTML limpios
    academy_index.html
    cors.html
    cross-site-scripting/
      reflected-xss.html
  content_md/             # Markdown convertido
    academy_index.md
    cors.md
    cross-site-scripting/
      reflected-xss.md
  images/                 # Todas las imagenes
    academy_index/
    cors/
      lab-basic-cors-vulnerability/
        abc123_diagram.png
  ESP/                    # Traduccion EN->ES (con --translate)
    INDEX.html
    INDEX.json
    md/                   # Markdown en espanol
    html/                 # HTML en espanol
  .download_progress.json # Progreso para resume
```

## Instalacion

```bash
pip install requests beautifulsoup4 markitdown

# Solo si necesitas traduccion:
pip install deep_translator
```

## Uso

```bash
# Descarga completa (HTML + MD, default)
python download.py

# Solo HTML, sin conversion MD
python download.py --no-md

# Con traduccion EN->ES
python download.py --translate

# Con opciones
python download.py -o mi_carpeta -t 8 -d 0.5 -v

# Solo idioma
python download.py -l en
```

### Opciones

| Flag | Descripcion | Default |
|------|-------------|---------|
| `-l, --lang` | Idioma de salida (es/en) | es |
| `-o, --output` | Directorio de salida | portswigger_academy_content |
| `-d, --delay` | Segundos entre requests | 1.0 |
| `-r, --retries` | Intentos maximos por URL | 3 |
| `-t, --threads` | Hilos paralelos | 4 |
| `-v, --verbose` | Salida detallada | off |
| `--md` | Convertir HTML a Markdown | on |
| `--no-md` | No convertir a Markdown | - |
| `--translate` | Traducir contenido a espanol | off |
| `--rate` | Max requests/s a Google Translate | 3 |

## Dependencias

### Base (descarga)
- `requests` - HTTP client
- `beautifulsoup4` - Parser HTML
- `markitdown` - Conversion HTML a Markdown
- `urllib3` (viene con requests) - Retry adapter

### Traduccion (opcional)
- `deep_translator` - Google Translate API

## Caracteristicas

- **Multihilo**: imagenes y lecciones se descargan en paralelo
- **Rate-limit**: maneja automaticamente respuestas 429
- **Retry**: reintenta automaticamente en errores de red
- **Resume**: guarda progreso en `.download_progress.json`, al re-ejecutar continua desde donde iba
- **Limpieza HTML**: elimina nav, footer, scripts, bloques de registro/publicidad
- **Markdown**: conversion automatica a `.md` para lectura offline con cualquier visor
- **Fuentes**: cada archivo incluye comentario con la URL original y fecha de descarga
- **Traduccion**: MD via Google Translate, HTML via mirror dict (sin API), headers via Google API

## Limitaciones

- No descarga contenido que requiere autenticacion (labs interactivos)
- El contenido dinamico (JavaScript) no se ejecuta offline
- Algunos labs dependen de Burp Suite para funcionar
- La traduccion requiere conexion a internet (Google Translate API)

## Aviso Legal

Esta herramienta es unicamente para fines educativos y de auditoria de seguridad autorizada. El uso no autorizado contra sistemas sin el consentimiento explicito del propietario es ilegal.

## Licencia

MIT
