# Jasper - Analisis y conversion de reportes JasperReports (.jrxml/.jasper)

**Source (origen):** Local (scripts propios del repositorio Apuromafo).
**Categoria:** util - Analisis estatico / Reportes
**Licencia:** MIT
**CLI:** `main.py` (orquestador) + `analizar.py`, `compilar.py`, `convertir.py`, `decompilar_v3.py`, `Reporte.py` (Python 3).

## Que hace

Suite para trabajar con reportes JasperReports en auditorias de seguridad:

| Modulo | Funcion |
|--------|---------|
| `main.py` | **Orquestador.** Pipeline directo en un comando: analiza, compila lo que falte, convierte a PDF y deja todo ordenado + registro en la carpeta destino. Tambien mantiene el menu interactivo clasico. |
| `analizar.py` | Analisis estatico de `.jrxml`/`.jasper`: metadatos, hash SHA-256, expresiones, imagenes embebidas y motor OWASP (SQLi, RCE, LFI/RFI, XXE, XSS, exposicion de datos, deuda tecnica). |
| `compilar.py` | Compila `.jrxml` -> `.jasper` via puente Java (usa los jars de `pyreportjasper`). |
| `convertir.py` | Convierte `.jasper` -> PDF silenciosamente (suprime logs de la JVM), con proteccion anti-sobrescritura. |
| `decompilar_v3.py` | Descompila `.jasper` -> `.jrxml` y audita el codigo recuperado (JSON + MD + informe ejecutivo). |
| `Reporte.py` | Genera informes Markdown (individual o consolidado) desde hallazgos. |

## Uso rapido (pipeline directo, recomendado)

Un solo comando procesa la carpeta completa y deja **todo ordenado** en la carpeta destino:

```powershell
cd C:\Users\pente\Documents\PENTEST\Herramientas\util\029_Jasper
python main.py -f "C:\ruta\con_reportes" -o "C:\ruta\con_reportes\all"
python main.py -a "C:\ruta\reporte.jasper" -o "C:\salida"
```

### Estructura generada en la carpeta destino (`-o`)

```
all\
├── reporte.log                      # Registro completo de la corrida (tool/version/comando,
│                                    #   exit codes, salidas de cada paso, resumen final)
├── informe_auditoria.md             # Informe legible: resumen de severidad + detalle de hallazgos
├── analisis\
│   └── reporte_analisis.json        # Hallazgos tecnicos completos (analizar.py)
├── pdf\                             # PDFs convertidos
│   └── *.pdf
└── compilados\                      # .jasper generados desde .jrxml que no tenian binario
    └── *.jasper
```

### Que hace el pipeline (4 pasos)

1. **Analizar** — auditoria estatica de todos los `.jrxml`/`.jasper` (recursivo) -> JSON.
2. **Compilar** — solo los `.jrxml` que **no** tienen su `.jasper` correspondiente.
3. **Convertir** — todos los `.jasper` (originales + compilados) -> PDF.
4. **Informe** — genera `informe_auditoria.md` con severidades y detalle.

Al finalizar, el registro (`reporte.log`) queda automaticamente en la carpeta destino.

## Uso interactivo (menu clasico)

```powershell
python main.py
```

Menu para lanzar cada modulo por separado (pide modo archivo/carpeta y rutas).

## Uso individual de modulos

```powershell
python analizar.py -f <carpeta_con_.jrxml> -o reporte.json
python analizar.py -a <archivo.jrxml>
python compilar.py -f <carpeta> -o <carpeta_destino>
python convertir.py -f <carpeta_con_.jasper> -o <carpeta_salida>
python decompilar_v3.py -f <carpeta> -o <carpeta_destino>
python Reporte.py -i reporte.json
```

## Opciones (main.py)

| Opcion | Descripcion |
|--------|-------------|
| `-a, --archivo` | Archivo individual (`.jrxml`/`.jasper`). Mutuamente excluyente con `-f`. |
| `-f, --folder` | Carpeta a procesar (recursiva). Mutuamente excluyente con `-a`. |
| `-o, --output` | **(Obligatorio)** Carpeta destino donde queda todo ordenado + `reporte.log`. |

Opciones comunes de los modulos: `-a`/`-f` (entrada), `-o` (salida), `-i` (resumen/input JSON), `-l` (idioma, `es` por defecto), `-h` (ayuda).

## Requisitos e instalacion

- **Python 3** (stdlib + deps de `requirements.txt`).
- **Java JDK** (`java` y `javac` en PATH) para compilar, convertir y descompilar.
- Dependencias: `pip install -r requirements.txt` (`pyreportjasper`, `jpype1`, `pillow`, `packaging`).

Esta herramienta usa **venv propio** (`.venv` dentro de la carpeta) porque sus dependencias
(JVM bridge) chocan con otras tools del toolbox. `main.py` detecta y usa el `.venv`
automaticamente si existe (patron wrapper del repositorio):

```powershell
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
```

## Compatibilidad / Multiplataforma

Windows, Linux, macOS (Python 3; conversiones requieren Java/JasperReports en el entorno
via `pyreportjasper`). Salidas de consola y archivos en UTF-8.

## Notas tecnicas

- El analisis de `.jasper` es limitado (binario): se calcula hash; el analisis profundo
  se hace sobre `.jrxml`. Para recuperar el fuente desde un binario usar `decompilar_v3.py`.
- `convertir.py` no sobrescribe: si el PDF ya existe genera nombre con timestamp.
- Los puentes Java (`JasperCompilerBridge`, `JasperBridge`) se crean y limpian en tiempo
  de ejecucion desde la carpeta de la herramienta.

## Lineamientos (obligatorio)

- Solo contra entornos autorizados (alcance del cliente) y dentro de ventana horaria.
- Uso educativo y de auditoria de seguridad autorizada.
- Licencia MIT.
