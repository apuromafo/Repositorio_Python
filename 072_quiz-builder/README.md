# Quiz Builder

Generador de exámenes interactivos para navegador, 100% offline.

## Estructura

```
quiz-builder/
├── generar.py           # Crea nuevos exámenes con preguntas por tema
├── preguntas.py         # CLI para gestionar preguntas (list, add, edit, etc.)
├── examenes.json        # Registro de exámenes creados
├── template/            # Template base
│   ├── index.html       # Página del examen
│   ├── editor.html      # Editor visual de preguntas
│   ├── preguntas.js     # Banco de preguntas (plantilla)
│   ├── css/             # Estilos + 4 temas (oscuro, claro, sepia, alto contraste)
│   └── js/              # Motor del simulador + almacenamiento multi-usuario
└── README.md
```

## Requisitos

- Python 3.6+

## Crear un examen nuevo

```bash
python generar.py
```

Responde: ID único, título, tiempo, temas y cantidad de preguntas por tema.
Se genera una carpeta con todo listo para abrir en el navegador.

## CLI de preguntas (`preguntas.py`)

```
python preguntas.py [-lang es|en] <comando> [opciones]
```

| Comando | Descripción |
|---------|-------------|
| `list [tema]` | Listar preguntas (opcional: filtrar por tema) |
| `show <id>` | Mostrar detalle de una pregunta |
| `add` | Agregar pregunta (interactivo) |
| `edit <id>` | Editar pregunta |
| `delete <id>` | Eliminar pregunta |
| `count` | Total de preguntas y por tema |
| `validate` | Validar estructura y referencias de preguntas |
| `export <archivo>` | Exportar a JSON |
| `import <archivo>` | Importar desde JSON |
| `exams` | Listar exámenes registrados |
| `help` | Esta ayuda |

Usa `-lang en` para output en inglés (defecto: español).

## Editor visual

Cada examen incluye `editor.html`. Ábrelo en el navegador para:
- Listar preguntas por tema
- Agregar/editar/eliminar preguntas
- Cambiar tipo (única, múltiple, texto libre)
- Añadir imagen (URL o archivo)
- Exportar `preguntas.js` actualizado

## Multi-usuario

La barra de navegación del examen incluye un selector de usuarios.
Cada usuario tiene su propio progreso, historial y estadísticas
guardados en localStorage con prefijo independiente.

## Funcionalidades

- 4 modos: Examen (temporizado), Estudio (libre), Temas, Adaptativo
- Temporizador configurable
- Temas visuales: oscuro, claro, sepia, alto contraste
- Multi-idioma: español / inglés (selector en configuración)
- Marcado de preguntas con bandera
- Atajos de teclado (1-5 respuesta, Enter siguiente, F marcar)
- Estadísticas por tema (heatmap)
- Historial de intentos por usuario
- Repaso de fallos
- Exportación a PDF
- Datos guardados en el navegador (localStorage)
- 100% offline, sin servidor ni internet

## Autor

**Apuromafo** — [github.com/Apuromafo](https://github.com/Apuromafo)

## Disclaimer

Este software se proporciona "TAL CUAL", sin garantía de ningún tipo,
expresa o implícita, incluyendo pero no limitado a garantías de
comercialización, idoneidad para un propósito particular y no
infracción. El autor no será responsable por ningún reclamo, daño u
otra responsabilidad, ya sea en una acción de contrato, agravio o
cualquier otro motivo, que surja de o en conexión con el software.

## Licencia

MIT. El archivo `template/js/jspdf.umd.min.js` es la biblioteca
jsPDF (MIT) con componentes bajo BSD-3-Clause (Adobe).
