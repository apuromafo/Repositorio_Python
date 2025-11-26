# Cuestionario de Estilo de Liderazgo en Ciberseguridad (V3)

Script interactivo en Python 3 para evaluar tu estilo de liderazgo en contextos de ciberseguridad, usando escenarios tipo STAR y cálculo de puntuaciones normalizadas.

## Características

- 10 preguntas con escenarios realistas (phishing, incident response, auditorías, proyectos SIEM, etc.).
- Opciones tipo test (A, B, C, D) basadas en cuatro estilos de liderazgo:
  - Autocrático
  - Democrático
  - Transaccional
  - Transformacional
- Cálculo de:
  - Puntuación bruta por estilo.
  - Puntuación normalizada por estilo (ajustada por máximo posible).
- Identificación de:
  - Estilo principal.
  - Estilos secundarios cercanos.
- Feedback:
  - Contexto y consejo por estilo principal.
  - Sugerencias tácticas inmediatas.
- Exportación opcional a JSON con:
  - Timestamp.
  - Respuestas crudas.
  - Puntuaciones normalizadas.
  - Mensajes asociados a los estilos.

## Estilos de liderazgo evaluados

El cuestionario trabaja con cuatro estilos de liderazgo clásicos, aplicados al contexto de ciberseguridad:

### Liderazgo autocrático

- El líder concentra la toma de decisiones y define de forma directa qué se hace y cómo se hace.  
- Es útil en situaciones de alta presión o crisis (por ejemplo, incidentes críticos) donde se necesita rapidez y claridad, pero si se abusa puede reducir la participación y la creatividad del equipo.

### Liderazgo democrático (participativo)

- El líder busca la opinión del equipo, fomenta el debate y suele tomar decisiones después de escuchar distintas perspectivas.  
- Favorece la colaboración, el compromiso y la aceptación de las decisiones, aunque puede ser más lento cuando se requieren respuestas inmediatas.

### Liderazgo transaccional

- El foco está en tareas, procesos, métricas y recompensas/castigos asociados al desempeño.  
- Encaja bien en entornos como SOC, cumplimiento y auditorías, donde son clave los procedimientos, SLAs y el seguimiento constante de resultados.

### Liderazgo transformacional

- El líder inspira con una visión a largo plazo, promueve el cambio y el desarrollo del equipo, y conecta el trabajo diario con un propósito mayor.  
- Es especialmente efectivo para impulsar innovación, mejora continua y cultura de seguridad, aunque necesita complementarse con procesos claros para la ejecución del día a día.

En el resultado del cuestionario verás qué estilo aparece como principal y cuáles se muestran como estilos secundarios cercanos, para entender mejor cómo lideras en distintos escenarios de ciberseguridad.

## Requisitos

- Python 3.8 o superior.
- Permisos de escritura en el directorio actual (solo si usas la opción de exportar a JSON).

## Uso básico

Ejecutar el cuestionario de forma interactiva en terminal:

