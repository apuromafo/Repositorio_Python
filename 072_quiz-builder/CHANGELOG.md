# Changelog

## [1.0.0] — 2026-07-29

### Added
- Proyecto inicial Quiz Builder
- Script `generar.py` para crear examenes desde terminal
- Template base con 4 modos: Examen, Estudio, Temas, Adaptativo
- Dashboard HTML para gestion de examenes
- Temporizador configurable por examen
- Marcado de preguntas con bandera
- Atajos de teclado (1-5 respuesta, Enter siguiente, F marcar)
- Estadisticas por tema con heatmap
- Historial de intentos y repaso de fallos
- Exportacion a PDF
- Datos guardados en localStorage (100% offline)
- Demo incluido: `demo_quiz/` con datos dummy

### Fixed
- Correccion en `generar.py`: regex de `timeRemaining` ahora reemplaza correctamente
  el valor completo (antes dejaba `* 60` residual, duplicando el tiempo)
