#  test_autismo 🧩🩺

Este repositorio contiene un **Sistema Profesional de Evaluación de Autismo** (Versión 5.3.0). Es una herramienta técnica orientada a facilitar el cribado (*screening*) mediante instrumentos científicos validados, como el **M-CHAT-R** y el **AQ-10**, con un motor multilingüe y generación de informes detallados.

## 📂 Descripción del Proyecto

El sistema está diseñado como una aplicación de terminal modular que separa la lógica de evaluación de los datos de los tests y las traducciones.

* **Instrumentos Incluidos**:
* **M-CHAT-R**: Para detección temprana en niños pequeños (16-30 meses).
* **AQ-10**: Cociente de Espectro Autista versión breve para adultos y adolescentes.


* **Arquitectura Robusta**: Utiliza archivos JSON externos para la localización (`locales/`) y los datos de los tests (`tests_data/`), permitiendo añadir nuevos idiomas o escalas sin modificar el código fuente.
* **Validación Inteligente**: Sistema de detección de edad (meses vs. años) y sugerencia automática del instrumento más adecuado.
* **Reportes Detallados**: Al finalizar, genera una tabla con todas las respuestas, el puntaje total y una interpretación basada en umbrales clínicos.

---

## 🚀 Instalación y Ejecución

### 1. Estructura de Carpetas

Para que el script funcione correctamente, asegúrate de mantener esta estructura:

```text
.
├── test.py              # Script principal
├── locales/             # Archivos: es.json, en.json
└── tests_data/          # Archivos: tests_es.json, tests_en.json

```

### 2. Ejecución

Inicia la evaluación con el siguiente comando:

```bash
python test.py

```

---

## ⚠️ Disclaimer Médico (IMPORTANTE)

**Este software es una herramienta de cribado (screening) y NO proporciona un diagnóstico médico.**

1. **No Sustituye a un Profesional**: Los resultados obtenidos son orientativos. Un diagnóstico de TEA (Trastorno del Espectro Autista) solo puede ser realizado por un médico, psicólogo clínico o especialista cualificado.
2. **Uso Ético**: Esta herramienta debe utilizarse con respeto a la privacidad del participante. Los datos generados en la carpeta `results/` son responsabilidad del usuario.
3. **Fines Educativos**: El autor proporciona este código con fines educativos y de soporte a la comunidad, pero no se hace responsable de las decisiones tomadas basadas en los puntajes obtenidos.

---

## 🛠️ Especificaciones Técnicas

* **Lenguaje**: Python 3.x.
* **Persistencia**: Guarda resultados en formato JSON con marcas de tiempo en la carpeta `/results`.
* **Logs**: Sistema de registro de errores en la carpeta `/logs` para asegurar la trazabilidad del sistema.

--- 