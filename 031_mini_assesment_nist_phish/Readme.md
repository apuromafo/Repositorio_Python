# 🛡️ Evaluador NIST TN-2276 de Phishing

Este script implementa una herramienta interactiva para evaluar el nivel de riesgo y dificultad de detección de correos electrónicos sospechosos, basándose en las directrices del **NIST TN-2276: Measuring Email Phishing Susceptibility Using the Phish Scale**.

---

## 📌 Descripción

El programa guía al usuario a través de varias secciones para evaluar diferentes aspectos del correo electrónico sospechoso, como:

- Indicadores técnicos, visuales y lingüísticos
- Tácticas comunes de phishing
- Alineación con situaciones reales (*Premise Alignment*)

Al finalizar, genera un informe estructurado en texto plano con:

- Categoría de riesgo
- Puntuación de *Premise Alignment*
- Nivel de dificultad de detección
- Recomendaciones personalizadas

---

## 🧰 Requisitos

- Python 3.x
- No requiere instalación de paquetes externos

---

## 📁 Estructura del Proyecto

```
.
├── Assesment.py                # Script principal
├── data/                   # Carpeta con archivos JSON de preguntas y recomendaciones
│   ├── partA_cues_yesno.json
│   ├── partA_cues_count.json
│   ├── partC_premise_alignment.json
│   └── recommendations.json
└── reports/                # Carpeta donde se guardan los informes generados
```

> 🔐 **Importante**: El script espera encontrar estos archivos dentro de la carpeta `data/`. Si no están presentes, lanzará un error.

---

## 🚀 Instrucciones de Uso

1. **Clona o descarga** el proyecto
2. **Coloca todos los archivos JSON requeridos** dentro de la carpeta `data/`
3. Ejecuta el script:
   ```bash
   python Assesment.py
   ```
4. Sigue las instrucciones paso a paso

---

## 💬 Idiomas Soportados

- Español
- Inglés

El usuario puede seleccionar el idioma al inicio del programa.

---

## 📝 Informe Generado

Los informes se guardan automáticamente en la carpeta `reports/` con el siguiente formato:

```
report_<nombre_caso>_<fecha>_<hora>.txt
```

Contiene información organizada por secciones:

- Datos del caso
- Antecedentes
- Puntuaciones clave
- Recomendaciones

---

## 📄 Archivos JSON Necesarios

### `partA_cues_yesno.json`

Preguntas sí/no sobre indicadores generales (técnicos, visuales, tácticas, etc.).

### `partA_cues_count.json`

Preguntas numéricas para contar elementos específicos en el mensaje.

### `partC_premise_alignment.json`

Evalúa si el escenario del mensaje parece realista o alineado con situaciones cotidianas.

### `recommendations.json`

Recomendaciones específicas según los resultados obtenidos.

 

## ⚠️ Aviso Legal / Legal Notice

Esta herramienta es unicamente para fines educativos y de auditoria de seguridad autorizada. El uso no autorizado contra sistemas sin el consentimiento explicito del propietario es ilegal. El usuario asume toda responsabilidad por el uso indebido.

This tool is for educational and authorized security auditing purposes only. Unauthorized use against systems without the owner's explicit consent is illegal. The user assumes all responsibility for misuse.
