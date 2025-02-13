# RUT Chileno v3.0

## Descripción

Este script de Python es un generador y validador de RUTs chilenos con múltiples funcionalidades. Permite generar RUTs de forma aleatoria o secuencial, validar RUTs individuales o en masa, y guardar los resultados en archivos. Además, incluye un banner de texto coloreado para mejorar la experiencia visual.

El programa está estructurado de manera **no modular** a partir de la experiencia modular previa

 
---

## Requerimientos

- **Python**: Requiere Python 3.x para ejecutarse.
- **Librerías estándar de Python**: No se necesitan librerías externas.

---

## Funcionalidades Principales

1. **Generación de RUTs Aleatorios**:
   - Genera RUTs dentro de un rango específico (por defecto: entre 10 y 20 millones).
   - Personalizable por cantidad, formato (con/sin puntos y guion) y archivo de salida.

2. **Generación de RUTs Secuenciales**:
   - Genera RUTs a partir de un número inicial y una cantidad específica.
   - Compatible con formatos personalizados y guardado en archivos.

3. **Validación de RUTs**:
   - Valida uno o más RUTs ingresados manualmente o desde un archivo.
   - Muestra un resumen detallado de los resultados (válidos/inválidos).

4. **Banner Coloreado**:
   - Incluye un banner ASCII con degradados de colores generados dinámicamente.

 

---

## Forma de Uso

### Modo Interactivo

Ejecuta el script sin argumentos para acceder al menú interactivo:

```bash
python Menu_rutchile.py
```

#### Ejemplo de Menú Interactivo:

```
=== MENÚ PRINCIPAL ===
1. Generar RUTs Aleatorios
2. Generar RUTs Secuenciales
3. Validar RUTs
4. Salir
Seleccione una opción (1-4): 1
```

Sigue las instrucciones en pantalla para configurar las opciones deseadas.

---

  