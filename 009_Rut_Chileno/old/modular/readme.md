# RUT Chileno v3.0

## Descripción

Este script de Python es un generador y validador de RUTs chilenos con múltiples funcionalidades. Permite generar RUTs de forma aleatoria o secuencial, validar RUTs individuales o en masa, y guardar los resultados en archivos. Además, incluye un banner de texto coloreado para mejorar la experiencia visual.

El programa está estructurado de manera **modular**, lo que facilita su mantenimiento, escalabilidad y reutilización de componentes. Cada funcionalidad está implementada en módulos separados (`generar_aleatorio.py`, `generar_secuencial.py`, `validar_ruts.py`, `banner.py`), lo que permite una integración clara con el menú principal.

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

## Estructura Modular

El proyecto está organizado en los siguientes módulos:

- **`main.py`**: Menú principal que integra todas las funcionalidades.
- **`generar_aleatorio.py`**: Genera RUTs aleatorios dentro de un rango especificado.
- **`generar_secuencial.py`**: Genera RUTs secuenciales a partir de un número inicial.
- **`validar_ruts.py`**: Valida RUTs individuales o en masa.
- **`banner.py`**: Genera el banner ASCII con degradados de colores.

---

## Forma de Uso

### Modo Interactivo

Ejecuta el script sin argumentos para acceder al menú interactivo:

```bash
python main.py
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

  