
# Fridump Pro (Single File) 🚀

Una herramienta potente y simplificada basada en el framework **Frida** para realizar volcados (dumps) de memoria RAM de aplicaciones en tiempo real. Esta versión consolida las funcionalidades de `fridump3`, `dumper` y `utils` en un único archivo ejecutable.

## ✨ Características

* **Archivo Único**: Todo el código en un solo script para facilitar su transporte y uso.
* **Organización Inteligente**: Crea carpetas automáticas con el nombre de la app y la fecha del volcado para evitar sobreescritura.
* **Reporte de Dispositivo**: Genera un archivo `info_dispositivo.txt` con metadatos del hardware analizado.
* **Extracción de Strings**: Capacidad de buscar texto legible (contraseñas, URLs, tokens) dentro del volcado binario.
* **Soporte Multi-Plataforma**: Funciona de forma local, por USB o mediante red (IP:Puerto).

## 📋 Requisitos

* Python 3.x
* Frida instalado:
```bash
pip install frida-tools frida

```



## 🚀 Modo de Uso

### 1. Volcado Local (PC)

Analiza un proceso que se ejecuta en tu misma computadora:

```bash
python3 fridump_pro.py "NombreDelProceso"

```

### 2. Dispositivo Móvil (USB)

Ideal para auditorías en Android o iOS:

```bash
python3 fridump_pro.py -u "NombreDeLaApp"

```

### 3. Conexión Remota (IP y Puerto)

Si el servidor de Frida está escuchando en una dirección específica:

```bash
python3 fridump_pro.py -H 192.168.1.15:27042 "NombreDeLaApp"

```

### 4. Volcado Completo con Extracción de Texto

Vuelca regiones de solo lectura y extrae strings automáticamente:

```bash
python3 fridump_pro.py -u -r -s "NombreDeLaApp"

```

## 🛠️ Parámetros Principales

| Parámetro | Descripción |
| --- | --- |
| `process` | Nombre o PID del proceso objetivo. |
| `-u` | Indica conexión por **USB**. |
| `-H` | Especifica un **Host** remoto (IP:Puerto). |
| `-r` | Incluye regiones de memoria de **solo lectura**. |
| `-s` | Activa la extracción de **strings** al finalizar. |
| `-o` | Define un directorio de salida personalizado. |

## 📁 Estructura de Salida

Cada ejecución crea una estructura organizada:

```text
dump/
└── NombreApp_20240520_143005/
    ├── info_dispositivo.txt  <-- Detalles del hardware
    ├── strings.txt           <-- Texto extraído (si se usó -s)
    └── 0x..._dump.data       <-- Archivos binarios de memoria

```

---

*Aviso: Utiliza esta herramienta solo en entornos controlados y con autorización.*

---
 