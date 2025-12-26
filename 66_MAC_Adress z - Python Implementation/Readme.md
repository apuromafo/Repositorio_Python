 
# Unicast.py v0.0.2

**Unicast.py** es una herramienta técnica diseñada para la generación y validación de direcciones MAC con un enfoque en la evasión y el análisis de red.
 Este script es una evolución optimizada en Python inspirada directamente en el script `randomMACcreator.rb` de **iTrox **.

## 🚀 Funcionalidades

* **Generación Unicast/UAA:** El script asegura que las MACs generadas no tengan activos los bits de "Multicast" ni de "Administración Local (LAA)", lo que las hace parecer hardware legítimo de fábrica.
* **Análisis Offline (Portable):** Utiliza una base de datos local ubicada en `/db/nmap-mac-prefixes` para identificar fabricantes (OUI) sin generar tráfico de red externo.
* **Gestión Masiva:** Capacidad para generar múltiples opciones, analizar MACs específicas o validar listas completas desde archivos externos.
* **Logs de Auditoría:** Soporte para exportar resultados a formato `.csv` para documentación técnica.

## 🛠️ Requisitos y Estructura

Para garantizar la portabilidad, el script busca la base de datos de Nmap en la siguiente ruta relativa:

```text
/Proyecto/
├── Unicast.py
└── db/
    └── nmap-mac-prefixes

```

## 💻 Guía de Uso

### Uso básico (Genera 4 opciones por defecto)

```bash
python Unicast.py

```

### Generación masiva (ej. 10 MACs)

```bash
python Unicast.py -g 10

```

### Validación de lista desde archivo

```bash
python Unicast.py -f lista_macs.txt -o

```

---

## ⚖️ Licencia y Créditos

Este software se rige bajo la **Licencia MIT Modificada** de su autor original.

**Copyright (c) 2025 (aKa "iTrox")**

1. **Restricción Comercial:** Queda prohibida cualquier comercialización, venta o monetización directa o indirecta de este software.
2. **Atribución:** Debe mantenerse el aviso de copyright original en cualquier copia o versión derivada.
3. **Inspiración:** Basado en el script original: [Random MAC Creator (Ruby)](https://github.com/iTroxB/My-scripts/blob/main/Random-MAC-Creator/randomMACcreator.rb).
4. **Responsabilidad:** El usuario asume toda la responsabilidad por las consecuencias del uso de esta herramienta. El autor no se hace responsable de daños o violaciones legales.

---

📂 Fuentes de Datos (Disclaimer)
Este script utiliza la base de datos de prefijos MAC proporcionada por el proyecto Nmap.

Nmap (Network Mapper): Copyright (c) 1996–2025 Insecure.Com LLC. La base de datos nmap-mac-prefixes es una compilación de datos de la IEEE y otros registros públicos mantenida por la comunidad de Nmap.

Todos los derechos sobre la recopilación y el formato de dicha base de datos pertenecen a sus respectivos autores. Este script solo actúa como un motor de lectura para dichos datos en local.



### Análisis Técnico  

El script verifica el primer octeto de la dirección MAC para confirmar su anatomía:

* **I/G Bit (Individual/Group):** Si es 0, es **Unicast**.
* **U/L Bit (Universal/Local):** Si es 0, es **Universal (UAA)**.
 