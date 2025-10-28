

# 🛡️ Generador Modular de Datos Chilenos para QA

Este script es una herramienta modular desarrollada en Python diseñada para generar grandes volúmenes de **datos falsos (simulados) pero altamente coherentes** con el ecosistema chileno. Los datos generados son matemáticamente válidos (RUT, números de tarjetas, etc.) y plausibles (coherencia geográfica, técnica y de mercado).

## ⚠️ Advertencia y Usos

Este generador está destinado **únicamente** para ser utilizado en **ambientes de Desarrollo, Control de Calidad (QA), y Pruebas de Seguridad Ofensiva (Pentesting)** bajo un marco legal y ético estricto.

  * **Pruebas de QA:** Ideal para llenar bases de datos de desarrollo y testing, garantizando que las validaciones de sistemas (formatos de RUT, direcciones, lógica de vehículos, etc.) funcionen correctamente con **datos realistas pero ficticios**.
  * **Pruebas Ofensivas/Seguridad:** Puede usarse para simular la creación de usuarios o entidades en sistemas de prueba para evaluar vulnerabilidades de entrada de datos, lógica de negocio y exposición.

> **¡IMPORTANTE\!**
> **NO UTILIZAR** los datos generados en entornos de **producción** o para **fines ilícitos o fraudulentos** de ningún tipo. El uso indebido es responsabilidad exclusiva del usuario.

-----

## 🛠️ Contenido Generado

El script es capaz de generar los siguientes tipos de entidades, asegurando la máxima coherencia entre sus atributos:

  * **👤 Personas Naturales:** RUT válido, datos demográficos, de contacto y financieros (ej. tarjetas válidas Luhn).
  * **🏢 Empresas:** RUT (Rol Único Tributario) válido, Razón Social, Giro Económico y dirección tributaria.
  * **🚗 Vehículos:** Patentes, VIN, Marca, Modelo, y Norma de Emisiones, con **coherencia estricta** (modelo, carrocería, motor plausible).

-----

## ⚙️ Cómo Ejecutar

Asegúrese de tener todos los scripts modulares (`main.py`, `gen_auto.py`, etc.) en la misma carpeta.

1.  Ejecute el script principal desde su terminal:
    ```bash
    python main.py
    ```
2.  El script le solicitará la **cantidad** de registros por cada tipo (Personas, Empresas, Vehículos).
3.  Finalmente, podrá seleccionar los formatos de exportación deseados (**JSON** y/o **CSV**) para guardar los resultados en la carpeta `output/`.
 