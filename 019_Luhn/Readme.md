# README - Generador y Validador de IMEI

## Descripción

Este proyecto implementa el algoritmo de Luhn para validar números IMEI (Identidad Internacional de Equipo Móvil). Permite calcular el dígito de verificación de un número IMEI y proporciona información sobre cómo encontrar y utilizar el IMEI de un dispositivo.

## Contenido del Proyecto

- **Luhn.py**: Script en Python que calcula el dígito de verificación de Luhn para un número IMEI dado.
- **Referencias**:
  - [Business Insider - IMEI: qué es y cómo saberlo](https://www.businessinsider.es/imei-utiliza-como-saberlo-1374340)
  - [La Vanguardia - Qué es el número IMEI](https://www.lavanguardia.com/andro4all/operadoras/que-es-numero-imei-donde-encontrarlo-para-que-sirve)
  - [Generador de IMEI - Fake Person Generator](https://www.fakepersongenerator.com/imei-generator)
  - [Calculadora de Luhn](https://es.planetcalc.com/2464/)

## ¿Qué es el IMEI?

El IMEI es un número único que identifica a cada dispositivo móvil. Generalmente, está formado por 15 dígitos y se utiliza para validar la autenticidad del dispositivo, así como para bloquearlo en caso de robo.

### Estructura del IMEI

- **TAC (Type Allocation Code)**: 6 primeros dígitos.
- **FAC (Final Assembly Code)**: 2 siguientes dígitos.
- **SNR (Serial Number)**: 6 dígitos que siguen al FAC.
- **CD (Check Digit)**: 1 dígito que sirve para validar el IMEI.

## Uso

Para calcular el dígito de verificación de Luhn para un número IMEI:

1. Asegúrate de que tienes Python 3.x instalado.
2. Descarga el archivo `Luhn.py`.
3. Ejecuta el script desde la terminal:

   ```
   python Luhn.py
   ```
   verás algo asi de salida
   ```
Introduce el número IMEI (solo dígitos) cuando se te solicite.
Ejemplo de Uso
Si introduces el número 352378027261183, el script calculará el dígito de verificación de Luhn y mostrará resultados como:


Dígito de verificación de Luhn: 0
```

##Validación de IMEI
Puedes validar números IMEI en línea utilizando servicios como IMEI.info, sin embargo este mini proyecto se enfoca directamente en abordar lo que sería el algoritmo de luhr y ver 

##Advertencias
Asegúrate de usar este script y la información sobre el IMEI de manera responsable. El IMEI es una parte crucial de la identidad de un dispositivo y debe ser protegido adecuadamente.

