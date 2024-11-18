# RUT Chileno v3.0

Descripción:

Este script de Python es un validador de RUTs chilenos con funcionalidades  realizarlo como texto o inclusive como fichero .
Permite crear RUTs de forma aleatoria o secuencial, personalizables por rango, cantidad y formato. Además, ofrece la opción de guardar los resultados en un archivo.
Incluye un banner de texto coloreado para una mejor visualización.
La creación fue hecha paso a paso de forma manual , en forma autónoma, pero la optimización de código fue con IA, para mejorar  cualquier error gramatical y implementar uno a uno estos componentes como tal a esta versión.

Requerimientos:
 Python: Requiere Python 3.x para ejecutarse.
 Librerías estándar de Python.


Saludos


WIKI :

Forma de Uso de forma interactiva y CLI 

Modo Interactivo

 

![Pasted image 20241113232810](https://github.com/user-attachments/assets/0167faef-68b7-4b65-8455-a3a9723303ca)




Modo CLI
```
python generador_ruts.py -h
```
 
Esto mostrará una ayuda detallada con todas las opciones disponibles que se irán actualizando
![Pasted image 20241113232652](https://github.com/user-attachments/assets/b94c0757-4a0d-41e3-8427-f8defcd5fde2)

Opciones:
```
  -h, --help            show this help message and exit
  -m, --modo {a,s}      Modo de operación: "a" para aleatorio o "s" para secuencial.
  -r, --rango INICIAL FINAL
                        Rango en millones para generación aleatoria (INICIAL FINAL). Por defecto: [10, 20].
  -c, --cantidad CANTIDAD
                        Cantidad de RUTs a generar (por defecto: 50).
  -p, --con-puntos      Generar RUTs con puntos. Por defecto: sin puntos.
  -g, --con-guion       Generar RUTs con guión. Por defecto: sin guión.
  -o, --rut-inicial RUT_INICIAL
                        RUT inicial para generación secuencial.
  -f, --archivo ARCHIVO
                        Nombre del archivo de salida (por defecto: ruts_generados.txt).
  -v, --verbose         Mostrar la tabla de opciones en la salida y en el archivo.
  -val, --validar VALIDAR [VALIDAR ...]
                        Validar uno o más RUTs (Ej: 12345678-K ).
  -vo, --archivo-salida ARCHIVO_SALIDA
                        Nombre del archivo para guardar los resultados de la validación.
```
 
 
 Ejemplo de uso en interactivo
 
 python3 rutchile.py
 
 En modo aleatorio:
 
![Pasted image 20241113233011](https://github.com/user-attachments/assets/ba843d58-b64b-487e-9b59-6f3f3b5ef1b7)
  
 Modo secuencial
 
![Pasted image 20241113234813](https://github.com/user-attachments/assets/088a493d-8c4a-469d-9447-7e3be4f77c49)


En modo CLI

# modo secuencial, genera desde el numero 12345678 , la cantidad de 500 , con punto, con guión, archivo de salida poc01.txt
 
```
  python .\rutchile.py -m s -o 12345678 -c 500 -p -g -f poc01.txt
```  

# modo aleatorio, genera desde el numero 12345678 , la cantidad de 500 , con punto, con guión, archivo de salida poc02.txt
```
 python .\rutchile.py -m a -o 12345678 -c 500 -p -g -f poc02.txt
```

con información (añadir -v es verbose , esto permitirá hacer una tabla con las variables usadas) 


Saludos
