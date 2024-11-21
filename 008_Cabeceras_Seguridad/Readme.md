Pequeño script pensado en validar las cabeceras de seguridad (algo sencillo). 

![image](https://github.com/apuromafo/Repositorio_Python/assets/23161917/681ad0e8-d176-41db-88f5-bcb8ceaf458a)

con el paso del tiempo se añadieron argumentos -h 


![[Pasted image 20241118184355.png]](img%2FPasted%20image%2020241118184355.png)


cuenta con los siguientes paquetes:
los siguientes paquetes:

```
argparse: Herramienta para la creación de interfaces de línea de comandos.
requests: Biblioteca para realizar solicitudes HTTP.
json: Biblioteca para trabajar con datos JSON.
datetime: Biblioteca para trabajar con fechas y horas.
tabulate: Biblioteca para formatear datos en tablas.
colorama: Biblioteca para agregar colores a la salida de la consola.
locale: Biblioteca para trabajar con localizaciones.
socket: Biblioteca para trabajar con sockets.
urllib3: Biblioteca para realizar solicitudes HTTP seguras.
ipaddress: Biblioteca para trabajar con direcciones IP.

```

requiere uso de python3 
para usar basta tener los requerimientos y autorización explícita para uso.
```
pip install -r requirements.txt
```

El día de Hoy este código permite no solo identificar que cabeceras están presentes, sino también recomendaciones de buenas prácticas de que cabeceras podrían eliminarse y cuales podrían configurarse.

![[demo1.jpg]](img/demo1.jpg) 


es posible hacer uso de una petición distinta a GET, por ejemplo con -H podemos pasar los headers personalizados, y en el caso de necesitar enviar contenido raw, podemos hacerlo con un adicional -b como se muestra 
```
python Cabeceras_Seguridad.py http://sitio POST -H "Content-Type: application/json" -b '{"key": "value"}'
```
sin embargo como el uso de json suele ser un poco complejo el scapar carácteres, implementé que valide si lo aborda como raw o json, esto es mejor en un archivo como argumento opcional
 -b poc.txt
  -b poc.json  
   -b poc.raw  
 
 La última opción que se ha configurado es de añadir un proxy  
  -p 127.0.0.1:8080

> [!NOTE]
>      por lo cual , si tienes dudas como está funcionando el argumento -H y -b puedes de paso usar el proxy y ver como está enviando las peticiones.

en particular esta herramienta para mi es funcional a la necesidad actual que necesito, se podría optimizar en muchas formas y maneras, pero por algo se empieza...


 
  21.11.2024





