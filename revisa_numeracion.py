import os
import re

def normalizar_carpetas():
    # Obtener la ruta actual
    ruta_actual = os.getcwd()
    print(f"Revisando carpetas en: {ruta_actual}\n")

    # Listar solo directorios
    directorios = [d for d in os.listdir(ruta_actual) if os.path.isdir(d)]
    
    cambios = []

    for nombre in directorios:
        # Busca si el nombre empieza con números
        match = re.match(r'^(\d+)(.*)', nombre)
        
        if match:
            numero_str = match.group(1)
            resto_nombre = match.group(2)
            
            # Si tiene menos de 3 dígitos, rellenar con ceros
            if len(numero_str) < 3:
                nuevo_numero = numero_str.zfill(3)
                nuevo_nombre = f"{nuevo_numero}{resto_nombre}"
                
                # Evitar renombrar si el nombre ya es igual
                if nuevo_nombre != nombre:
                    cambios.append((nombre, nuevo_nombre))

    if not cambios:
        print("No se encontraron carpetas que necesiten ajuste de ceros.")
        return

    # Mostrar cambios propuestos
    print("Se proponen los siguientes cambios:")
    for antiguo, nuevo in cambios:
        print(f"  {antiguo}  -->  {nuevo}")

    confirmar = input("\n¿Deseas aplicar estos cambios? (s/n): ")
    
    if confirmar.lower() == 's':
        for antiguo, nuevo in cambios:
            try:
                os.rename(antiguo, nuevo)
                print(f"Renombrado: {nuevo}")
            except Exception as e:
                print(f"Error al renombrar {antiguo}: {e}")
        print("\n¡Proceso finalizado!")
    else:
        print("\nOperación cancelada.")

if __name__ == "__main__":
    normalizar_carpetas()