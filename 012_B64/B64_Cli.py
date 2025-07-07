import base64 as b64

def cifrar_mensaje(msj):
    msj_bytes = msj.encode("utf-8")
    cifrado = b64.b64encode(msj_bytes).decode("utf-8")
    print(cifrado)


def decifrar_mensaje(cifrado):
    cifrado_bytes = cifrado.encode("utf-8")
    decifrar = b64.b64decode(cifrado_bytes ).decode("utf-8")
    print(decifrar)


def cifrar_archivo(archivo_entrada, archivo_salida):
    try:
        with open(archivo_entrada, 'rb') as f:
            file_content = f.read()
        base64_string = b64.b64encode(file_content).decode('utf-8')
        with open(archivo_salida, 'w') as f:
            f.write(base64_string)
        print(f"Archivo '{archivo_entrada}' cifrado y guardado en '{archivo_salida}'.")

    except FileNotFoundError:
        print(f"Error: El archivo '{archivo_entrada}' no fue encontrado.")
    except Exception as e:
        print(f"Ocurrió un error al cifrar el archivo: {e}")


def decifrar_archivo(archivo_entrada, archivo_salida):
    try:
        with open(archivo_entrada, 'r') as f:
            base64_string = f.read()
        cifrado_bytes = base64.b64decode(base64_string)
        decifrar = cifrado_bytes.decode('utf-8')
        with open(archivo_salida, 'w') as f:
            f.write(decifrar)
        print(f"Archivo '{archivo_entrada}' descifrado y guardado en '{archivo_salida}'.")

    except FileNotFoundError:
        print(f"Error: El archivo '{archivo_entrada}' no fue encontrado.")
    except Exception as e:
        print(f"Ocurrió un error al descifrar el archivo: {e}")



def mostrar_menu():
    print("\n--- Menu Base64 ---")
    print("1) Cifrar mensaje")
    print("2) Descifrar mensaje")
    print("3) Cifrar archivo")
    print("4) Descifrar archivo")
    print("5) Salir")


def main():
    while True:
        mostrar_menu()
        opcion = input("Seleccione una opcion: ")

        if opcion == '1':
            mensaje = input("Ingrese el mensaje a cifrar: ")
            cifrar_mensaje(mensaje)
        elif opcion == '2':
            cifrado = input("Ingrese el mensaje cifrado: ")
            decifrar_mensaje(cifrado)
        elif opcion == '3':
            archivo_entrada = input("Ingrese la ruta del archivo a cifrar: ")
            archivo_salida = input("Ingrese la ruta del archivo de salida (ejemplo.txt): ")
            cifrar_archivo(archivo_entrada, archivo_salida)
        elif opcion == '4':
            archivo_entrada = input("Ingrese la ruta del archivo a descifrar: ")
            archivo_salida = input("Ingrese la ruta del archivo de salida (ejemplo.txt): ")
            decifrar_archivo(archivo_entrada, archivo_salida)
        elif opcion == '5':
            print("Saliendo...")
            break
        else:
            print("Opcion no valida. Intente nuevamente.")


if __name__ == "__main__":
    main()
