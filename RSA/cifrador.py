import base64

def cifrar_rsa():
    archivo_pub = input("Ingresa el nombre del archivo de la llave pública: ")
    archivo_llave_b64 = "../TBC/key.txt"
    
    try:
        with open(archivo_pub, "r") as f:
            lineas = f.readlines()
            e = int(lineas[0].strip())
            n = int(lineas[1].strip())
            print(f"(e={e}, n={n})")
        
        with open(archivo_llave_b64, "r") as f:
            contenido_b64 = f.read().strip()
            llave_bytes = base64.b64decode(contenido_b64)
            r = int.from_bytes(llave_bytes, byteorder='big')

        print("-" * 30)
        print(f"Valor de la llave (entero r): {r}")
        
        c = pow(r, e, n)
        
        print("-" * 30)
        print(f"Valor cifrado (c): {c}")
        print("-" * 30)
        
        archivo_salida = "cipher_key.txt"
        with open(archivo_salida, "w") as f:
            f.write(str(c))
        print(f"llave guardada en {archivo_salida}")

    except FileNotFoundError:
        print("Error: No se encontró uno de los archivos especificados.")
    except Exception as err:
        print(f"Error inesperado: {err}")

if __name__ == "__main__":
    cifrar_rsa()