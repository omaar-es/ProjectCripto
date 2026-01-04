def descifrar_rsa():
    
    archivo_priv = input("Ingresa el nombre del archivo de la llave privada: ")
    cipher_key = "cipher_key.txt"
    
    try:
        with open(archivo_priv, "r") as f:
            lineas = f.readlines()
            d = int(lineas[0].strip())
            n = int(lineas[1].strip())

        with open(cipher_key, "r") as f:
            c = int(f.read().strip())

        m = pow(c, d, n)
        
        print("-" * 30)
        print("DESCIFRADO:")
        print(m)
        print("-" * 30)

    except FileNotFoundError:
        print("Error: No se encontro el archivo.")
    except Exception as err:
        print(f"Error: {err}")

if __name__ == "__main__":
    descifrar_rsa()