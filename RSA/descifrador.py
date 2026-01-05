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
        
        m_hex = f"{m:X}"

        with open("key.txt", "w") as f_out:
            f_out.write(m_hex)

        print("-" * 30)
        print(f"Descifrado guardado en: key.txt")
        print("-" * 30)

    except FileNotFoundError:
        print("Error: No se encontró el archivo.")
    except Exception as err:
        print(f"Error: {err}")

if __name__ == "__main__":
    descifrar_rsa()