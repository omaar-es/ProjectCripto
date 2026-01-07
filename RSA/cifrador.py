def cifrar_rsa():
    archivo_pub = input("Ingresa el nombre del archivo de la llave pública: ")
    archivo_llave_hex = "../TBC/key.txt" 
    
    try:
        with open(archivo_pub, "r") as f:
            lineas = f.readlines()
            e = int(lineas[0].strip())
            n = int(lineas[1].strip())
            print(f"(e={e}, n={n})")

        with open(archivo_llave_hex, "r") as f:
            contenido_hex = f.read().strip()
            r = int(contenido_hex, 16)

        print("-" * 30)
        print(f"llave:  {r}")
        
        c = pow(r, e, n)
        
        print("-" * 30)
        print(f"c: {c}")
        print("-" * 30)
        
        archivo_salida = "cipher_key.txt"
        with open(archivo_salida, "w") as f:
            f.write(str(c))
            
        print(f"llave cifrada en {archivo_salida}")

    except FileNotFoundError:
        print(f"Error: No se encontró el archivo '{archivo_pub}' o '{archivo_llave_hex}'.")
    except ValueError:
        print("Error: El contenido del archivo no es un hexadecimal válido o los valores de la llave no son números.")
    except Exception as err:
        print(f"Error inesperado: {err}")

if __name__ == "__main__":
    cifrar_rsa()