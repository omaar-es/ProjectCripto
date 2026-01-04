import random
import math
from Crypto.Util import number

def generar_y_guardar_llaves():
    
    bits = 64
    p = number.getPrime(bits)
    q = number.getPrime(bits)
    while p == q:
        q = number.getPrime(bits)

    n = p * q
    phi = (p - 1) * (q - 1)

    e = 0
    while True:
        e = random.randrange(2, phi)
        if e == 3 or e == 65537:
            continue
        # Debe ser coprimo
        if math.gcd(e, phi) == 1:
            break

    d = pow(e, -1, phi)

    nombre_pub = "publica.txt"
    with open(nombre_pub, "w") as f:
        f.write(f"{e}\n{n}")

    nombre_priv = "privada.txt"
    with open(nombre_priv, "w") as f:
        f.write(f"{d}\n{n}")
    
    print("-" * 30)
    print(f"p: {p}")
    print(f"q: {q}")
    print(f"n: {n}")
    print(f"e: {e}")
    print(f"d: {d}")

if __name__ == "__main__":
    generar_y_guardar_llaves()