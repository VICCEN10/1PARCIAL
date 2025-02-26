# Ejercicio 1 - Cifrado RSA con autenticidad del mensaje
# 2025-02-26

import Crypto.Util.number
import hashlib

# Usamos 2^16 + 1 = 65537 (número de Fermat)
e = 65537

# Generamos los primos aleatorios de 1024 bits para Bob
pB = Crypto.Util.number.getPrime(1024, randfunc=Crypto.Random.get_random_bytes)
qB = Crypto.Util.number.getPrime(1024, randfunc=Crypto.Random.get_random_bytes)
nB = pB * qB
phiB = (pB - 1) * (qB - 1)
dB = Crypto.Util.number.inverse(e, phiB)

print("\nBob - Clave Pública (n, e):", nB, e)
print("\nBob - Clave Privada (d):", dB)

# Mensaje original de 1050 caracteres
mensaje = "A" * 1050  # Puedes cambiarlo por cualquier texto de 1050 caracteres

# Generamos el hash del mensaje original
hM = int.from_bytes(hashlib.sha256(mensaje.encode('utf-8')).digest(), byteorder='big')

# Dividimos el mensaje en bloques de 128 caracteres
bloques = [mensaje[i:i+128] for i in range(0, len(mensaje), 128)]

# Cifrado de cada bloque con la clave pública de Bob
cifrados = [pow(int.from_bytes(b.encode(), byteorder='big'), e, nB) for b in bloques]

print("\nMensaje cifrado:", cifrados)

# Bob descifra cada bloque con su clave privada
descifrados = [pow(c, dB, nB) for c in cifrados]
mensaje_recibido = ''.join([bytes.fromhex(hex(d)[2:]).decode() for d in descifrados])

# Bob genera el hash del mensaje recibido
hM_recibido = int.from_bytes(hashlib.sha256(mensaje_recibido.encode('utf-8')).digest(), byteorder='big')

# Comparación de los hashes
print("\nHash original:", hex(hM))
print("\nHash recibido:", hex(hM_recibido))
print("\nAutenticidad del mensaje:", hM == hM_recibido)
