# Ejercicio 2 - Firma digital de un contrato usando RSA
# 2025-02-26

import Crypto.Util.number
import hashlib

# Número de Fermat 2^16 + 1 = 65537
e = 65537

# Generamos las claves de Alice
pA = Crypto.Util.number.getPrime(1024, randfunc=Crypto.Random.get_random_bytes)
qA = Crypto.Util.number.getPrime(1024, randfunc=Crypto.Random.get_random_bytes)
nA = pA * qA
phiA = (pA - 1) * (qA - 1)
dA = Crypto.Util.number.inverse(e, phiA)

print("\nAlice - Clave Pública (n, e):", nA, e)
print("\nAlice - Clave Privada (d):", dA)

# Leer el archivo NDA.pdf y calcular su hash
pdf_path = "/Users/viccen10/Documents/8to Semestre/Seguridad Informatica/Parcial1/NDA.pdf"
with open(pdf_path, "rb") as file:
    pdf_content = file.read()

hM = int.from_bytes(hashlib.sha256(pdf_content).digest(), byteorder='big')
print("\nHash del documento:", hex(hM))

# Alice firma el hash con su clave privada
firma_Alice = pow(hM, dA, nA)
print("\nFirma digital de Alice:", firma_Alice)

# La Autoridad Certificadora (AC) verifica la firma de Alice
hM_verificado = pow(firma_Alice, e, nA)
print("\nVerificación de Alice:", hM == hM_verificado)

# AC firma el documento con su propia clave privada
pAC = Crypto.Util.number.getPrime(1024, randfunc=Crypto.Random.get_random_bytes)
qAC = Crypto.Util.number.getPrime(1024, randfunc=Crypto.Random.get_random_bytes)
nAC = pAC * qAC
phiAC = (pAC - 1) * (qAC - 1)
dAC = Crypto.Util.number.inverse(e, phiAC)

firma_AC = pow(hM, dAC, nAC)
print("\nFirma de la AC:", firma_AC)

# Bob verifica la firma de la AC
hM_final = pow(firma_AC, e, nAC)
print("\nVerificación de la AC:", hM == hM_final)

