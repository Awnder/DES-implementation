# uses python venv RSA
import random
import math
import cui_des
import hashlib

# import pycryptodome

# gen random primes
# ct numbers into bytestring
# find two primes p&q whose prod is N - look at sieve of eratothenes
# digital signature and verification

def generate_random_primes(max_value: int=1000000) -> tuple:
    ''' returns two static primes, will eventually implement random '''
    return (436673, 807707)

def generate_e(phi: int) -> int:
    ''' generates an integer e relatively prime with phi '''
    # common value that is relatively prime
    e = 65537
    if math.gcd(phi, e) == 1:
        return e
    
    # if 65537 is not relatively prime, find another one
    while True:
        e = random.randint(0, phi)
        if math.gcd(phi, e) == 1:
            return e

def calculate_d(phi: int, e: int) -> int:
    ''' effectively returns x^-1 % y using the pow function which is faster '''
    return pow(e, -1, phi)

def encrypt(plaintext: bytes, e: int, N: int) -> list:
    ct = []
    for b in plaintext:
        ct.append(pow(b, e, N))
    return ct

def decrypt(ciphertext: list, d: int, N: int) -> bytes:
    pt = b''
    for i in ciphertext:
        i = pow(i, d, N)
        pt += i.to_bytes(1, byteorder='big')
    return pt 

def sign(plaintext: bytes, d: int, N: int):
    sha = hashlib.sha256()
    sha.update(plaintext)
    hashval = sha.digest()

    block_size = (N.bit_length() + 7) // 8 # round up to largest amount of bytes
    signature = b''
    for p in hashval:
        c = pow(p, d, N)
        c = p.to_bytes(block_size, byteorder='big')
        signature += c

    return signature

    
p, q = generate_random_primes()
phi = (p-1) * (q-1)
N = p*q
e = generate_e(phi)
d = calculate_d(phi, e)

print('p:',p,'q:',q,'N:',N,'phi:',phi,'e:',e,'d:',d)

test = b'abcd\x11\x22\x33\x44'
c = encrypt(test, e, N)
p = decrypt(c, d, N)
print(c)
print(p)

s = sign(test, d, N)


