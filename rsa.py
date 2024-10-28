# uses python venv RSA
import random
import math
import cui_des
import hashlib
from Crypto.Util.number import getPrime

# find two primes p&q whose prod is N - look at sieve of eratothenes
# digital signature and verification

def generate_random_primes(size: int=1024) -> tuple:
    ''' uses pycryptodome's getPrime to generate two random {size}-bit (1024 bit default) primes '''
    return (getPrime(size), getPrime(size))

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
    ''' effectively returns x^-1 % y using the pow function which is faster than doing it without the pow function'''
    return pow(e, -1, phi)

def encrypt(plaintext: bytes, e: int, N: int) -> bytes:
    ''' takes byte plaintext, the e (gcd), and N (p*q) to convert the message to bytes ciphertext '''
    ct = b''
    block_size = (N.bit_length() + 7) // 8 # round up to largest amount of bytes
    for p in plaintext:
        ct += pow(p, e, N).to_bytes(block_size, byteorder='big') # to convert to bytes, need to adjust the integer block size accordingly, since 1 is too small
    return ct

def decrypt(ciphertext: bytes, d: int, N: int) -> bytes:
    ''' takes byte ciphertext, the d (reversed e), and N (p*q) to convert the message to bytes plaintext.
    debugged with pieces os 
    '''
    pt = b''
    block_size = (N.bit_length() + 7) // 8
    for i in range(0, len(ciphertext), block_size):
        block = ciphertext[i:i+block_size]
        decrypt_block = int.from_bytes(block, byteorder='big')
        pt += pow(decrypt_block, d, N).to_bytes(1, byteorder='big')  
    return pt 

def sign(plaintext: bytes, d: int, N: int):
    sha = hashlib.sha256()
    sha.update(plaintext)
    hashval = sha.digest()

    block_size = (N.bit_length() + 7) // 8
    signature = b''
    for p in hashval:
        signature += pow(p, d, N).to_bytes(block_size, byteorder='big')

    return signature

    
p, q = generate_random_primes(8)
phi = (p-1) * (q-1)
N = p*q
e = generate_e(phi)
d = calculate_d(phi, e)

test = b'abcd'
c = encrypt(test, e, N)
p = decrypt(c, d, N)
print(c)
print(p)
