import cui_des
import time
import string

# think of stopwatching it when found a word
# 'pad' with numbers at the end of the dict word for tallman's
# use a while loop to count up starting at 0, maybe set a max of around 5 digits in total
# for zerocool, repeat above but with common character replacements

def pswdcrack(desired_pswd: str):
    cp_list = read_common_pswd('common_pswd.txt')
    
    start = time.time()
    for pswd in cp_list:
        num = 0
        temp_pswd = pswd
        pswd_encrypted = crack(temp_pswd).hex().upper()
        print(pswd_encrypted)
        if pswd_encrypted == desired_pswd:
            return [pswd_encrypted, time.time() - start]
        # while num < 2: # test all numbers up to 99999
        #     pswd_encrypted = crack(temp_pswd).hex().upper()
        #     temp_pswd = pswd + str(num).encode()
        #     print(num, pswd_encrypted)
        #     num += 1
        #     if pswd_encrypted in desired_pswd:
        #         found += 1
        #         fpswds.append([pswd_encrypted, time.time() - start])
        #     if found == len(desired_pswd):
        #         return fpswds

def crack(pswd: bytes):
    lm_const = b"KGS!@#$%"
    pswd = pswd.upper()
    pswd = pswd + b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    l = pswd[0:7]
    r = pswd[7:14]
    l = addparity(l)
    r = addparity(r)
    l = crack_encrypt(lm_const, l)
    r = crack_encrypt(lm_const, r)
    return l + r

def crack_encrypt(data: bytes, key: bytes) -> bytes:
    ''' custom DES encryption method designed for cracking. removes padding for lmhash '''
    subkeys = cui_des._generate_subkeys(key)
    plaintext = cui_des._bytes_to_bit_array(data)

    ciphertext = cui_des._crypt_block(plaintext, subkeys)

    ciphertext = cui_des._bit_array_to_bytes(ciphertext)

    return ciphertext

def addparity(p: bytes) -> bytes:
    p = cui_des._bytes_to_bit_array(p)
    p_array = [c for c in cui_des._nsplit(p, 7)]
    for element in p_array:
        element += [0]

    return b''.join([cui_des._bit_array_to_bytes(p) for p in p_array])

def read_common_pswd(filename: str) -> list:
    if filename == None:
        return
    cp = ''
    with open(filename, 'r') as f:
        cp = f.read()
    cp = cp.split('\n')
    cp = [p.encode() for p in cp]
    return cp


# bozo:1001:CE2390AA223560BBE917F8D6FA472D2C:91AFAADB932D20FFD6A26AD91BE226E8:::
# tallman:1002:D3CC6BB953241B61EFB303C2F126705E:8C219140EF269E446F982AD0FD989AC1:::
# zerocool:500:6F3989F97ADB6701C2676C7231D0B1B5:4BCA5C033CC8A87FF18696E7F35DE514:::

pswd = pswdcrack('CE2390AA223560BBE917F8D6FA472D2C')
print(pswd)
