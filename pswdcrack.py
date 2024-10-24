import cui_des
import time

def pswdcrack(desired_pswd: str) -> list:
    ''' wrapper function for lmhash decryption, takes an input hash string and iterates through a dictionary to find a matching hash 
        returns the password and epoch time
    '''
    cp_list = read_common_pswd('common_pswd.txt')    
    start = time.time()
    cp_nums = [b'0',b'1',b'2',b'3',b'4',b'5',b'01',b'012',b'0123',b'01234',b'12',b'123',b'1234',b'00',b'11',b'22',b'33',b'44',b'55',b'12345',b'123456']
    
    for pswd in cp_list:

        # cracking a password without modification
        temp_pswd = pswd
        pswd_encrypt = lmhash(temp_pswd).hex().upper()
        print(pswd_encrypt)
        if pswd_encrypt == desired_pswd:
            return [temp_pswd, time.time() - start]

        # cracking a password by appending common number suffixes
        for cpn in cp_nums:
            temp_pswd = pswd + cpn
            pswd_encrypt = lmhash(temp_pswd).hex().upper()
            print(pswd_encrypt)
            if pswd_encrypt == desired_pswd:
              return [temp_pswd, time.time() - start]

        # cracking a password by removing an 's' for singular if applicable
        # temp_pswd = pswd
        # if temp_pswd == b's':
        #     temp_pswd = temp_pswd[0:-1]
        #     pswd_encrypt = crack(temp_pswd).hex().upper()
        #     if pswd_encrypt in desired_pswd:
        #         return [temp_pswd, time.time() - start]
            
        # cracking a password by adding an 's' for plural if applicable
        # temp_pswd = pswd
        # if temp_pswd[-1] != b's':
        #     temp_pswd = temp_pswd + b's'
        #     pswd_encrypt = crack(temp_pswd).hex().upper()
        #     if pswd_encrypt in desired_pswd:
        #         return [temp_pswd, time.time() - start]


def lmhash(pswd: bytes) -> bytes:
    ''' the actual lm hash, takes a byte string plaintext and operates on it, returning a byte string ciphertext '''
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

def crack_encrypt(lm_const: bytes, side: bytes) -> bytes:
    ''' custom DES encryption method designed for cracking. removes padding for lmhash '''
    subkeys = cui_des._generate_subkeys(side)
    plaintext = cui_des._bytes_to_bit_array(lm_const)
    ciphertext = cui_des._crypt_block(plaintext, subkeys)
    ciphertext = cui_des._bit_array_to_bytes(ciphertext)
    return ciphertext

def addparity(p: bytes) -> bytes:
    ''' adds a 0 to each 7 bits of data '''
    p = cui_des._bytes_to_bit_array(p)
    p_array = [c for c in cui_des._nsplit(p, 7)]
    for element in p_array:
        element += [0]
    return b''.join([cui_des._bit_array_to_bytes(p) for p in p_array])

def read_common_pswd(filename: str) -> list:
    ''' reads a given filename to return a byte string list of all the passwords in the dictionary file '''
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

pswd = pswdcrack('D3CC6BB953241B61EFB303C2F126705E')
print(pswd)
