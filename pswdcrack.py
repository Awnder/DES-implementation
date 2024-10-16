from cui_des import DESCore
from cui_des import DESCore
import time
import string
import itertools

class lmh_cracker:
    def __init__(self):
        # info from wikipedia's LAN manager article
        self.pt_key = b"KGS!@#$%"
        # lmh only uses uppercased letters and printable chars 
        self.ascii_chars = [b' ', b'!', b'"', b'#', b'$', b'%', b'&', b"'", b'(', b')', b'*', b'+', b',', b'-', b'.', b'/', b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b':', b';', b'<', b'=', b'>', b'?', b'@', b'A', b'B', b'C', b'D', b'E', b'F', b'G', b'H', b'I', b'J', b'K', b'L', b'M', b'N', b'O', b'P', b'Q', b'R', b'S', b'T', b'U', b'V', b'W', b'X', b'Y', b'Z', b'[', b'\\', b']', b'^', b'_', b'`', b'{', b'|', b'}', b'~']
        self.alphanumerics = string.ascii_uppercase.encode(encoding='utf-8') + string.digits.encode(encoding='utf-8')
        self.des = DESCore()

    def brute_force(self, hashed_pswd: bytes, filename: str) -> None:
        ''' brute forces (with a dictionary aid) one bytestring hashed passwords encrypted with LM Hash, with timed info
            parameters:
                hashed_pswd: bytestring hashed password to brute force
                filename: common words to use in brute forcing
            output:
                prints the found password or 'not found' if password isn't in common words
                prints the time elapsed
        '''
        start = time.time()
        
        hashed_pswd = hashed_pswd.upper()
        found = False
        # remove_chars = self.init_remove_chars(hashed_pswd)
        common_pswd = self.init_common_pswd(filename) # bytes 

        # for i in range(0, 2):
        #     c = common_pswd[i]
        #     c = self.l_addpadding(c)
        #     l, r = c[0:7], c[7:14]
        #     l = self.l_addparity(l)
        #     r = self.l_addparity(r)
        #     result = self.des.encrypt(l,self.pt_key).upper()
        #     result = self.l_rem_x(result)
        #     print('final',result)


        for p in common_pswd:
            p = p + b'\00\00\00\00\00\00\00\00\00\00\00\00\00\00' # add 14 bits of padding, extraneous will be removed
            l, r = p[0:7], p[7:14]
            l = self.l_addparity(l)
            r = self.l_addparity(r)
            le = self.des.encrypt(l, self.pt_key).upper()
            re = self.des.encrypt(r, self.pt_key).upper()
            # le = self.l_rem_x(le)
            # re = self.l_rem_x(re)

            print(le+re)

            if le + re == hashed_pswd: # removing the last ' from left and 'b from the right
                print('password', p)
                end = time.time()
                found = True
                print('time',end - start)
                break
            

            # encrypted_pswd = self.encrypt_crack(p, remove_chars)
            # # skipped if the hash from the guessed password contains a character not in the desired hash
            # if encrypted_pswd == None: 
            #     continue
            # encrypted_pswd = self.l_rem_x(encrypted_pswd).upper()
            # print(encrypted_pswd)
            # if encrypted_pswd == hashed_pswd:
            #     end = time.time()
            #     print('FOUND PSWD:', p)
            #     print('time:', end-start)
            #     found = True
            #     break

        if not found:
            end = time.time()
            print('pswd not in dictionary')
            print('time:', end-start)


    def init_common_pswd(self, filename: str) -> list:
        ''' reads a file and returns an list of uppercase bytestring words '''
        if filename == None:
            return
        cp = ''
        with open(filename, 'r') as f:
            cp = f.read()
        cp = cp.split('\n')
        cp = [p.upper().encode(encoding='utf-8') for p in cp]
        return cp
                
    def encrypt(self, pswd: bytes) -> bytes:
        ''' runs the lm hash encryption and returns the final encryption hash '''
        pswd = self.l_addpadding(pswd)
        pswd_l, pswd_r = self.l_splithalf(pswd)
        encrypted_l = self.des.encrypt(self.pt_key, self.l_addparity(pswd_l))
        encrypted_r = self.des.encrypt(self.pt_key, self.l_addparity(pswd_r))
        return encrypted_l + encrypted_r
    
    def encrypt_crack(self, pswd: bytes, remove_chars: list) -> bytes:
        ''' runs the lm hash encryption and returns the final encryption hash. 
            if a hash contains a character in the remove_chars list, then discard the attempt by returning None
        '''
        pswd = self.l_addpadding(pswd)
        pswd_l, pswd_r = self.l_splithalf(pswd)
        encrypted_l = self.des.encrypt(self.pt_key, self.l_addparity(pswd_l))
        if any(c in encrypted_l for c in remove_chars):
            return None
        encrypted_r = self.des.encrypt(self.pt_key, self.l_addparity(pswd_r))
        if any(c in encrypted_r for c in remove_chars):
            return None

        return encrypted_l + encrypted_r

    def init_remove_chars(self, hashed_pswd: bytes) -> list:
        ''' returns list of printable ascii characters used to remove a hash as a possibility if it contains characters not in hashed_pswd '''
        remove_chars = []
        for c in self.ascii_chars:
            if c not in hashed_pswd:
                remove_chars.append(c)
        return remove_chars

    def l_addpadding(self, pswd: bytes) -> bytes:
        pad_length = 14 - len(pswd) % 15
        return pswd + (b'\x00' * pad_length)

    def l_splithalf(self, pswd: bytes) -> bytes:
        return pswd[0:7], pswd[7:14]

    def l_addparity(self, pswd_half: bytes) -> bytes:
        ''' adds an even parity bit to the password '''
        p = DESCore._bytes_to_bit_array(pswd_half)
        pswd_list = [i for i in DESCore._nsplit(p, 7)]
        for p in pswd_list:
            if p.count(1) % 2 == 0:
                p += [0]
            else:
                p += [1]
        
        return b''.join([DESCore._bit_array_to_bytes(p) for p in pswd_list])


p1 = b"\xCE\x23\x90\xAA\x22\x35\x60\xBB\xE9\x17\xF8\xD6\xFA\x47\x2D\x2C"
p2 = b"D3CC6BB953241B61EFB303C2F126705E"
p3 = b"6F3989F97ADB6701C2676C7231D0B1B5"

testp = b'password'

lmhc = lmh_cracker()
# lmhc.brute_force(p1, 'common_pswd.txt')
# print(lmhc.l_rem_x(b'\x00\x13'))
# print(lmhc.l_rem_x(lmhc.encrypt(testp)))


# think of stopwatching it when found a word
# 'pad' with numbers at the end of the dict word for tallman's
# use a while loop to count up starting at 0, maybe set a max of around 5 digits in total
# for bozo, repeat above but with common character replacements

def crack(pswd: str):
    cp_list = read_common_pswd('common_pswd.txt')
    lm_const = b"KGS!@#$%"
    pswd = pswd.upper().encode()
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
    subkeys = DESCore._generate_subkeys(key)
    plaintext = DESCore._bytes_to_bit_array(data)

    ciphertext = DESCore._crypt_block(plaintext, subkeys)

    ciphertext = DESCore._bit_array_to_bytes(ciphertext)

    return ciphertext

def addparity(p: bytes) -> bytes:
    p = DESCore._bytes_to_bit_array(p)
    p_array = [c for c in DESCore._nsplit(p, 7)]
    for element in p_array:
        element += [0]

    return b''.join([DESCore._bit_array_to_bytes(p) for p in p_array])

def read_common_pswd(filename: str) -> list:
    if filename == None:
        return
    cp = ''
    with open(filename, 'r') as f:
        cp = f.read()
    cp = cp.split('\n')
    cp = [p.encode() for p in cp]
    return cp

test = crack('password')

print(test.hex())
