
### tables
# 32-bit to 48-bit
_EXPAND = [31,  0,  1,  2,  3,  4,  3,  4,
            5,  6,  7,  8,  7,  8,  9, 10,
           11, 12, 11, 12, 13, 14, 15, 16,
           15, 16, 17, 18, 19, 20, 19, 20,
           21, 22, 23, 24, 23, 24, 25, 26,
           27, 28, 27, 28, 29, 30, 31,  0]

# 32-bit permutation after S-BOX substitution
_SBOX_PERM = [15,  6, 19, 20, 28, 11, 27, 16,
               0, 14, 22, 25,  4, 17, 30,  9,
               1,  7, 23, 13, 31, 26,  2,  8,
              18, 12, 29,  5, 21, 10,  3, 24]

# Initial permutation on incoming block
_INIT_PERMUTATION = [57, 49, 41, 33, 25, 17,  9, 1,
                     59, 51, 43, 35, 27, 19, 11, 3,
                     61, 53, 45, 37, 29, 21, 13, 5,
                     63, 55, 47, 39, 31, 23, 15, 7,
                     56, 48, 40, 32, 24, 16,  8, 0,
                     58, 50, 42, 34, 26, 18, 10, 2,
                     60, 52, 44, 36, 28, 20, 12, 4,
                     62, 54, 46, 38, 30, 22, 14, 6]

# Inverse of _INITIAL_PERMUTATION
_FINAL_PERMUTATION = [39,  7, 47, 15, 55, 23, 63, 31,
                      38,  6, 46, 14, 54, 22, 62, 30,
                      37,  5, 45, 13, 53, 21, 61, 29,
                      36,  4, 44, 12, 52, 20, 60, 28,
                      35,  3, 43, 11, 51, 19, 59, 27,
                      34,  2, 42, 10, 50, 18, 58, 26,
                      33,  1, 41,  9, 49, 17, 57, 25,
                      32,  0, 40,  8, 48, 16, 56, 24]

# 64-bit to 56-bit permutation on the key
_KEY_PERMUTATION1 = [56, 48, 40, 32, 24, 16,  8,  0, 
                     57, 49, 41, 33, 25, 17,  9,  1,
                     58, 50, 42, 34, 26, 18, 10,  2, 
                     59, 51, 43, 35, 62, 54, 46, 38, 
                     30, 22, 14,  6, 61, 53, 45, 37,
                     29, 21, 13,  5, 60, 52, 44, 36,
                     28, 20, 12,  4, 27, 19, 11,  3]

# 56-bit to 48-bit permutation on the key
_KEY_PERMUTATION2 = [13, 16, 10, 23,  0,  4,  2, 27,
                     14,  5, 20,  9, 22, 18, 11,  3, 
                     25,  7, 15,  6, 26, 19, 12,  1,
                     40, 51, 30, 36, 46, 54, 29, 39, 
                     50, 44, 32, 47, 43, 48, 38, 55, 
                     33, 52, 45, 41, 49, 35, 28, 31]

# Matrix that determines the shift for each round of keys
_KEY_SHIFT = [ 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

_S_BOXES = [
    [[14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7],
     [ 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8],
     [ 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0],
     [15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13],
    ],
    [[15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10],
     [ 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5],
     [ 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15],
     [13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9],
    ],
    [[10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8],
     [13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1],
     [13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7],
     [ 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12],
    ],
    [[ 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15],
     [13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9],
     [10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4],
     [ 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14],
    ],
    [[ 2, 12,  4,  1,  7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
     [14, 11,  2, 12,  4,  7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
     [ 4,  2,  1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
     [11,  8, 12,  7,  1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    ],
    [[12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11],
     [10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8],
     [ 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6],
     [ 4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13],
    ],
    [[ 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1],
     [13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6],
     [ 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2],
     [ 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12],
    ],
    [[13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7],
     [ 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2],
     [ 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8],
     [ 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11],
    ]
]

subkey_input = b"\xEF\x00\xEF\x00\xFF\x80\xFF\x80"
subkey_result = [ [0,1,1,0,1,1,1,1,1,0,1,0,1,1,0,0,0,0,0,1,1,0,1,1,
                   1,0,1,1,1,0,0,0,1,1,1,0,0,1,1,0,0,0,0,0,0,0,1,0],
                  [1,0,0,1,1,0,0,1,0,1,0,1,0,0,1,1,1,1,1,0,1,1,0,1,
                   0,0,0,0,0,0,1,1,0,0,0,1,1,0,0,1,1,0,1,1,1,1,0,1],
                  [1,0,0,1,0,0,0,1,0,1,0,1,0,0,1,1,1,1,1,0,1,1,0,1,
                   0,0,0,0,0,0,1,1,0,0,0,1,1,0,0,1,1,0,1,1,0,1,0,1],
                  [1,0,0,1,0,0,0,1,0,1,0,1,1,0,1,1,1,1,1,0,0,1,0,1,
                   0,1,0,0,0,0,1,1,0,0,0,0,1,0,0,1,1,0,1,1,0,1,0,1],
                  [1,0,0,1,0,0,0,1,0,1,1,1,1,0,1,1,1,1,1,0,0,1,0,1,
                   0,1,0,0,0,0,1,1,0,0,0,0,1,0,0,1,1,0,0,1,1,1,0,1],
                  [1,0,0,1,0,0,0,1,0,1,1,1,0,1,1,1,1,1,1,0,0,1,0,1,
                   0,1,0,0,0,0,1,1,0,0,0,1,0,0,0,1,1,0,0,1,1,1,0,1],
                  [1,1,0,1,0,0,0,1,0,1,0,1,0,1,1,1,1,1,1,0,0,1,0,1,
                   0,1,0,0,0,0,1,1,0,0,0,1,0,0,0,1,1,0,1,0,1,1,0,1],
                  [1,1,0,1,0,0,0,1,1,1,0,1,0,0,1,1,1,1,1,0,0,1,0,1,
                   0,1,0,0,0,0,1,0,0,0,0,1,1,0,0,1,1,0,1,0,1,1,0,1],
                  [1,1,1,0,1,1,1,0,1,0,1,0,1,1,0,0,0,0,1,1,1,0,1,0,
                   0,0,1,1,1,1,0,0,1,1,1,0,0,1,0,0,0,1,0,0,0,0,1,0],
                  [1,1,1,0,1,1,1,0,1,0,1,0,1,1,1,0,0,0,0,1,1,0,1,0,
                   1,0,1,0,1,1,0,0,1,1,1,0,0,1,0,0,0,1,0,0,0,0,1,0],
                  [0,1,1,0,1,1,1,0,1,0,1,1,1,1,1,0,0,0,0,1,1,0,1,0,
                   1,0,1,0,1,1,0,0,1,1,1,0,0,1,1,0,0,1,0,0,0,0,1,0],
                  [0,1,1,0,1,1,1,0,1,0,1,1,1,1,0,0,0,1,0,1,1,0,1,0,
                   1,0,1,1,1,1,0,0,1,1,0,0,0,1,1,0,0,1,0,0,0,0,1,0],
                  [0,1,1,0,1,1,1,0,1,1,1,0,1,1,0,0,0,1,0,1,1,0,1,0,
                   1,0,0,1,1,1,0,0,1,1,0,0,0,1,1,0,0,1,0,0,0,0,1,0],
                  [0,1,1,0,1,1,1,0,1,1,1,0,1,1,0,1,0,0,0,1,1,0,1,0,
                   1,0,0,1,1,1,0,0,1,1,1,0,0,1,1,0,0,1,0,0,0,0,0,0],
                  [0,1,1,0,1,1,1,0,1,0,1,0,1,1,0,1,0,0,0,1,1,0,1,1,
                   1,0,1,1,1,0,0,0,1,1,1,0,0,1,1,0,0,1,0,0,0,0,0,0],
                  [1,0,0,1,1,0,1,1,0,1,0,1,0,0,1,1,1,1,1,0,0,1,0,1,
                   0,1,0,0,0,0,1,1,0,0,0,1,1,0,0,0,1,0,1,1,1,1,0,1] ]

from typing import Generator

class DESCore:
  def __init__(self, mode='ECB', iv='\x00\x00\x00\x00\x00\x00\x00\x00'):
    ''' mode can be ECB, CBC, or OFB 
        iv must be 8 hex in length
    '''
    self.mode = mode
    self.iv = iv
    self._iv = iv

  def resetIV(self):
    self._iv = self.iv

  def encrypt(self, data: bytes, key: bytes) -> bytes:
    """ Encrypts plaintext data with DES (Data Encryption Standard).

        Parameters:
          data (bytes): input data to be encrypted
          key (bytes):  64-bit key used for DES encryption

        Returns:
          An encrypted byte string of equal length to the original data, encrypted by specific DES mode
    """
    subkeys = DESCore._generate_subkeys(key)

    plaintext = data
    if self.mode == 'ECB' or self.mode == 'CBC':
      plaintext = DESCore._add_padding(data)

    plaintext = DESCore._bytes_to_bit_array(plaintext)

    ciphertext = []
    for p in DESCore._nsplit(plaintext, 64):
      if self.mode == 'ECB':
        result = DESCore._crypt_block(p, subkeys)
        ciphertext += result

      if self.mode == 'CBC':
        p = DESCore._xor(p, self._iv)
        result = DESCore._crypt_block(p, subkeys)
        self._iv = result
        ciphertext += result

      if self.mode == 'OFB':
        result = DESCore._crypt_block(self._iv, subkeys)
        self._iv = result
        ciphertext += DESCore._xor(p, result)


    ciphertext = DESCore._bit_array_to_bytes(ciphertext)

    return ciphertext
        
  def decrypt(self, data: bytes, key: bytes) -> bytes:
    """ Decrypts ciphertext data with DES (Data Encryption Standard).

        Parameters:
          data (bytes): input data to be decrypted
          key (bytes):  64-bit key used for DES decryption

        Returns:
          An decrypted byte string of equal length to the original data, decrypted by specific DES mode
    """
    if self.mode == 'ECB' or self.mode == 'CBC':
      subkeys = list(reversed(DESCore._generate_subkeys(key)))
    else:
      subkeys = DESCore._generate_subkeys(key)

    if self.mode == 'OFB': # b/c using _iv in crypt, need to be a bit list
      self._iv = DESCore._bytes_to_bit_array(self._iv) 

    ciphertext = DESCore._bytes_to_bit_array(data)

    plaintext = []
    for c in DESCore._nsplit(ciphertext, 64):
      if self.mode == 'ECB':
        result = DESCore._crypt_block(c, subkeys)
        plaintext += result

      if self.mode == 'CBC':
        result = DESCore._crypt_block(c, subkeys)
        plaintext += DESCore._xor(self._iv, result)
        self._iv = c

      if self.mode == 'OFB':
        result = DESCore._crypt_block(self._iv, subkeys)
        self._iv = result
        plaintext += DESCore._xor(c, result)

    plaintext = DESCore._bit_array_to_bytes(plaintext)

    if self.mode == 'ECB' or self.mode == 'CBC':
      plaintext = DESCore._rem_padding(plaintext)

    return plaintext

class TDES:
  def __init__(self, mode='ECB', iv='\x00\x00\x00\x00\x00\x00\x00\x00'):
    ''' mode can be ECB, CBC, or OFB. iv must be 8 hex in length '''
    self.mode = mode
    self.iv = iv
    self._iv = iv

  def resetIV(self):
    self._iv = self.iv

  def encrypt(self, data: bytes, key: bytes) -> bytes:
    """ Encrypts plaintext data with DES (Data Encryption Standard).

        Parameters:
          data (bytes): input data to be encrypted
          key (bytes):  192-bit key used for DES encryption

        Returns:
          An encrypted byte string of equal length to the original data, encrypted by specific DES mode
    """
    subkeys1 = DESCore._generate_subkeys(key1)
    subkeys2 = list(reversed(DESCore._generate_subkeys(key2)))
    subkeys3 = DESCore._generate_subkeys(key3)

    plaintext = data
    if self.mode == 'ECB' or self.mode == 'CBC':
      plaintext = DESCore._add_padding(data)

    plaintext = DESCore._bytes_to_bit_array(plaintext)

    ciphertext = []
    for p in DESCore._nsplit(plaintext, 64):
      if self.mode == 'ECB':
        result = DESCore._crypt_block(p, subkeys)
        result = DESCore._crypt_block(result, subkeys)
        ciphertext += result

      if self.mode == 'CBC':
        p = DESCore._xor(p, self._iv)
        result = DESCore._crypt_block(p, subkeys)
        self._iv = result
        ciphertext += result

      if self.mode == 'OFB':
        result = DESCore._crypt_block(self._iv, subkeys)
        self._iv = result
        ciphertext += DESCore._xor(p, result)


    ciphertext = DESCore._bit_array_to_bytes(ciphertext)

    return ciphertext
        
  def decrypt(self, data: bytes, key: bytes) -> bytes:
    """ Decrypts ciphertext data with DES (Data Encryption Standard).

        Parameters:
          data (bytes): input data to be decrypted
          key (bytes):  64-bit key used for DES decryption

        Returns:
          An decrypted byte string of equal length to the original data, decrypted by specific DES mode
    """
    if self.mode == 'ECB' or self.mode == 'CBC':
      subkeys = list(reversed(DESCore._generate_subkeys(key)))
    else:
      subkeys = DESCore._generate_subkeys(key)

    if self.mode == 'OFB': # b/c using _iv in crypt, need to be a bit list
      self._iv = DESCore._bytes_to_bit_array(self._iv) 

    ciphertext = DESCore._bytes_to_bit_array(data)

    plaintext = []
    for c in DESCore._nsplit(ciphertext, 64):
      if self.mode == 'ECB':
        result = DESCore._crypt_block(c, subkeys)
        plaintext += result

      if self.mode == 'CBC':
        result = DESCore._crypt_block(c, subkeys)
        plaintext += DESCore._xor(self._iv, result)
        self._iv = c

      if self.mode == 'OFB':
        result = DESCore._crypt_block(self._iv, subkeys)
        self._iv = result
        plaintext += DESCore._xor(c, result)

    plaintext = DESCore._bit_array_to_bytes(plaintext)

    if self.mode == 'ECB' or self.mode == 'CBC':
      plaintext = DESCore._rem_padding(plaintext)

    return plaintext

class DESCore:
  def _crypt_block(block: list, subkeys: list) -> bytes:
    ''' block: list - 64 bits, subkeys: list of 16 bit lists 
        encrypts one block of 64 bit text
    '''
    # rewrote in class with prof tallman
    block = DESCore._permute(block, _INIT_PERMUTATION)

    # split 64 bit block into 32 bit halves
    L = block[:32]
    R = block[32:]
    
    for i in range(16):
      temp = DESCore._func_f(R, subkeys[i])
      temp = DESCore._xor(temp, L)
      # change L to R and R to modified R
      L = R
      R = temp
    
    # need to do one final swap of L and R for the algorithm
    block = DESCore._permute(R+L, _FINAL_PERMUTATION)

    return block
  
  def _add_padding(message: str) -> list:
    ''' Returns the message with extra padding (ie: 2 bytes w padding -> \x02\x02).
        used tallman's code
    '''
    pad_length = 8 - len(message) % 8
    return message + (chr(pad_length) * pad_length).encode("utf-8")

  def _rem_padding(message: bytes) -> bytes:
    ''' Returns the message and removes extra padding '''
    last = message[-1]
    return (message[:-last])

  def _bytes_to_bit_array(byte_string: bytes) -> list:
    ''' converts a byte string to bit array. used tallman's code '''
    result = []
    for byte in byte_string:
        for bit in [7,6,5,4,3,2,1,0]:
            mask = 1 << bit           # left shift
            if byte & mask > 0:       # AND together
              result.append(1)
            else:
              result.append(0)
    return result

  def _bit_array_to_bytes(bit_array: list) -> bytes:
    ''' converts bit array to a byte string. used tallman's code and edited using gpt-4o as bit length was off '''
    result = []
    byte = 0
    for i,bit in enumerate(bit_array):
      byte = (byte << 1) | bit
      # byte += bit_array[bit] << (7 - (bit % 8))
      if (i+1) % 8 == 0:
        result.append(byte)
        byte = 0
    if len(bit_array) % 8 != 0:
      byte = byte << (8 - (len(bit_array) % 8))
      result.append(byte)
    return bytes(result)

  def _nsplit(data: list, split_size: int=64) -> Generator[bytes, None, None]:
    ''' Splits data (list of bits) into a list where each len(element) == split_size.
        The last element does not necessarily have the max amount of characters 
    '''
    for i in range(0, len(data), split_size):
      stop = i+split_size
      yield data[i:stop]

  def _hex_print(block, length=16):
    ''' gets a list of binary digits and prints the hex representation, used tallman's code '''
    s = [str(i) for i in block]
    binary = int(''.join(s),2)
    print(hex(binary)[2:].zfill(length)) #pad length

  def _generate_subkeys(key: bytes) -> list:
    ''' Generates 16 subkeys from a 64 bit key. Used gpt-4o to write '''
    key = DESCore._bytes_to_bit_array(key)
    
    # permutes 64 bit key into 56bits
    permuted_key = DESCore._permute(key, _KEY_PERMUTATION1)
    
    L = permuted_key[:28]
    R = permuted_key[28:]
    
    subkeys = []
    for shift in _KEY_SHIFT: # shifts to randomize new key
        L = DESCore._lshift(L, shift)
        R = DESCore._lshift(R, shift)

        # permutes 56 key into 48 bit subkeys
        subkey = DESCore._permute(L+R, _KEY_PERMUTATION2)
        subkeys.append(subkey)
    
    return subkeys

  @staticmethod
  def _substitute(bit_array: list) -> list:
    ''' substitutes key with subkey boxes '''
    result = []
    for i in range(0, len(bit_array), 6):
      row = [bit_array[i], bit_array[i+5]] # 1st and last bit
      col = bit_array[i+1:i+5]             # middle bits

      row = int(''.join([str(i) for i in row]),2) # convert to binary
      col = int(''.join([str(i) for i in col]),2)

      sub = _S_BOXES[i//6][row][col] # getting 1 out of the 6 boxes

      sub = list(bin(sub)[2:].zfill(4)) # convert to binary, then pad
      sub = [int(s) for s in sub] # in a binary string, so convert to integer

      result += sub
    return result

  def _permute(block: list, table: list) -> list:
    return [block[i] for i in table]

  def _lshift(sequence: list, n: int) -> list:
    sequence = sequence[n:] + sequence[:n]
    return sequence

  def _xor(x: list, y: list) -> list:
    return [a^b for a,b in zip(x,y)]

  def _func_f(R: list, subkey: list) -> list:
    ''' R: list - 32 bits, subkey: list - 48 bits. Wraps DES together for the 16 loops '''
    temp = DESCore._permute(R,_EXPAND)
    temp = DESCore._xor(temp, subkey)
    temp = DESCore._substitute(temp)
    temp = DESCore._permute(temp, _SBOX_PERM)
    return temp


def run_unit_tests():
    """ Runs unit tests for each function in this module. Prints 'ALL UNIT
        TESTS PASSED' if all of the unit tests were successful. Raises an
        AssertionError if any single unit test fails. """

    try:
      t_add1 = DESCore._add_padding(b'CSC428')
      t_add2 = DESCore._add_padding(b'TALLMAN')
      t_add3 = DESCore._add_padding(b'JTALLMAN')
      t_rem1 = DESCore._rem_padding(b'CSC428\x02\x02')
      t_rem2 = DESCore._rem_padding(b'TALLMAN\x01')
      t_rem3 = DESCore._rem_padding(b'JTALLMAN\x08\x08\x08\x08\x08\x08\x08\x08')
      t_btba1 = DESCore._bytes_to_bit_array(b'\x00')
      t_btba2 = DESCore._bytes_to_bit_array(b'\xA5')
      t_btba3 = DESCore._bytes_to_bit_array(b'\xFF')
      t_batb1 = DESCore._bit_array_to_bytes([0,0,0,0,0,0,0,0])
      t_batb2 = DESCore._bit_array_to_bytes([1,0,1,0,0,1,0,1])
      t_batb3 = DESCore._bit_array_to_bytes([1,1,1,1,1,1,1,1])
      t_nsplit1 = DESCore._nsplit(b'1111222233334444',4)
      t_nsplit1 = [t for t in t_nsplit1]
      t_nsplit2 = DESCore._nsplit(b'ABCDEFGHIJKLMN', 3)
      t_nsplit2 = [t for t in t_nsplit2]
      t_nsplit3 = DESCore._nsplit(b'THE CODE BOOK BY SINGH', 5)
      t_nsplit3 = [t for t in t_nsplit3]
      t_xor = DESCore._xor(b'1111', b'0101')
      t_lshift = DESCore._lshift([1,0,1,1], 1)
      t_subst = DESCore._substitute([1,0,1,1,0,0,0,1,0,1,1,1,0,1,0,1,0,1,1,1,0,0,1,0,1,0,0,1,1,0,0,1,1,0,1,1,1,1,0,1,0,1,1,0,0,1,0,0])
      t_init_perm1 = DESCore._permute([
        "y", "0", "u", "'", "v", "3", "i", "n", "t", "3", "r", "c", "3", "p", "t", "3",
        "d", "a", "s", "u", "s", "p", "i", "c", "i", "0", "u", "s", "c", "i", "p", "h",
        "3", "r", "f", "3", "x", "t", ",", "w", "h", "i", "c", "h", "y", "0", "u", "b",
        "3", "l", "i", "3", "v", "3", "t", "0", "h", "a", "v", "3", "b", "3", "3", "n"
      ], _INIT_PERMUTATION)
      t_init_perm2 = DESCore._permute([
        "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P",
        "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", 'a', 'b', 'c', 'd', 'e', 'f',
        'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
        'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '!', '@'
      ], _INIT_PERMUTATION)
      t_final_perm = DESCore._permute([
        "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P",
        "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "0", "1", "2", "3", "4", "5",
        "6", "7", "8", "9", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l",
        "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "0", "!", "?", "*", ":", ")"
      ], _FINAL_PERMUTATION)
      t_expand_perm = DESCore._permute([
        "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P",
        "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "0", "1", "2", "3", "4", "!"
      ], _EXPAND)
      t_sbox_perm = DESCore._permute([
        "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P",
        "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "!", "1", "2", "3", "4", "5"
      ], _SBOX_PERM)
      t_subkeys = DESCore._generate_subkeys(subkey_input)

      assert t_add1 == b'CSC428\x02\x02', "failed add 1"
      assert t_add2 == b'TALLMAN\x01', 'failed add 2'
      assert t_add3 == b'JTALLMAN\x08\x08\x08\x08\x08\x08\x08\x08', 'failed add 3'
      assert t_rem1 == b'CSC428', 'failed rem 1'
      assert t_rem2 == b'TALLMAN', 'failed rem 2'
      assert t_rem3 == b'JTALLMAN', 'failed rem 3'
      assert t_btba1 == [0,0,0,0,0,0,0,0], 'failed btba 1'
      assert t_btba2 == [1,0,1,0,0,1,0,1], 'failed btba 2'
      assert t_btba3 == [1,1,1,1,1,1,1,1], 'failed btba 3'
      assert t_batb1 == b'\x00', 'failed batb 1'
      assert t_batb2 == b'\xA5', 'failed batb 2'
      assert t_batb3 == b'\xFF', 'failed batb 3'
      assert t_nsplit1 == [b'1111', b'2222', b'3333', b'4444'], 'failed nsplit 1'
      assert t_nsplit2 == [b'ABC', b'DEF', b'GHI', b'JKL', b'MN'], 'failed nsplit 2'
      assert t_nsplit3 == [b'THE C', b'ODE B', b'OOK B', b'Y SIN', b'GH'], 'failed nsplit 3'
      assert t_xor == [1,0,1,0], 'failed xor'
      assert t_lshift == [0,1,1,1], 'failed lshift'
      assert t_subst == [0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 
                         1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0], 'failed subst'
      assert t_init_perm1 == [
        "a", "l", "i", "r", "0", "a", "3", "0", "3", "3", "h", "3", "s", "u", "c", "'",
        "3", "3", "0", "t", "i", "p", "p", "3", "n", "0", "b", "w", "h", "c", "3", "n",
        "h", "3", "h", "3", "i", "d", "t", "y", "v", "i", "c", "f", "u", "s", "r", "u",
        "b", "v", "y", "x", "c", "s", "3", "v", "3", "t", "u", ",", "p", "i", "t", "i"
      ], 'failed init perm 1'
      assert t_init_perm2 == [
         '5','x','p','h','Z','R','J','B','7','z','r','j','b','T','L',
         'D','9','1','t','l','d','V','N','F','@','3','v','n','f','X',
         'P','H','4','w','o','g','Y','Q','I','A','6','y','q','i','a',
         'S','K','C','8','0','s','k','c','U','M','E','!','2','u','m',
         'e','W','O','G'
      ], 'failed init perm 2'
      assert t_final_perm == [
        "d", "H", "l", "P", "7", "X", ")", "5", "c", "G", "k", "O", "6", "W", ":", "4",
        "b", "F", "j", "N", "5", "V", "*", "3", "a", "E", "i", "M", "4", "U", "?", "2",
        "9", "D", "h", "L", "3", "T", "!", "1", "8", "C", "g", "K", "2", "S", "0", "0",
        "7", "B", "f", "J", "1", "R", "9", "Z", "6", "A", "e", "I", "0", "Q", "8", "Y"
      ], 'failed final perm'
      assert t_expand_perm == [
        "!", "A", "B", "C", "D", "E", "D", "E", "F", "G", "H", "I", "H", "I", "J", "K",
        "L", "M", "L", "M", "N", "O", "P", "Q", "P", "Q", "R", "S", "T", "U", "T", "U",
        "V", "W", "X", "Y", "X", "Y", "Z", "0", "1", "2", "1", "2", "3", "4", "!", "A"
      ], 'failed expand perm'
      assert t_sbox_perm == [
        "P", "G", "T", "U", "2", "L", "1", "Q", "A", "O", "W", "Z", "E", "R", "4", "J",
        "B", "H", "X", "N", "5", "!", "C", "I", "S", "M", "3", "F", "V", "K", "D", "Y"
      ], 'failed sbox perm'
      assert t_subkeys == subkey_result, 'failed subkeys'

      DESCore._hex_print([1,1,1,1,0,1,0,1,0,0,0,0,1,0,1,0,1,0,0,1,0,1,1,0,1,1,0,1,1,0,1,1]) # b'F50A96DB'
      DESCore._hex_print([1,0,1,0,1,0,1,1,1,1,0,0,1,1,0,1,1,1,1,0,1,1,1,1,0,0,0,0,0,0,0,0]) # b'ABCDFF00'
      DESCore._hex_print([0,0,0,1,0,0,1,0,0,0,1,1,0,1,0,0,0,1,0,1,0,1,1,0,0,1,1,1,1,0,0,0]) # b'12345678'

    except:
      raise AssertionError

if __name__ == 'main':
  run_unit_tests()
