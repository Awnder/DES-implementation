import des_constants_permutation_tables as permutation_tables
import des_constants_sbox_tables as sbox_tables
import des_constants_subkey_tables as subkey_tables
import des_tests_subkey as subkey_test

def _add_padding(message):
    ''' Returns the message with extra padding (ie: 2 bytes w padding -> \x02\x02).
        used tallman's code
    '''
    pad_length = 8 - len(message) % 8
    return message + (chr(pad_length) * pad_length).encode("utf-8")

def _rem_padding(message):
    ''' Returns the message and removes extra padding '''
    last = message[-1]
    return (message[:-last])

def _bytes_to_bit_array(byte_string):
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

def _bit_array_to_bytes(bit_array):
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

def _nsplit(data, split_size=64):
    ''' Splits data into a list where each len(element) == split_size.
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

def _generate_subkeys(key):
    ''' Generates 16 subkeys from a 64 bit key. Used gpt-4o to write '''
    key = _bytes_to_bit_array(key)
    
    # permutes 64 bit key into 56bits
    permuted_key = _permute(key, subkey_tables._KEY_PERMUTATION1)
    
    # Split into C and D
    C = permuted_key[:28]
    D = permuted_key[28:]
    
    subkeys = []
    for shift in subkey_tables._KEY_SHIFT: # shifts to randomize new key
        # Left shift C and D
        C = C[shift:] + C[:shift]
        D = D[shift:] + D[:shift]
        
        # permutes 56 key into 48 bit subkeys
        subkey = _permute(C+D, subkey_tables._KEY_PERMUTATION2)
        subkeys.append(subkey)
    
    return subkeys

def _permute(block, table):
    return [block[i-1] for i in table] # need to i-1 as permutation keys are 1-indexed right now

def _lshift(sequence: list, n: int):
    sequence = sequence[n:] + sequence[:n]
    return sequence

def _xor(x: list, y: list):
    return [a^b for a,b in zip(x,y)]

def _feistel_round(L, R, subkey):
    ''' XORs the Left 32bits and Right 32bits together after permuting the right side. Used gpt-4o to write '''
    newL = R
    newR = [l ^ p for l, p in zip(L, _permute(R, subkey))]
    return newL, newR

def _encrypt_block(block, subkeys):
    ''' Used gpt-4o to generate permutation tables and give advice on how to structure loop '''
    # split 64 bit block into 32 bit halves
    L = block[:len(block)//2]
    R = block[len(block)//2:]

    block = _permute(block, permutation_tables._INIT_PERMUTATION)
    
    for i in range(16):
      L, R = _feistel_round(L, R, subkeys[i])

    block = R + L # combine halves for ciphertext
       
    block = _permute(block, permutation_tables._FINAL_PERMUTATION)

    return block

def encrypt(data, key):
    
    """ Encrypts plaintext data with DES (Data Encryption Standard).

        Parameters:
          data (bytes): input data to be encrypted
          key (bytes):  64-bit key used for DES encryption

        Returns:
          An encrypted byte string of equal length to the original data
    """
    subkeys = _generate_subkeys(key)
    plaintext = _add_padding(data)
    plaintext = _bytes_to_bit_array(plaintext)
    ciphertext = []
    for block in _nsplit(plaintext, 64):
      ciphertext += _encrypt_block(block, subkeys)
    ciphertext = _bit_array_to_bytes(ciphertext)
    return ciphertext

def run_unit_tests():
    """ Runs unit tests for each function in this module. Prints 'ALL UNIT
        TESTS PASSED' if all of the unit tests were successful. Raises an
        AssertionError if any single unit test fails. """

    try:
      t1 = _add_padding(b'CSC428')
      t2 = _add_padding(b'TALLMAN')
      t3 = _add_padding(b'JTALLMAN')
      t4 = _rem_padding(b'CSC428\x02\x02')
      t5 = _rem_padding(b'TALLMAN\x01')
      t6 = _rem_padding(b'JTALLMAN\x08\x08\x08\x08\x08\x08\x08\x08')
      t7 = _bytes_to_bit_array(b'\x00')
      t8 = _bytes_to_bit_array(b'\xA5')
      t9 = _bytes_to_bit_array(b'\xFF')
      t10 = _bit_array_to_bytes([0,0,0,0,0,0,0,0])
      t11 = _bit_array_to_bytes([1,0,1,0,0,1,0,1])
      t12 = _bit_array_to_bytes([1,1,1,1,1,1,1,1])
      t13 = _nsplit(b'1111222233334444',4)
      t13 = [t for t in t13]
      t14 = _nsplit(b'ABCDEFGHIJKLMN', 3)
      t14 = [t for t in t14]
      t15 = _nsplit(b'THE CODE BOOK BY SINGH', 5)
      t15 = [t for t in t15]
      t16 = _xor(b'1111', b'0101')
      print('xor:',t16)
      t17 = _lshift([1,0,1,1], 1)
      print('lshift:',t17)
      t17 = _lshift(t17, 1)
      print('lshift:',t17)

      assert t1 == b'CSC428\x02\x02', "Unit test #1 failed: _add_padding(b'CSC428')"
      assert t2 == b'TALLMAN\x01', 'failed t2'
      assert t3 == b'JTALLMAN\x08\x08\x08\x08\x08\x08\x08\x08', 'failed t3'
      assert t4 == b'CSC428', 'failed t4'
      assert t5 == b'TALLMAN', 'failed t5'
      assert t6 == b'JTALLMAN', 'failed t6'
      assert t7 == [0,0,0,0,0,0,0,0], 'failed t7'
      assert t8 == [1,0,1,0,0,1,0,1], 'failed t8'
      assert t9 == [1,1,1,1,1,1,1,1], 'failed t9'
      assert t10 == b'\x00', 'failed 10'
      assert t11 == b'\xA5', 'failed 11'
      assert t12 == b'\xFF', 'failed 12'
      assert t13 == [b'1111', b'2222', b'3333', b'4444']
      assert t14 == [b'ABC', b'DEF', b'GHI', b'JKL', b'MN']
      assert t15 == [b'THE C', b'ODE B', b'OOK B', b'Y SIN', b'GH']

      _hex_print([1,1,1,1,0,1,0,1,0,0,0,0,1,0,1,0,1,0,0,1,0,1,1,0,1,1,0,1,1,0,1,1]) #b'F50A96DB'
      _hex_print([1,0,1,0,1,0,1,1,1,1,0,0,1,1,0,1,1,1,1,0,1,1,1,1,0,0,0,0,0,0,0,0]) #b'ABCDFF00'
      _hex_print([0,0,0,1,0,0,1,0,0,0,1,1,0,1,0,0,0,1,0,1,0,1,1,0,0,1,1,1,1,0,0,0]) #b'12345678'

      plaint = b'1234567890'
      key = b'abdefgh'
      ciphert = encrypt(plaint,key)
      print(ciphert)
    except:
      raise AssertionError

run_unit_tests()