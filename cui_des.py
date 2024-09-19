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
    split_data = []
    for i in range(0, len(data), split_size):
      split_data.append(data[i:i+split_size])
    return split_data

def _hex_print(block, length=16):
    ''' gets a list of binary digits and prints the hex representation, used tallman's code '''
    s = [str(i) for i in block]
    binary = int(''.join(s),2)
    print(hex(binary)[2:].zfill(length)) #pad length

def _generate_subkeys(key):
    ''' Generates 16 subkeys from a 64 bit key. Used gpt-4o to write '''
    permute_56bit = [
      56, 48, 40, 32, 24, 16, 8,
      1, 55, 47, 39, 31, 23, 15,
      7, 2, 54, 46, 38, 30, 22,
      14, 6, 3, 53, 45, 37, 29,
      52, 44, 36, 28, 20, 12, 4,
      5, 51, 43, 35, 27, 19, 11,
      3, 6, 50, 42, 34, 26, 18,
      10, 13, 5, 25, 17, 9, 4
    ]

    permute_48bit = [
      14, 17, 11, 24,  1,  5,  3, 28,
      15,  6, 21, 10, 23, 19, 12,  4,
      26,  8, 16,  7, 27, 20, 13,  2,
      41,  32, 31, 37, 47, 30, 40, 38,
      33, 45, 34, 48, 36, 29, 39, 42,
      35, 44, 46, 43, 39,  36, 29, 32
    ]

    # Number of left shifts per round
    SHIFT_SCHEDULE = [
      1, 1, 2, 2, 2, 2, 2, 2,
      1, 2, 2, 2, 2, 2, 2, 1
    ]

    key = _bytes_to_bit_array(key)
    
    # permutes 64 bit key into 56bits
    permuted_key = _permute(key, permute_56bit)
    
    # Split into C and D
    C = permuted_key[:28]
    D = permuted_key[28:]
    
    subkeys = []
    for shift in SHIFT_SCHEDULE: # shifts to randomize new key
        # Left shift C and D
        C = C[shift:] + C[:shift]
        D = D[shift:] + D[:shift]
        
        # permutes 56 key into 48 bit subkeys
        subkey = _permute(C+D, permute_48bit)
        subkeys.append(subkey)
    
    return subkeys

def _permute(block, table):
    return [block[i-1] for i in table] # need to i-1 as permutation keys are 1-indexed

def _feistel_round(L, R, subkey):
    ''' XORs the Left 32bits and Right 32bits together after permuting the right side. Used gpt-4o to write '''
    newL = R
    newR = [l ^ p for l, p in zip(L, _permute(R, subkey))]
    return newL, newR

def _encrypt_block(block, subkeys):
    ''' Used gpt-4o to generate permutation tables and give advice on how to structure loop '''
    _INIT_PERMUTATION = [
      58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7
    ]
    _FINAL_PERMUTATION = [
      40, 8, 48, 16, 56, 24, 64, 32,
      39, 7, 47, 15, 55, 23, 63, 31,
      38, 6, 46, 14, 54, 22, 62, 30,
      37, 5, 45, 13, 53, 21, 61, 29,
      36, 4, 44, 12, 52, 20, 60, 28,
      35, 3, 43, 11, 51, 19, 59, 27,
      34, 2, 42, 10, 50, 18, 58, 26,
      33, 1, 41, 9, 49, 17, 57, 25
    ]

    # split 64 bit block into 32 bit halves
    L = block[:len(block)//2]
    R = block[len(block)//2:]

    block = _permute(block, _INIT_PERMUTATION)
    
    for i in range(16):
      L, R = _feistel_round(L, R, subkeys[i])

    block = R + L # combine halves for ciphertext
       
    block = _permute(block, _FINAL_PERMUTATION)

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
      t14 = _nsplit(b'ABCDEFGHIJKLMN', 3)
      t15 = _nsplit(b'THE CODE BOOK BY SINGH', 5)

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