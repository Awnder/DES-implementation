# used tallman's code 
def _add_padding(message):
    ''' Returns the message with extra padding (ie: 2 bytes w padding -> \x02\x02) '''
    pad_length = 8 - len(message) % 8
    return message + (chr(pad_length) * pad_length).encode("utf-8")

def _rem_padding(message):
    ''' Returns the message and removes extra padding '''
    last = message[-1]
    return (message[:-last])

# used tallman's code
def _bytes_to_bit_array(byte_string):
    result = []
    for byte in byte_string:
        for bit in [7,6,5,4,3,2,1,0]:
            mask = 1 << bit           # left shift
            if byte & mask > 0:       # AND together
              result.append(1)
            else:
              result.append(0)
    return result

# used tallman's code
def _bit_array_to_bytes(bit_array):
    result = []
    byte = 0
    for bit in range(len(bit_array)):
        byte += bit_array[bit] << (7 - (bit % 8))
        if (byte % 8) == 7:
          result += [byte]
          byte = 0
    return bytes(result)

def _nsplit(data, split_size=64):
    ''' splits data into a list where each len(element) == split_size
        the last element does not necessarily have the max amount of characters 
    '''
    split_data = []
    for i in range(0, len(data), split_size):
      split_data.append(data[i:i+split_size])
    return split_data

# used tallman's code
def _hex_print(block, length=16):
    ''' gets a list of binary digits and prints the hex representation '''
    s = [str(i) for i in block]
    binary = int(''.join(s),2)
    print(hex(binary)[2:].zfill(length)) #pad length
    return

def _encrypt_block(plaintext, subkeys):
    block = _permute(block, _INIT_PERMUTATION)
    
    for i in range(len(16)):
       
    block = _permute(block, _FINAL_PERMUTATION)

    return block
def encrypt(data, key):
    return
    """ Encrypts plaintext data with DES (Data Encryption Standard).

        Parameters:
          data (bytes): input data to be encrypted
          key (bytes):  64-bit key used for DES encryption

        Returns:
          An encrypted byte string of equal length to the original data
    """
    pt = _add_padding(data)
    pt = _bytes_to_bit_array(pt)
    ct = []
    for block in _nsplit(pt, 64):
      ct += _encrypt_block(block, key)
    ct = _bit_array_to_bytes(ct)
    return ct


def run_unit_tests():
    """ Runs unit tests for each function in this module. Prints 'ALL UNIT
        TESTS PASSED' if all of the unit tests were successful. Raises an
        AssertionError if any single unit test fails. """

    try:
      test1_result1 = _add_padding(b'CSC428')
      assert test1_result1 == b'CSC428\x02\x02', "Unit test #1 failed: _add_padding(b'CSC428')"
    except:
      raise AssertionError
