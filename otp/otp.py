#!/usr/bin/env python
# encoding: utf-8

"""
   @author: Joshua Tallman
  @license: MIT Licence
  @contact: joshua.tallman@cui.edu
     @file: otp.py
     @time: 2030-06-05 12:03
"""

# For encrypting and decrypting text with a One Time Pad.


def bytes_to_bit_array(byte_string):
    """ Converts a string of bytes to a series of binary digits
    """
    bit_count = len(byte_string) * 8
    result = []
    for byte in byte_string:
        for bit_pos in [7, 6, 5, 4, 3, 2, 1, 0]:
            if byte & (1 << bit_pos) > 0:
                result.append(1)
            else:
                result.append(0)
    return result


# ChatGPT's pythonic code
def _bytes_to_bit_array_chatgpt(byte_string):
    bit_list = []
    for byte in byte_string:
        bits = f'{byte:08b}'
        bit_list.extend([int(bit) for bit in bits])
    return bit_list


def bit_array_to_bytes(bit_array):
    """ Converts a series of binary digits to a string of bytes
    """
    if len(bit_array) % 8 != 0:
        raise ValueError("Length of bit_array must be a multiple of 8.")
    result = []
    byte = 0
    for pos in range(len(bit_array)):
        byte += bit_array[pos] << (7 - (pos % 8))
        if (pos % 8) == 7:
            result += [byte]
            byte = 0
    return bytes(result)


# ChatGPT's pythonic version
def _bit_array_to_bytes_chatgpt(bit_array):
    if len(bit_array) % 8 != 0:
        raise ValueError("Length of bit_array must be a multiple of 8.")
    byte_string = bytearray()
    for i in range(0, len(bit_array), 8):
        byte_str = ''.join(str(bit) for bit in bit_array[i:i+8])
        byte = int(byte_str, 2)
        byte_string.append(byte)
    return bytes(byte_string)


def crypt(data, key):
    """ Performs One Time Pad encryption/decryption by XORing two byte 
        strings together
    """
    bit_array = bytes_to_bit_array(data)
    key_array = bytes_to_bit_array(key)

    # the operation is the same for encryption or decryption
    paired  = [(d,k) for d,k in zip(bit_array,key_array)]
    crypted = [d^k for d,k in paired]

    crypted = bit_array_to_bytes(crypted)
    return crypted
    