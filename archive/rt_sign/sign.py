"""
Signs the input using the specified user PIN and key pair ID.
"""

from ctypes import CDLL, c_char_p, c_size_t, Structure
from typing import Any

class TMemoryBlock(Structure):
    _fields_ = [
        ("length", c_size_t),
        ("data", c_char_p)
    ]

def perform_signing(input_data: bytes, user_pin: bytes, key_pair_id: bytes) -> TMemoryBlock:
    """
    Signs the input using the specified user PIN and key pair ID.
    """
    lib = CDLL("./librtpkcs11sign/librtpkcs11sign.so")
    lib.perform_signing.restype = TMemoryBlock
    lib.perform_signing.argtypes = [TMemoryBlock, c_char_p, c_char_p]
    input_struct = TMemoryBlock(len(input_data), input_data)
    result: TMemoryBlock = lib.perform_signing(
        input_struct, user_pin, key_pair_id
    )
    return result
