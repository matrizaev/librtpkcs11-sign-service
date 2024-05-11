"""
Signs the input using the specified user PIN and key pair ID.
"""

from ctypes import CDLL, Structure, c_char_p, c_size_t
from typing import Any


class TByteArray(Structure):
    _fields_ = [("length", c_size_t), ("data", c_char_p)]


def perform_signing(input_data: bytes, user_pin: bytes, key_pair_id: bytes) -> TByteArray:
    """
    Signs the input using the specified user PIN and key pair ID.
    """
    lib = CDLL("./librtpkcs11sign/librtpkcs11sign.so")
    lib.perform_signing.restype = TByteArray
    lib.perform_signing.argtypes = [TByteArray, c_char_p, c_char_p]
    input_struct = TByteArray(len(input_data), input_data)
    result: TByteArray = lib.perform_signing(input_struct, user_pin, key_pair_id)
    return result
