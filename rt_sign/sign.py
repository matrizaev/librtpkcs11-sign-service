"""
Signs the input using the specified user PIN and key pair ID.
"""

from ctypes import CDLL, POINTER, byref, c_char_p, c_size_t


def perform_signing(input_data: bytes, user_pin: bytes, key_pair_id: bytes) -> tuple[bytes, int]:
    """
    Signs the input using the specified user PIN and key pair ID.
    """
    lib = CDLL("./librtpks11sign/librtpks11sign.so")
    lib.perform_signing.perform_signing = c_char_p
    lib.perform_signing.argtypes = [c_char_p, c_size_t, POINTER(c_size_t), c_char_p, c_size_t, c_char_p, c_size_t]
    output_size = c_size_t()
    result: bytes = lib.perform_signing(
        input_data, len(input_data), byref(output_size), user_pin, len(user_pin), key_pair_id, len(key_pair_id)
    )
    return result, output_size.value
