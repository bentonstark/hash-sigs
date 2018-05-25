import binascii
import struct

from Crypto.Hash import SHA256

from need_to_sort import err_bad_length


def sha256_hash(x):
    """
    SHA256 hash function
    :param x: input that will be hashed
    :return: list of 32 bytes, hash digest
    """
    h = SHA256.new()
    h.update(x)
    return h.digest()


def u32str(x):
    """
    Integer to 4-byte string conversion
    :param x: integer that will be converted
    :return: 4-byte string representing integer
    """
    return struct.pack('>I', x)


def u16str(x):
    """
    Integer to 2-byte string conversion
    :param x: integer that will be converted
    :return: 2-byte string representing integer
    """
    return struct.pack('>H', x)


def u8str(x):
    """
    Integer to 1-byte string conversion
    :param x: integer that will be converted
    :return: 1-byte representing integer
    """
    return chr(x)


def hex_u32_to_int(hex_value):
    """
    Converts a double byte hex-encoded value to a 16-bit
    integer value.
    :param hex_value:
    :return: integer
    """
    if len(hex_value) != 4:
        raise ValueError(err_bad_length, str(len(hex_value)))
    return int(hex_value.encode('hex'), 16)


def serialize_array(array):
    result = ""
    for e in array:
        result = result + e
    return result


def string_to_hex(x):
    return binascii.hexlify(bytearray(x))
