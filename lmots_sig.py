from utils import u32str, hex_u32_to_int, serialize_array
from print_util import PrintUtl
from lmots_type import LmotsType


class LmotsSignature:
    """
    Leighton-Micali One Time Signature
    """
    def __init__(self, c, y, lmots_type=LmotsType.LMOTS_SHA256_M32_W8):
        if not isinstance(lmots_type, LmotsType):
            raise ValueError("lmots_type must be of type LmotsType")

        self.c = c
        self.y = y
        self.lmots_type = lmots_type

    def print_hex(self):
        PrintUtl.print_line()
        print "LMOTS signature"
        PrintUtl.print_hex("LMOTS type", u32str(self.lmots_type.type_code), self.lmots_type.name)
        PrintUtl.print_hex("C", self.c)
        for i, e in enumerate(self.y):
            PrintUtl.print_hex("y[" + str(i) + "]", e)
        PrintUtl.print_line()
