
from utils import u32str, hex_u32_to_int, serialize_array
from print_util import PrintUtl
from lmots import LmotsType


class LmotsSignature:
    """
    Leighton-Micali One Time Signature
    """
    def __init__(self, C, y, lmots_type=LmotsType.LMOTS_SHA256_N32_W8):
        self.C = C
        self.y = y
        self.lmots_type = lmots_type

    def serialize(self):
        return u32str(self.lmots_type.type_code) + self.C + serialize_array(self.y)

    @classmethod
    def deserialize(cls, hex_value):
        # extract the type code value that identifies the LMOTS algorithm used in the signature
        sig_type_code = hex_u32_to_int(hex_value[0:4])
        lmots_type = LmotsType.get_by_type_code(sig_type_code)

        if len(hex_value) != cls.bytes(lmots_type):
            raise ValueError("hex_value is wrong length")
        C = hex_value[4:lmots_type.n + 4]
        y = list()
        pos = lmots_type.n + 4
        for i in xrange(0, lmots_type.p):
            y.append(hex_value[pos:pos + lmots_type.n])
            pos = pos + lmots_type.n
        return cls(C, y, lmots_type)

    @classmethod
    def bytes(cls, lmots_type):
        return 4 + lmots_type.n * (lmots_type.p + 1)

    def print_hex(self):
        PrintUtl.print_line()
        print "LMOTS signature"
        PrintUtl.print_hex("LMOTS type", u32str(self.lmots_type.type_code), self.lmots_type.name)
        PrintUtl.print_hex("C", self.C)
        for i, e in enumerate(self.y):
            PrintUtl.print_hex("y[" + str(i) + "]", e)
        PrintUtl.print_line()
