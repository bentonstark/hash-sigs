from lmots_type import LmotsType
from utils import u32str, hex_u32_to_int
from print_util import PrintUtl


class LmotsPublicKey:
    """
    Leighton-Micali One Time Signature Public Key
    """
    def __init__(self, s, k, lmots_type):
        if not isinstance(lmots_type, LmotsType):
            raise ValueError("lmots_type must be of type LmotsType")

        self.s = s
        self.k = k
        self.lmots_type = lmots_type

    def serialize(self):
        return u32str(self.lmots_type.type_code) + self.s + self.k

    @classmethod
    def deserialize(cls, hex_value):
        sig_type_code = hex_u32_to_int(hex_value[0:4])
        lmots_type = LmotsType.get_by_type_code(sig_type_code)

        if len(hex_value) != 4 + 2 * lmots_type.n:
            raise ValueError("hex_value is wrong length")
        s = hex_value[4:4 + lmots_type.n]
        k = hex_value[4 + lmots_type.n:4 + 2 * lmots_type.n]
        return cls(s, k, lmots_type)

    def print_hex(self):
        PrintUtl.print_line()
        print "LMOTS public key"
        PrintUtl.print_hex("LMOTS type", u32str(self.lmots_type.type_code), self.lmots_type.name)
        PrintUtl.print_hex("S", self.s)
        PrintUtl.print_hex("K", self.k)
        PrintUtl.print_line()
