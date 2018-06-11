from lmots_type import LmotsType
from utils import u32str
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

    def print_hex(self):
        PrintUtl.print_line()
        print "LMOTS public key"
        PrintUtl.print_hex("LMOTS type", u32str(self.lmots_type.type_code), self.lmots_type.name)
        PrintUtl.print_hex("S", self.s)
        PrintUtl.print_hex("K", self.k)
        PrintUtl.print_line()
