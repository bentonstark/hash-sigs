
from utils import u32str
from lmots_pubkey import LmotsPublicKey
from print_util import PrintUtl
from lmots_type import LmotsType


class LmotsPrivateKey:
    """
    Leighton-Micali One Time Signature Private Key
    """
    def __init__(self, lmots_type, raw_key, s, seed, signatures_remaining):
        if not isinstance(lmots_type, LmotsType):
            raise ValueError("lmots_type must be of type LmotsType")

        self.lmots_type = lmots_type
        self.raw_key = raw_key
        self.s = s
        self.seed = seed
        self.signatures_remaining = signatures_remaining

    def print_hex(self):
        PrintUtl.print_line()
        print "LMOTS private key"
        PrintUtl.print_hex("LMOTS type", u32str(self.lmots_type.type_code), self.lmots_type.name)
        PrintUtl.print_hex("S", self.s)
        for i, x in enumerate(self.raw_key):
            PrintUtl.print_hex("x[" + str(i) + "]", x)
        PrintUtl.print_line()



