
from utils import u32str
from lmots_pubkey import LmotsPublicKey
from print_util import PrintUtl


class LmotsPrivateKey:
    """
    Leighton-Micali One Time Signature Private Key
    """
    def __init__(self, lmots_type, raw_key, s, seed, signatures_remaining):
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

    def get_param_list(self):
        # dumps the possible LMOTS types for informational purposes
        param_list = list()
        for t in lmots_params.keys():
            param_list.append({'lmots_type': t})
        return param_list

    def get_public_key_class(self):
        return LmotsPublicKey

