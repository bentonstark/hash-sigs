
from need_to_sort import err_private_key_exhausted, D_ITER, D_PBLC, D_MESG, D_PRG, entropySource
from merkle import Merkle
from utils import sha256_hash, u32str, u16str, u8str
from lmots_pubkey import LmotsPublicKey
from lmots_sig import LmotsSignature
from print_util import PrintUtl


class LmotsPrivateKey:
    """
    Leighton-Micali One Time Signature Private Key
    """
    def __init__(self, lmots_type, raw_key, s, seed, signatures_remaining):
        self.type = lmots_type
        self.raw_key = raw_key
        self.s = s
        self.seed = seed
        self.signatures_remaining = signatures_remaining

    def print_hex(self):
        PrintUtl.print_line()
        print "LMOTS private key"
        PrintUtl.print_hex("LMOTS type", u32str(self.type), lmots_name[self.type])
        PrintUtl.print_hex("S", self.S)
        for i, x in enumerate(self.x):
            PrintUtl.print_hex("x[" + str(i) + "]", x)
        PrintUtl.print_line()

    @classmethod
    def get_param_list(cls):
        param_list = list()
        for t in lmots_params.keys():
            param_list.append({'lmots_type':t})
        return param_list

    @classmethod
    def get_public_key_class(cls):
        return LmotsPublicKey