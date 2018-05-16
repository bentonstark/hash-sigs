from Crypto.Hash import SHA256

from need_to_sort import err_unknown_typecode, err_bad_length, VALID, INVALID, D_ITER, D_PBLC, D_MESG, lmots_params, \
    lmots_name
from merkle_checksum import coef, checksum
from lmots_sig import LmotsSignature
from utils import u32str, hex_u32_to_int, sha256_hash, u16str, u8str
from printutl import PrintUtl


class LmotsPublicKey:
    """
    Leighton-Micali One Time Signature Public Key
    """
    def __init__(self, S, K, lmots_type):
        self.S = S
        self.K = K
        self.type = lmots_type

    # Algorithm 4: Verifying a Signature and Message Using a Public Key
    #
    def verify(self, message, sig):
        if self.K == lmots_sig_to_pub(sig, self.S, self.type, message):
            return VALID
        else:
            return INVALID

    def serialize(self):
        return u32str(self.type) + self.S + self.K

    @classmethod
    def deserialize(cls, hex_value):
        lmots_type = hex_u32_to_int(hex_value[0:4])
        if lmots_type in lmots_params:
            n, p, w, ls = lmots_params[lmots_type]
        else:
            raise ValueError(err_unknown_typecode)
        if len(hex_value) != 4+2*n:
            raise ValueError(err_bad_length)
        S = hex_value[4:4 + n]
        K = hex_value[4 + n:4 + 2 * n]
        return cls(S, K, lmots_type)

    def print_hex(self):
        PrintUtl.print_line()
        print "LMOTS public key"
        PrintUtl.print_hex("LMOTS type", u32str(self.type), lmots_name[self.type])
        PrintUtl.print_hex("S", self.S)
        PrintUtl.print_hex("K", self.K)
        PrintUtl.print_line()


def lmots_sig_to_pub(sig, S, lmots_type, message):
    signature = LmotsSignature.deserialize(sig)
    if signature.type != lmots_type:
        raise ValueError(err_unknown_typecode)
    n, p, w, ls = lmots_params[lmots_type]
    hashQ = sha256_hash(S + signature.C + message + D_MESG)
    V = hashQ + checksum(hashQ, w, ls)
    hash = SHA256.new()
    hash.update(S)
    for i, y in enumerate(signature.y):
        tmp = y
        for j in xrange(coef(V, i, w), 2**w - 1):
            tmp = sha256_hash(S + tmp + u16str(i) + u8str(j) + D_ITER)
        hash.update(tmp)
    hash.update(D_PBLC)
    return hash.digest()