from Crypto.Hash import SHA256

from need_to_sort import err_private_key_exhausted, D_ITER, D_PBLC, D_MESG, D_PRG, lmots_sha256_n32_w8, lmots_params, \
    lmots_name, entropySource
from merkle_checksum import coef, checksum
from utils import sha256_hash, u32str, u16str, u8str
from lmots_pubkey import LmotsPublicKey
from lmots_sig import LmotsSignature
from printutl import PrintUtl


class LmotsPrivateKey:
    """
    Leighton-Micali One Time Signature Private Key
    """
    # Algorithm 0: Generating an LMOTS Private Key
    #
    def __init__(self, S=None, SEED=None, lmots_type=lmots_sha256_n32_w8):
        n, p, w, ls = lmots_params[lmots_type]
        if S is None:
            self.S = entropySource.read(n)
        else:
            self.S = S
        self.x = list()
        if SEED is None:
            for i in xrange(0, p):
                self.x.append(entropySource.read(n))
        else:
            for i in xrange(0, p):
                self.x.append(sha256_hash(self.S + SEED + u16str(i + 1) + D_PRG))
        self.type = lmots_type
        self._signatures_remaining = 1

    def num_signatures_remaining(self):
        return self._signatures_remaining

    # Algorithm 1: Generating a Public Key From a Private Key
    #
    def get_public_key(self):
        n, p, w, ls = lmots_params[self.type]
        hash = SHA256.new()
        hash.update(self.S)
        for i, x in enumerate(self.x):
            tmp = x
            for j in xrange(0, 2**w - 1):
                tmp = sha256_hash(self.S + tmp + u16str(i) + u8str(j) + D_ITER)
            hash.update(tmp)
        hash.update(D_PBLC)
        return LmotsPublicKey(self.S, hash.digest(), self.type)

    # Algorithm 3: Generating a Signature From a Private Key and a Message
    #
    def sign(self, message):
        if self._signatures_remaining != 1:
            raise ValueError(err_private_key_exhausted)
        n, p, w, ls = lmots_params[self.type]
        C = entropySource.read(n)
        hashQ = sha256_hash(self.S + C + message + D_MESG)
        V = hashQ + checksum(hashQ, w, ls)
        y = list()
        for i, x in enumerate(self.x):
            tmp = x
            for j in xrange(0, coef(V, i, w)):
                tmp = sha256_hash(self.S + tmp + u16str(i) + u8str(j) + D_ITER)
            y.append(tmp)
        self._signatures_remaining = 0
        return LmotsSignature(C, y, self.type).serialize()

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