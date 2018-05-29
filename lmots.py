from Crypto.Hash import SHA256
from Crypto import Random
from need_to_sort import D_MESG, D_ITER, D_PBLC, D_PRG
from utils import sha256_hash, u16str, u8str
from lmots_pubkey import LmotsPublicKey
from lmots_pvtkey import LmotsPrivateKey
from merkle import Merkle
from lmots_sig import LmotsSignature
from lmots_alg import LmotsDefinition
from enum import Enum


class LmotsType(Enum):
    """
    Leighton-Micali One Time Signature (LMOTS) Algorithm Type Enumeration
    """
    LMOTS_SHA256_M32_W1 = LmotsDefinition(name="LMOTS_SHA256_M32_W1", n=32, p=265, w=1, ls=7, type_code=0x00000001)
    LMOTS_SHA256_M32_W2 = LmotsDefinition(name="LMOTS_SHA256_M32_W2", n=32, p=133, w=2, ls=6, type_code=0x00000002)
    LMOTS_SHA256_M32_W4 = LmotsDefinition(name="LMOTS_SHA256_M32_W4", n=32, p=67, w=4, ls=4, type_code=0x00000003)
    LMOTS_SHA256_M32_W8 = LmotsDefinition(name="LMOTS_SHA256_M32_W8", n=32, p=34, w=8, ls=0, type_code=0x00000004)

    @staticmethod
    def get_by_type_code(type_code):
        if type_code == LmotsType.LMOTS_SHA256_M32_W1.type_code:
            return LmotsType.LMOTS_SHA256_M32_W1
        elif type_code == LmotsType.LMOTS_SHA256_M32_W2.type_code:
            return LmotsType.LMOTS_SHA256_M32_W2
        elif type_code == LmotsType.LMOTS_SHA256_M32_W4.type_code:
            return LmotsType.LMOTS_SHA256_M32_W4
        elif type_code == LmotsType.LMOTS_SHA256_M32_W8.type_code:
            return LmotsType.LMOTS_SHA256_M32_W8
        else:
            raise ValueError("unknown LMOTS type code", str(type_code))


class Lmots:
    """
    Leighton-Micali One Time Signature (LMOTS) Algorithm
    """

    def __init__(self, alg=LmotsType.LMOTS_SHA256_N32_W8, entropy_source=None):
        self.alg = alg
        if entropy_source is None:
            self._entropy_source = Random.new()
        else:
            self._entropy_source = entropy_source

    def generate_key_pair(self, s=None, seed=None):
        """
        Generates a LMOTS key pair.
        :param s: entropy s value; if None then random bytes read from entropy source
        :param seed: seed value; if None then random bytes read from entropy source
        :return: key pair set (public key, private key)
        """
        pvt_key = self.generate_private_key(s, seed)
        pub_key = self.generate_public_key(s, pvt_key)
        return pub_key, pvt_key

    def generate_private_key(self, s=None, seed=None):
        """
        Generate a LMOTS private key.
        Algorithm 0.
        :param s: entropy s value; if None then random bytes read from entropy source
        :param seed: seed value; if None then random bytes read from entropy source
        :return: LMOTS private key object
        """
        if s is None:
            s = self._entropy_source.read(self.alg.n)
        raw_key = list()
        if seed is None:
            for i in xrange(0, self.alg.p):
                raw_key.append(self._entropy_source.read(self.alg.n))
        else:
            for i in xrange(0, self.alg.p):
                raw_key.append(sha256_hash(s + seed + u16str(i + 1) + D_PRG))

        return LmotsPrivateKey(lmots_type=self.alg, raw_key=raw_key, s=s, seed=seed, signatures_remaining=1)

    def generate_public_key(self, s, pvt_key):
        """
        Generate LMOTS public key from a private key.
        Algorithm 1.
        :param s: entropy s value
        :param pvt_key: LMOTS private key object
        :return: LMOTS public key object
        """
        outer_hash = SHA256.new()
        outer_hash.update(s)
        for i, pvt_key in enumerate(pvt_key.raw_key):
            tmp = pvt_key
            for j in xrange(0, 2 ** self.alg.w - 1):
                tmp = sha256_hash(s + tmp + u16str(i) + u8str(j) + D_ITER)
            outer_hash.update(tmp)
        outer_hash.update(D_PBLC)

        return LmotsPublicKey(s=s, k=outer_hash.digest(), lmots_type=self.alg)

    def verify(self, message, signature, s, k):
        """
        Verify a LMOTS signature.
        Algorithm 4: Verifying a Signature and Message Using a Public Key
        :param message: original message bytes
        :param signature: signature to verify
        :param s: entropy s value
        :param k: k value
        :return: true if valid; otherwise false
        """
        pub_key = self.extract_public_key(signature, s, message)
        is_valid = k == pub_key.k
        return is_valid

    def extract_public_key(self, signature, s, message):
        """
        Extracts a LMOTS public key object from a LMOTS signature.
        :param signature: LMOTS signature
        :param s: entropy s value
        :param message: original message
        :return: LMOTS public key object
        """
        signature = LmotsSignature.deserialize(signature)
        if signature.type != self.alg.type_code:
            raise ValueError("signature type code does not match expected value")
        hashQ = sha256_hash(s + signature.C + message + D_MESG)
        V = hashQ + Merkle.checksum(hashQ, self.alg.w, self.alg.ls)
        outer_hash = SHA256.new()
        outer_hash.update(s)
        for i, y in enumerate(signature.y):
            tmp = y
            for j in xrange(Merkle.coef(V, i, self.alg.w), 2 ** self.alg.w - 1):
                tmp = sha256_hash(s + tmp + u16str(i) + u8str(j) + D_ITER)
            outer_hash.update(tmp)
        outer_hash.update(D_PBLC)

        return LmotsPublicKey(s=s, k=outer_hash.digest())
