from enum import Enum
from Crypto import Random
from lms_alg import LmsAlg
from lmots import LmotsType
from utils import sha256_hash, u32str, hex_u32_to_int


class LmsType(Enum):
    """
    Leighton-Micali Signature (LMS) Algorithm Type Enumeration
    """
    LMOTS_SHA256_M32_H5 = LmsAlg(name="LMS_SHA256_M32_H5", m=32, h=5, len_i=64, type_code=0x00000005)
    LMOTS_SHA256_M32_H10 = LmsAlg(name="LMS_SHA256_M32_H10", m=32, h=10, len_i=64, type_code=0x00000006)
    LMOTS_SHA256_M32_H15 = LmsAlg(name="LMS_SHA256_M32_H15", m=32, h=15, len_i=64, type_code=0x00000007)
    LMOTS_SHA256_M32_H20 = LmsAlg(name="LMS_SHA256_M32_H20", m=32, h=20, len_i=64, type_code=0x00000008)
    LMOTS_SHA256_M32_H25 = LmsAlg(name="LMS_SHA256_M32_H25", m=32, h=25, len_i=64, type_code=0x00000009)

    @staticmethod
    def get_by_type_code(type_code):
        if type_code == LmsType.LMOTS_SHA256_M32_H5.type_code:
            return LmsType.LMOTS_SHA256_M32_H5
        elif type_code == LmsType.LMOTS_SHA256_M32_H10.type_code:
            return LmsType.LMOTS_SHA256_M32_H10
        elif type_code == LmsType.LMOTS_SHA256_M32_H15.type_code:
            return LmsType.LMOTS_SHA256_M32_H15
        elif type_code == LmsType.LMOTS_SHA256_M32_H20.type_code:
            return LmsType.LMOTS_SHA256_M32_H20
        elif type_code == LmsType.LMOTS_SHA256_M32_H25.type_code:
            return LmsType.LMOTS_SHA256_M32_H25
        else:
            raise ValueError("unknown LMOTS type code", str(type_code))


class Lms:
    """
    Leighton-Micali Signature (LMS) Algorithm
    """

    def __init__(self, lms_type=LmsType.LMOTS_SHA256_M32_H10, lmots_type=LmotsType.LMOTS_SHA256_N32_W8,
                 entropy_source=None):
        self.lms_type = lms_type
        self.lmots_type = lmots_type
        if entropy_source is None:
            self._entropy_source = Random.new()
        else:
            self._entropy_source = entropy_source

    def generate_key_pair(self, seed=None, var_i=None):
        """
        Generate a LMS key pair.
        :param seed: seed value; if None then random bytes read from entropy source
        :param var_i: var_i value; if None then random bytes read from entropy source
        :return:
        """
        if seed is not None and len(seed) != self.lmots_type.n:
            raise ValueError("seed length invalid", str(len(seed)))
        if var_i is not None and len(var_i) != self.lms_type.len_i:
            raise ValueError("var_id length invalid", str(len(var_i)))

        if seed is None:
            seed = self._entropy_source.read(self.lmots_type.n)
        if var_i is None:
            var_i = self._entropy_source.read(self.lms_type.len_i)

        priv = list()
        pub = list()

        # Q: instance number
        # w: Winternitz parameter
        # I: identity
        for Q in xrange(0, 2 ** self.lms_type.h):
            s = var_i + u32str(Q)
            ots_priv = LmotsPrivateKey(s=s, seed=seed, lmots_type=self.lmots_type)
            ots_pub = ots_priv.generate_public_key()
            priv.append(ots_priv)
            pub.append(ots_pub)

        return pub, priv