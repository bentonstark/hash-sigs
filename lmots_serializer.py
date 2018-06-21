from utils import u32str, hex_u32_to_int, serialize_array
from lmots_type import LmotsType
from lmots_pubkey import LmotsPublicKey
from lmots_sig import LmotsSignature


class LmotsSerializer(object):

    @staticmethod
    def serialize_public_key(public_key):
        return u32str(public_key.lmots_type.type_code) + public_key.s + public_key.k

    @staticmethod
    def deserialize_public_key(hex_value):
        sig_type_code = hex_u32_to_int(hex_value[0:4])
        lmots_type = LmotsType.get_by_type_code(sig_type_code)
        if len(hex_value) != 4 + 2 * lmots_type.n:
            raise ValueError("hex_value is wrong length")
        s = hex_value[4:4 + lmots_type.n]
        k = hex_value[4 + lmots_type.n:4 + 2 * lmots_type.n]
        return LmotsPublicKey(s=s, k=k, lmots_type=lmots_type)

    @staticmethod
    def serialize_signature(signature):
        return u32str(signature.lmots_type.type_code) + signature.c + serialize_array(signature.y)

    @staticmethod
    def deserialize_signature(hex_value):
        # extract the type code value that identifies the LMOTS algorithm used in the signature
        sig_type_code = hex_u32_to_int(hex_value[0:4])
        lmots_type = LmotsType.get_by_type_code(sig_type_code)

        if len(hex_value) != LmotsSerializer.bytes(lmots_type):
            raise ValueError("hex_value is wrong length")
        c = hex_value[4:lmots_type.n + 4]
        y = list()
        pos = lmots_type.n + 4
        for i in xrange(0, lmots_type.p):
            y.append(hex_value[pos:pos + lmots_type.n])
            pos = pos + lmots_type.n
        return LmotsSignature(c=c, y=y, lmots_type=lmots_type)

    @staticmethod
    def bytes(lmots_type):
        return 4 + lmots_type.n * (lmots_type.p + 1)
