
from utils import u32str, hex_u32_to_int
from sig_tests import deserialize_hss_sig
from lms_pubkey import LmsPublicKey
from print_util import PrintUtl
from lms import LmsSerializer
from lms import Lms


class HssPublicKey(object):
    """
    Hierarchical Signature System Public Key
    """
    def __init__(self, root_pub, levels):
        self.pub1 = root_pub
        self.levels = levels

    def verify(self, message, sig):
        levels, pub_list, sig_list, lms_sig = deserialize_hss_sig(sig)
        if levels != self.levels:
            raise ValueError("invalid HSS level")

        # verify the chain of signed public keys
        key = self.pub1
        lms = Lms(key.lms_type, key.lmots_type)
        i = key.i
        k = key.k
        for j in xrange(0, self.levels - 1):
            sig = sig_list[j]
            msg = pub_list[j]
            result = lms.verify(msg, sig, i, k)
            if result is False:
                return result
            lms_type, lmots_type, i, k = LmsSerializer.deserialize_public_key(msg)

        # TODO: why does key get re-assigned so many times?
        return lms.verify(message, lms_sig, i, k)


    def serialize(self):
        return u32str(self.levels) + LmsSerializer.serialize_public_key(self.pub1)

    @classmethod
    def deserialize(cls, hex_value):
        levels = hex_u32_to_int(hex_value[0:4])
        lms_type, lmots_type, i, k = LmsSerializer.deserialize_public_key(hex_value[4:])
        lms_root_pub_key = LmsPublicKey(lms_type=lms_type, lmots_type=lmots_type, i=i, k=k, nodes=None)
        return cls(root_pub=lms_root_pub_key, levels=levels)

    def print_hex(self):
        PrintUtl.print_line()
        print("HSS public key")
        PrintUtl.print_hex("levels", u32str(self.levels))
        self.pub1.print_hex()
        PrintUtl.print_line()
