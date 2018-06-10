from need_to_sort import err_list, INVALID_HSS_LEVEL_ERR, INVALID_WITH_REASON
from utils import u32str, hex_u32_to_int
from sig_tests import deserialize_hss_sig
from lms_pubkey import LmsPublicKey
from print_util import PrintUtl
from lms import LmsSerializer


class HssPublicKey(object):
    """
    Hierarchical Signature System Public Key
    """
    def __init__(self, root_pub, levels):
        self.pub1 = root_pub
        self.levels = levels

    def verify(self, message, sig):
        try:
            levels, pub_list, sig_list, lms_sig = deserialize_hss_sig(sig)
            if levels != self.levels:
                return INVALID_HSS_LEVEL_ERR

            # verify the chain of signed public keys
            key = self.pub1
            for i in xrange(0, self.levels - 1):
                sig = sig_list[i]
                msg = pub_list[i]
                result = key.verify(msg, sig)
                if result is False:
                    return result
                key = LmsPublicKey.deserialize(msg)
            return key.verify(message, lms_sig)

        except ValueError as err:
            if err.args[0] in err_list:
                return INVALID_WITH_REASON

    def serialize(self):
        return u32str(self.levels) + LmsSerializer.serialize_public_key(self.pub1)

    @classmethod
    def deserialize(cls, hex_value):
        levels = hex_u32_to_int(hex_value[0:4])
        lms_type, lmots_type, i, k = LmsSerializer.deserialize_public_key(hex_value[4:])
        # TODO: build lmots keys using levels (probably similar to what I did for signing)
        # TODO: build the nodes for the lms public key (See Lms.generate_key_pair())
        return LmsPublicKey(lms_type=lms_type, lmots_type=lmots_type, i=i, k=k, nodes=None)

    def print_hex(self):
        PrintUtl.print_line()
        print("HSS public key")
        PrintUtl.print_hex("levels", u32str(self.levels))
        self.pub1.print_hex()
        PrintUtl.print_line()
