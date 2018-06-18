from utils import u32str, hex_u32_to_int
from hss_pubkey import HssPublicKey
from lms_pvtkey import LmsPrivateKey
from print_util import PrintUtl


class HssPrivateKey(object):
    """
    Hierarchical Signature System Private Key
    """
    def __init__(self, lms_type, lmots_type, levels, private_keys, public_keys, public_key_signatures):
        self.lms_type = lms_type
        self.lmots_type = lmots_type
        self.levels = levels
        self.pvt_keys = private_keys
        self.pub_keys = public_keys
        self.pub_sigs = public_key_signatures

    def num_signatures_remaining(self):
        unused = self.pvt_keys[0].num_signatures_remaining()
        for i in xrange(1,self.levels):
            unused = unused * self.pvt_keys[i].max_signatures() + self.pvt_keys[i].num_signatures_remaining()
        return unused

    @classmethod
    def deserialize_print_hex(cls, hex_value):
        """
        Parse all of the data elements of an HSS private key out of the string buffer.

        Does not initialize an hss_private_key (as that initialization computes at least one
        LMS public/private keypair, which can take a long time)

        :param hex_value: string representing HSS private key
        :return:
        """
        PrintUtl.print_line()
        print "HSS private key"
        levels = hex_u32_to_int(hex_value[0:4])
        PrintUtl.print_hex("levels", u32str(levels))
        print "prv[0]:"
        LmsPrivateKey.deserialize_print_hex(hex_value[4:])
        PrintUtl.print_line()

    def print_hex(self):
        PrintUtl.print_line()
        print "HSS private key"
        PrintUtl.print_hex("levels", u32str(self.levels))
        for prv in self.pvt_keys:
            prv.print_hex()
        PrintUtl.print_line()

    @classmethod
    def get_param_list(cls):
        param_list = list()
        for x in [ lmots_sha256_n32_w1 ]: # lmots_params.keys():
            for y in [LMS_SHA256_M32_H05]: # lms_params.keys():
                for l in [2,3]:
                    param_list.append({'lmots_type': x, 'lms_type': y, 'levels': l})
        return param_list

    @classmethod
    def get_public_key_class(cls):
        return HssPublicKey
