from utils import u32str, hex_u32_to_int
from sig_tests import serialize_hss_sig
from hss_pubkey import HssPublicKey
from lms_pvtkey import LmsPrivateKey
from print_util import PrintUtl
from lms_serializer import LmsSerializer
from lms import Lms


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

    def sign(self, message):

        # is this some kind of clean-up attempt for exhausted keys?
        while self.pvt_keys[-1].is_exhausted():
            print "level " + str(len(self.pvt_keys)) + " is exhausted"
            if len(self.pvt_keys) == 1:
                raise ValueError("private hss (lms) key exhausted")
            self.pvt_keys.pop()
            self.pub_keys.pop()
            self.pub_sigs.pop()

        # auto-gen new keys?  This is not really going to work is it?
        #while len(self.pvt_keys) < self.levels:
        #    print "refreshing level " + str(len(self.pvt_keys))
        #    self.pvt_keys.append(LmsPrivateKey(lms_type=self.lms_type, lmots_type=self.lmots_type))
        #    self.pub_keys.append(self.pvt_keys[-1].get_public_key())
        #    self.pub_sigs.append(self.pvt_keys[-2].sign(self.pub_keys[-1].serialize()))

        # sign message
        lms = Lms(self.lms_type, self.lmots_type)
        lms_sig = lms.sign(message, self.pub_keys[-1], self.pvt_keys[-1])
        #lms_sig = self.pvt_keys[-1].sign(message)
        return serialize_hss_sig(self.levels - 1, self.pub_keys, self.pub_sigs, lms_sig)

    def num_signatures_remaining(self):
        unused = self.pvt_keys[0].num_signatures_remaining()
        for i in xrange(1,self.levels):
            unused = unused * self.pvt_keys[i].max_signatures() + self.pvt_keys[i].num_signatures_remaining()
        return unused

    def serialize(self):
        return u32str(self.levels) + LmsSerializer.serialize_private_key(self.pvt_keys[0])

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
