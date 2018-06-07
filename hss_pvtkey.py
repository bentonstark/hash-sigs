from need_to_sort import err_private_key_exhausted
from utils import u32str, hex_u32_to_int
from sig_tests import serialize_hss_sig
from hss_pubkey import HssPublicKey
from lms_pvtkey import LmsPrivateKey
from print_util import PrintUtl
from lms_type import LmsType
from lmots_type import LmotsType
from lms import Lms

class HssPrivateKey(object):
    """
    Hierarchical Signature System Private Key
    """
    def __init__(self, levels=2, lms_type=LmsType.LMS_SHA256_M32_H5, lmots_type=LmotsType.LMOTS_SHA256_M32_W8):
        self.levels = levels
        self.prv = list()
        self.pub = list()
        self.sig = list()

        lms = Lms(lms_type=lms_type, lmots_type=lmots_type)

        # TODO: this pub and prv lists needs to be LmsPublic and LmsPrivate key objects instead
        pub_0, prv_0 = lms.generate_key_pair()
        self.pub.append(pub_0)
        self.prv.append(prv_0)

        for i in xrange(1, self.levels):
            pub_key, pvt_key = lms.generate_key_pair()
            self.prv.append(pvt_key)
            self.pub.append(pub_key)
            pub_key_ser = pub_key.serialize()
            sig = lms.sign(pub_key_ser, self.prv[i-1])
            self.sig.append(sig)

    def sign(self, message):
        while self.prv[-1].is_exhausted():
            print "level " + str(len(self.prv)) + " is exhausted"
            if len(self.prv) == 1:
                raise ValueError(err_private_key_exhausted)
            self.prv.pop()
            self.pub.pop()
            self.sig.pop()
        while len(self.prv) < self.levels:
            print "refreshing level " + str(len(self.prv))
            self.prv.append(LmsPrivateKey(lms_type=self.prv[0].lms_type, lmots_type=self.prv[0].lmots_type))
            self.pub.append(self.prv[-1].get_public_key())
            self.sig.append(self.prv[-2].sign(self.pub[-1].serialize()))

        # sign message
        lms_sig = self.prv[-1].sign(message)
        return serialize_hss_sig(self.levels-1, self.pub, self.sig, lms_sig)

    def get_public_key(self):
        return HssPublicKey(self.prv[0].get_public_key(), self.levels)

    def num_signatures_remaining(self):
        unused = self.prv[0].num_signatures_remaining()
        for i in xrange(1,self.levels):
            unused = unused * self.prv[i].max_signatures() + self.prv[i].num_signatures_remaining()
        return unused

    def serialize(self):
        return u32str(self.levels) + self.prv[0].serialize()

    @classmethod
    def deserialize(cls, hex_value):
        levels = hex_u32_to_int(hex_value[0:4])
        prv = LmsPrivateKey.deserialize(hex_value[4:])
        return cls(levels, lms_type=prv.lms_type, lmots_type=prv.lmots_type, prv0=prv)

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
        for prv in self.prv:
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
