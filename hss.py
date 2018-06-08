from Crypto import Random
from lmots_type import LmotsType
from lms_type import LmsType
from lms import Lms
from lms_serializer import LmsSerializer
from hss_pvtkey import HssPrivateKey
from hss_pvtkey import HssPublicKey


class Hss:
    """
    Leighton-Micali Signature (LMS) Algorithm
    """

    def __init__(self, lms_type=LmsType.LMS_SHA256_M32_H5, lmots_type=LmotsType.LMOTS_SHA256_M32_W8,
                 entropy_source=None):
        self.lms_type = lms_type
        self.lmots_type = lmots_type
        if entropy_source is None:
            self._entropy_source = Random.new()
        else:
            self._entropy_source = entropy_source

    def generate_key_pair(self, levels=2):
        lms_pub_list = list()
        lms_pvt_list = list()
        lsm_pub_sig_list = list()

        lms = Lms(lms_type=self.lms_type, lmots_type=self.lmots_type)

        # generate the first lms key pair
        lms_pub_0, lms_pvt_0 = lms.generate_key_pair()
        lms_pub_list.append(lms_pub_0)
        lms_pvt_list.append(lms_pvt_0)

        # generate additional lms key pairs based on the number of levels needed
        for i in xrange(1, levels):
            lms_pub_key, lms_pvt_key = lms.generate_key_pair()
            lms_pvt_list.append(lms_pvt_key)
            lms_pub_list.append(lms_pub_key)
            # serialize the lms public key and sign it with the lms private key
            pub_key_ser = LmsSerializer.serialize_public_key(lms_pub_key)
            s = lms.sign(message=pub_key_ser, pub_key=lms_pub_key, pvt_key=lms_pvt_key)
            lsm_pub_sig_list.append(s)

        hss_pvt_key = HssPrivateKey(lms_type=self.lms_type, lmots_type=self.lmots_type, levels=levels,
                                    private_keys=lms_pvt_list, public_keys=lms_pub_list,
                                    public_key_signatures=lsm_pub_sig_list)
        hss_pub_key = HssPublicKey(lms_pub_list[0], levels)

        return hss_pub_key, hss_pvt_key



