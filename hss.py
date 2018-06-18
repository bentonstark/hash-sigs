from Crypto import Random
from lmots_type import LmotsType
from lms_type import LmsType
from lms import Lms
from lms_serializer import LmsSerializer
from hss_pvtkey import HssPrivateKey
from hss_pvtkey import HssPublicKey
from hss_serializer import HssSerializer


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

        # generate a new lms root key pair
        lms_root_pub_key, lms_root_pvt_key = Lms(lms_type=self.lms_type, lmots_type=self.lmots_type).generate_key_pair()

        # build the hss key pair tree based on the lms root pair
        hss_pub_key, hss_pvt_key = self.build_key_pair_from_root(levels, lms_root_pub_key, lms_root_pvt_key)

        return hss_pub_key, hss_pvt_key

    def build_key_pair_from_root(self, levels, lms_root_pub_key, lms_root_pvt_key):
        lms_pub_list = list()
        lms_pvt_list = list()
        lsm_pub_sig_list = list()

        # add the lms root key pair
        lms_pub_list.append(lms_root_pub_key)
        lms_pvt_list.append(lms_root_pvt_key)

        # generate additional lms key pairs based on the number of levels needed for the tree
        lms = Lms(lms_type=self.lms_type, lmots_type=self.lmots_type)
        for i in xrange(1, levels):
            lms_pub_key, lms_pvt_key = lms.generate_key_pair()
            lms_pvt_list.append(lms_pvt_key)
            lms_pub_list.append(lms_pub_key)
            # serialize the lms public key and sign it with the lms private key
            pub_key_ser = LmsSerializer.serialize_public_key(lms_pub_key)
            # signatures need to chain from the previous lms private key and not the current one
            s = lms.sign(message=pub_key_ser, pub_key=lms_pub_list[-2], pvt_key=lms_pvt_list[-2])
            lsm_pub_sig_list.append(s)
        hss_pvt_key = HssPrivateKey(lms_type=self.lms_type, lmots_type=self.lmots_type, levels=levels,
                                    private_keys=lms_pvt_list, public_keys=lms_pub_list,
                                    public_key_signatures=lsm_pub_sig_list)
        hss_pub_key = HssPublicKey(lms_pub_list[0], levels)
        return hss_pub_key, hss_pvt_key

    def sign(self, message, pvt_key):

        # is this some kind of clean-up attempt for exhausted keys?
        while pvt_key.pvt_keys[-1].is_exhausted():
            print "level " + str(len(pvt_key.pvt_keys)) + " is exhausted"
            if len(pvt_key.pvt_keys) == 1:
                raise ValueError("private hss (lms) key exhausted")
            pvt_key.pvt_keys.pop()
            pvt_key.pub_keys.pop()
            pvt_key.pub_sigs.pop()

        # auto-gen new keys?  This is not really going to work is it?
        # apparently this is some kind of hack that adds keys and signatures back on this list after
        # popping them off - the serializer method fails to include the public key signatures if this
        # code doesn't run
        lms = Lms(lms_type=self.lms_type, lmots_type=self.lmots_type)
        while len(pvt_key.pvt_keys) < pvt_key.levels:
            print "refreshing level " + str(len(pvt_key.pvt_keys))
            # generate a new lms root key pair
            lms_pub_key, lms_pvt_key = lms.generate_key_pair()

            pvt_key.pvt_keys.append(lms_pvt_key)
            pvt_key.pub_keys.append(lms_pub_key)
            pub_key_ser = LmsSerializer.serialize_public_key(lms_pub_key)
            pub_key_ser_sig = lms.sign(message=pub_key_ser, pub_key=pvt_key.pub_keys[-2], pvt_key=pvt_key.pvt_keys[-2])
            pvt_key.pub_sigs.append(pub_key_ser_sig)

        # sign message
        lms = Lms(self.lms_type, self.lmots_type)
        lms_sig = lms.sign(message, pvt_key.pub_keys[-1], pvt_key.pvt_keys[-1])
        return HssSerializer.serialize_hss_sig(pvt_key.levels - 1, pvt_key.pub_keys, pvt_key.pub_sigs, lms_sig)

    def verify(self, message, sig, pub_key):
        levels, pub_list, sig_list, lms_sig = HssSerializer.deserialize_hss_sig(sig)
        if levels != pub_key.levels:
            raise ValueError("invalid HSS level")

        # verify the chain of signed public keys
        key = pub_key.pub1
        lms = Lms(key.lms_type, key.lmots_type)
        i = key.i
        k = key.k
        for j in xrange(0, pub_key.levels - 1):
            sig = sig_list[j]
            msg = pub_list[j]
            result = lms.verify(msg, sig, i, k)
            if result is False:
                return result
            lms_type, lmots_type, i, k = LmsSerializer.deserialize_public_key(msg)

        # TODO: why does key get re-assigned so many times?
        return lms.verify(message, lms_sig, i, k)