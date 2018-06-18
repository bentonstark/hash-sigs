from lms import Lms
from lms_serializer import LmsSerializer
from utils import u32str, hex_u32_to_int
from lms_pubkey import LmsPublicKey


class HssSerializer:

    @staticmethod
    def serialize_public_key(public_key):
        return u32str(public_key.levels) + LmsSerializer.serialize_public_key(public_key.pub1)

    @staticmethod
    def serialize_private_key(private_key):
        return u32str(private_key.levels) + LmsSerializer.serialize_private_key(private_key.pvt_keys[0])

    @staticmethod
    def deserialize_private_key(hex_value):
        levels = hex_u32_to_int(hex_value[0:4])
        lms_type, lmots_type, seed, i, q = LmsSerializer.deserialize_private_key(hex_value[4:])
        lms = Lms(lms_type=lms_type, lmots_type=lmots_type)
        lms_root_pub_key, lms_root_pvt_key = lms.generate_key_pair(seed=seed, i=i, q=q)
        return lms_root_pub_key, lms_root_pvt_key, levels, lms_type, lmots_type

    @staticmethod
    def deserialize_public_key(hex_value):
        levels = hex_u32_to_int(hex_value[0:4])
        lms_type, lmots_type, i, k = LmsSerializer.deserialize_public_key(hex_value[4:])
        lms_root_pub_key = LmsPublicKey(lms_type=lms_type, lmots_type=lmots_type, i=i, k=k, nodes=None)
        return lms_root_pub_key, levels

    @staticmethod
    def serialize_hss_sig(levels_minus_one, pub_list, sig_list, msg_sig):
        result = u32str(levels_minus_one)
        for i in xrange(0, levels_minus_one):
            result = result + sig_list[i]
            result = result + LmsSerializer.serialize_public_key(pub_list[i + 1])
        result = result + msg_sig
        return result

    @staticmethod
    def deserialize_hss_sig(hex_value):
        hss_max_levels = 8
        levels = hex_u32_to_int(hex_value[0:4]) + 1
        if levels > hss_max_levels:
            raise ValueError("levels exceeds max level value")
        siglist = list()
        publist = list()
        tmp = hex_value[4:]
        for i in xrange(0, levels - 1):
            lms_sig, tmp = LmsSerializer.parse_lms_sig(tmp)
            siglist.append(lms_sig)
            lms_pub, tmp = LmsSerializer.parse_public_key(tmp)
            publist.append(lms_pub)
        msg_sig = tmp
        return levels, publist, siglist, msg_sig
