from lms import Lms
from hss import Hss
from lms_serializer import LmsSerializer
from utils import hex_u32_to_int


class HssSerializer:

    @staticmethod
    def deserialize_private_key(hex_value):
        levels = hex_u32_to_int(hex_value[0:4])
        lms_type, lmots_type, seed, i, q = LmsSerializer.deserialize_private_key(hex_value[4:])
        lms = Lms(lms_type=lms_type, lmots_type=lmots_type)
        lms_root_pub_key, lms_root_pvt_key = lms.generate_key_pair(seed=seed, i=i, q=q)

        hss = Hss(lms_type=lms_type, lmots_type=lmots_type)
        hss_pub_key, hss_pvt_key = hss.build_key_pair_from_root(levels=levels, lms_root_pub_key=lms_root_pub_key,
                                                                lms_root_pvt_key=lms_root_pvt_key)
        return hss_pub_key, hss_pvt_key
