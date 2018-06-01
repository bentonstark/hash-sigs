from need_to_sort import err_bad_value
from utils import u32str, hex_u32_to_int, serialize_array
from lmots_sig import LmotsSignature
from print_util import PrintUtl
from lms_type import LmsType
from lmots_type import LmotsType


class LmsSignature:

    @staticmethod
    def serialize(type_code, q, signature, path):
        return u32str(q) + signature + u32str(type_code) + serialize_array(path)

    @staticmethod
    def deserialize_lms_sig(hex_value):
        q = hex_u32_to_int(hex_value[0:4])
        lmots_type = LmotsType.get_by_type_code(hex_u32_to_int(hex_value[4:8]))
        pos = 4 + LmotsSignature.bytes(lmots_type.type_code)
        lmots_sig = hex_value[4:pos]
        lms_type = LmsType.get_by_type_code(hex_u32_to_int(hex_value[pos:pos + 4]))

        if q >= 2 ** lms_type.h:
            raise ValueError(err_bad_value)
        pos = pos + 4
        path = list()
        for i in xrange(0, lms_type.h):
            path.append(hex_value[pos:pos + lms_type.m])
            pos = pos + lms_type.m
        return lms_type, q, lmots_sig, path

    @staticmethod
    def parse_lms_sig(hex_value):
        lmots_type = LmotsType.get_by_type_code(hex_u32_to_int(hex_value[4:8]))
        pos = 4 + LmotsSignature.bytes(lmots_type.type_code)
        lms_type = hex_u32_to_int(hex_value[pos:pos + 4])
        pos = pos + 4 + lms_type.h * lms_type.m
        return hex_value[0:pos], hex_value[pos:]

    @staticmethod
    def print_lms_sig(signature):
        PrintUtl.print_line()
        print "LMS signature"
        lms_type, q, lmots_sig, path = LmsSignature.deserialize_lms_sig(signature)
        PrintUtl.print_hex("q", u32str(q))
        LmotsSignature.deserialize(lmots_sig).print_hex()
        PrintUtl.print_hex("LMS type", u32str(lms_type.type_code), lms_type.name)
        for i, e in enumerate(path):
            PrintUtl.print_hex("path[" + str(i) + "]", e)
