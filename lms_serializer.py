from need_to_sort import err_bad_value
from utils import u32str, hex_u32_to_int, serialize_array
from print_util import PrintUtl
from lms_type import LmsType
from lmots_type import LmotsType
from lmots_serializer import LmotsSerializer


class LmsSerializer:

    @staticmethod
    def get_lms_type(hex_value):
        # extract the type code value that identifies the LMS algorithm
        sig_type_code_lms = hex_u32_to_int(hex_value[0:4])
        lms_type = LmsType.get_by_type_code(sig_type_code_lms)
        return lms_type

    @staticmethod
    def get_lmots_type(hex_value):
        # extract the type code value that identifies the LMOTS algorithm
        sig_type_code_lmots = hex_u32_to_int(hex_value[4:8])
        lmots_type = LmotsType.get_by_type_code(sig_type_code_lmots)
        return lmots_type

    @staticmethod
    def serialize_private_key(pvt_key):
        return u32str(pvt_key.lms_type.type_code) + u32str(pvt_key.lmots_type.type_code) \
               + pvt_key.seed + pvt_key.i + u32str(pvt_key.leaf_num)

    @staticmethod
    def serialize_public_key(public_key):
        return u32str(public_key.lms_type.type_code) + u32str(public_key.lmots_type.type_code) + public_key.i \
               + public_key.k

    @staticmethod
    def parse_private_key(hex_value):
        lms_type = LmsSerializer.get_lms_type(hex_value)
        lmots_type = LmsSerializer.get_lmots_type(hex_value)
        return hex_value[:8 + lmots_type.n + lms_type.len_i], hex_value[8 + lmots_type.n + lms_type.len_i:]

    @staticmethod
    def parse_public_key(hex_value):
        lms_type = LmsSerializer.get_lms_type(hex_value)
        return hex_value[0:4 + 4 + lms_type.len_i + lms_type.m], hex_value[4 + 4 + lms_type.len_i + lms_type.m:]

    @staticmethod
    def deserialize_private_key(hex_value):
        # parse out values
        lmots_type = LmsSerializer.get_lmots_type(hex_value)
        lms_type = LmsSerializer.get_lms_type(hex_value)

        seed = hex_value[8:8 + lmots_type.n]
        i = hex_value[8 + lmots_type.n:8 + lmots_type.n + lms_type.len_i]
        q = hex_u32_to_int(hex_value[8 + lmots_type.n + lms_type.len_i:8 + lmots_type.n + lms_type.len_i + 4])
        return lms_type, lmots_type, seed, i, q

    @staticmethod
    def deserialize_public_key(hex_value):
        # parse out values
        lmots_type = LmsSerializer.get_lmots_type(hex_value)
        lms_type = LmsSerializer.get_lms_type(hex_value)

        i = hex_value[8:8 + lms_type.len_i]
        k = hex_value[8 + lms_type.len_i:8 + lms_type.len_i + lms_type.m]
        return lms_type, lmots_type, i, k

    @staticmethod
    def serialize_signature(signature):
        return u32str(signature.q) + signature.signature + u32str(signature.type_code.type_code) \
               + serialize_array(signature.path)

    @staticmethod
    def deserialize_lms_sig(hex_value):
        q = hex_u32_to_int(hex_value[0:4])
        lmots_type = LmsSerializer.get_lmots_type(hex_value)
        pos = 4 + LmotsSerializer.bytes(lmots_type)
        lmots_sig = hex_value[4:pos]
        lms_type = LmsSerializer.get_lms_type(hex_value[pos:pos+4])

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
        pos = 4 + LmotsSerializer.bytes(lmots_type)
        lms_type = LmsType.get_by_type_code(hex_u32_to_int(hex_value[pos:pos + 4]))
        pos = pos + 4 + lms_type.h * lms_type.m
        return hex_value[0:pos], hex_value[pos:]

    @staticmethod
    def deserialize_print_hex(hex_value):

        lms_type = LmsSerializer.get_lms_type(hex_value)
        lmots_type = LmsSerializer.get_lmots_type(hex_value)

        PrintUtl.print_line()
        print "LMS private key"

        seed = hex_value[8:8 + lmots_type.n]
        i = hex_value[8 + lmots_type.n:8 + lmots_type.n + lms_type.len_i]
        q = hex_u32_to_int(hex_value[8 + lmots_type.n + lms_type.len_i:8 + lmots_type.n + lms_type.len_i + 4])
        PrintUtl.print_hex("lms_type", u32str(lms_type))
        PrintUtl.print_hex("lmots_type", u32str(lmots_type))
        PrintUtl.print_hex("seed", seed)
        PrintUtl.print_hex("I", i)
        PrintUtl.print_hex("leaf_num", u32str(q))
        PrintUtl.print_line()