from need_to_sort import err_unknown_typecode, VALID, INVALID_LMS_TYPE_ERR, INVALID_LMS_PUB_ERR, D_LEAF, D_INTR, \
    lmots_params, lmots_name, lms_params, lms_name
from lmots_pubkey import lmots_sig_to_pub
from utils import sha256_hash, u32str, hex_u32_to_int
from lms_sig_funcs import deserialize_lms_sig
from print_util import PrintUtl


class LmsPublicKey(object):
    """
    Leighton-Micali Signature Public Key
    """

    def __init__(self, I, value, lms_type, lmots_type):
        self.I = I
        self.value = value
        self.lms_type = lms_type
        self.lmots_type = lmots_type

    def verify(self, message, sig):
        m, h, LenI = lms_params[self.lms_type]
        lms_type, q, lmots_sig, path = deserialize_lms_sig(sig)
        node_num = q + 2 ** h
        if lms_type != self.lms_type:
            return INVALID_LMS_TYPE_ERR
        path_value = iter(path)
        tmp = lmots_sig_to_pub(lmots_sig, self.I + u32str(q), self.lmots_type, message)
        tmp = sha256_hash(self.I + tmp + u32str(node_num) + D_LEAF)
        while node_num > 1:
            if node_num % 2:
                tmp = sha256_hash(self.I + path_value.next() + tmp + u32str(node_num / 2) + D_INTR)
            else:
                tmp = sha256_hash(self.I + tmp + path_value.next() + u32str(node_num / 2) + D_INTR)
            node_num = node_num / 2
        if tmp == self.value:
            return VALID
        else:
            return INVALID_LMS_PUB_ERR

    def serialize(self):
        return u32str(self.lms_type) + u32str(self.lmots_type) + self.I + self.value

    @classmethod
    def parse(cls, hex_value):
        lms_type = hex_u32_to_int(hex_value[0:4])
        if lms_type in lms_params:
            m, h, LenI = lms_params[lms_type]
        else:
            raise ValueError(err_unknown_typecode)
        return hex_value[0:4 + 4 + LenI + m], hex_value[4 + 4 + LenI + m:]

    @classmethod
    def deserialize(cls, hex_value):
        lms_type = hex_u32_to_int(hex_value[0:4])
        if lms_type in lms_params:
            m, h, LenI = lms_params[lms_type]
        else:
            raise ValueError(err_unknown_typecode)
        lmots_type = hex_u32_to_int(hex_value[4:8])
        if lmots_type not in lmots_params:
            raise ValueError(err_unknown_typecode)
        I = hex_value[8:8 + LenI]
        K = hex_value[8 + LenI:8 + LenI + m]
        return cls(I, K, lms_type, lmots_type)

    def print_hex(self):
        PrintUtl.print_line()
        print "LMS public key"
        PrintUtl.print_hex("LMS type", u32str(self.lms_type), lms_name[self.lms_type])
        PrintUtl.print_hex("LMOTS_type", u32str(self.lmots_type), lmots_name[self.lmots_type])
        PrintUtl.print_hex("I", self.I)
        PrintUtl.print_hex("K", self.value)
        PrintUtl.print_line()
