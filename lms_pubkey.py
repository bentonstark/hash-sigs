from utils import u32str
from print_util import PrintUtl
from lms import Lms


class LmsPublicKey(object):
    """
    Leighton-Micali Signature Public Key
    """

    def __init__(self, i, k, lms_type, lmots_type):
        self.i = i
        self.k = k
        self.lms_type = lms_type
        self.lmots_type = lmots_type

    def serialize(self):
        return u32str(self.lms_type.type_code) + u32str(self.lmots_type.type_code) + self.i + self.k

    @staticmethod
    def parse(hex_value):
        lms_type = Lms.get_lms_type(hex_value)
        return hex_value[0:4 + 4 + lms_type.len_i + lms_type.m], hex_value[4 + 4 + lms_type.len_i + lms_type.m:]

    @classmethod
    def deserialize(cls, hex_value):
        lms_type = Lms.get_lms_type(hex_value)
        lmots_type = Lms.get_lms_type(hex_value)

        i = hex_value[8:8 + lms_type.len_i]
        k = hex_value[8 + lms_type.len_i:8 + lms_type.len_i + lms_type.m]
        return cls(i, k, lms_type, lmots_type)

    def print_hex(self):
        PrintUtl.print_line()
        print "LMS public key"
        PrintUtl.print_hex("LMS type", u32str(self.lms_type.type_code), self.lms_type.name)
        PrintUtl.print_hex("LMOTS_type", u32str(self.lmots_type.type_code), self.lms_type.name)
        PrintUtl.print_hex("I", self.i)
        PrintUtl.print_hex("K", self.k)
        PrintUtl.print_line()
