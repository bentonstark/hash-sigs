from utils import u32str
from lmots_sig import LmotsSignature
from print_util import PrintUtl


class LmsSignature:

    def __init__(self, type_code, q, signature, path):

        self.type_code = type_code
        self.q = q
        self.signature = signature
        self.path = path

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
