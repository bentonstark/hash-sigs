from utils import u32str
from string_format import StringFormat
from lms_serializer import LmsSerializer
from lmots_serializer import LmotsSerializer


class LmsSignature:

    def __init__(self, type_code, q, signature, path):

        self.type_code = type_code
        self.q = q
        self.signature = signature
        self.path = path

    @staticmethod
    def print_lms_sig(signature):
        StringFormat.line()
        print "LMS signature"
        lms_type, q, lmots_sig, path = LmsSerializer.deserialize_signature(signature)
        StringFormat.format_hex("q", u32str(q))
        sig = LmotsSerializer.deserialize_signature(lmots_sig)
        sig.format_hex()
        StringFormat.format_hex("LMS type", u32str(lms_type.type_code), lms_type.name)
        for i, e in enumerate(path):
            StringFormat.format_hex("path[" + str(i) + "]", e)
