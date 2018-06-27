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

    def __str__(self):
        """
        String representation of LMS signature object.
        :return: string
        """
        s_list = list()
        StringFormat.line(s_list)
        s_list.append("LMS signature")
        # TODO: we should not be deserializing here - we should be working directly with the signature object
        lms_type, q, lmots_sig, path = LmsSerializer.deserialize_signature(self.signature)
        StringFormat.format_hex(s_list, "q", u32str(q))
        # TODO: we should not be deserializing here - we should be working directly with the signature object
        sig = LmotsSerializer.deserialize_signature(lmots_sig)
        s_list.append(str(sig))
        StringFormat.format_hex(s_list, "LMS type", u32str(lms_type.type_code), lms_type.name)
        for i, e in enumerate(path):
            StringFormat.format_hex(s_list, "path[" + str(i) + "]", e)
        return "\n".join(s_list)
