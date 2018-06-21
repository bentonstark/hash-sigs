from utils import u32str
from string_format import StringFormat
from lmots_type import LmotsType


class LmotsSignature:
    """
    Leighton-Micali One Time Signature
    """
    def __init__(self, c, y, lmots_type=LmotsType.LMOTS_SHA256_M32_W8):
        if not isinstance(lmots_type, LmotsType):
            raise ValueError("lmots_type must be of type LmotsType")

        self.c = c
        self.y = y
        self.lmots_type = lmots_type

    def __str__(self):
        """
        String representation of LMOTS signature object.
        :return: string
        """
        s_list = list()
        StringFormat.line(s_list)
        s_list.append("LMOTS signature")
        StringFormat.format_hex(s_list, "LMOTS type", u32str(self.lmots_type.type_code), self.lmots_type.name)
        StringFormat.format_hex(s_list, "C", self.c)
        for i, e in enumerate(self.y):
            StringFormat.format_hex(s_list, "y[" + str(i) + "]", e)
        StringFormat.line(s_list)
        return "\n".join(s_list)

