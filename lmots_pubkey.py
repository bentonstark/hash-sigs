from lmots_type import LmotsType
from utils import u32str
from string_format import StringFormat


class LmotsPublicKey:
    """
    Leighton-Micali One Time Signature Public Key
    """
    def __init__(self, s, k, lmots_type):
        if not isinstance(lmots_type, LmotsType):
            raise ValueError("lmots_type must be of type LmotsType")

        self.s = s
        self.k = k
        self.lmots_type = lmots_type

    def __str__(self):
        """
        String representation of LMOTS public key object.
        :return: string
        """
        s_list = list()
        StringFormat.line(s_list)
        s_list.append("LMOTS public key")
        StringFormat.format_hex(s_list, "LMOTS type", u32str(self.lmots_type.type_code), self.lmots_type.name)
        StringFormat.format_hex(s_list, "S", self.s)
        StringFormat.format_hex(s_list, "K", self.k)
        StringFormat.line(s_list)
        return "\n".join(s_list)

