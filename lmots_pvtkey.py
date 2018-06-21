
from utils import u32str
from lmots_pubkey import LmotsPublicKey
from string_format import StringFormat
from lmots_type import LmotsType


class LmotsPrivateKey:
    """
    Leighton-Micali One Time Signature Private Key
    """
    def __init__(self, lmots_type, raw_key, s, seed, signatures_remaining):
        if not isinstance(lmots_type, LmotsType):
            raise ValueError("lmots_type must be of type LmotsType")

        self.lmots_type = lmots_type
        self.raw_key = raw_key
        self.s = s
        self.seed = seed
        self.signatures_remaining = signatures_remaining

    def __str__(self):
        """
        String representation of LMOTS private key object.
        :return: string
        """
        s_list = list()
        StringFormat.line(s_list)
        s_list.append("LMOTS private key")
        StringFormat.format_hex(s_list, "LMOTS type", u32str(self.lmots_type.type_code), self.lmots_type.name)
        StringFormat.format_hex(s_list, "S", self.s)
        for i, x in enumerate(self.raw_key):
            StringFormat.format_hex(s_list, "x[" + str(i) + "]", x)
        StringFormat.line(s_list)
        return "\n".join(s_list)


