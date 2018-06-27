from utils import u32str
from string_format import StringFormat


class LmsPrivateKey:
    """
    Leighton-Micali Signature Private Key
    """
    def __init__(self, lms_type, lmots_type, private_keys, seed, i, q_init):
        self.lms_type = lms_type
        self.lmots_type = lmots_type
        self.priv = private_keys
        self.seed = seed
        self.i = i
        self.leaf_num = q_init

    def __str__(self):
        """
        String representation of LMS public key object.
        :return: string
        """
        s_list = list()
        StringFormat.line(s_list)
        s_list.append("LMS private key")
        StringFormat.format_hex(s_list, "LMS type", u32str(self.lms_type.type_code), self.lms_type.name)
        StringFormat.format_hex(s_list, "LMOTS_type", u32str(self.lmots_type.type_code), self.lms_type.name)
        StringFormat.format_hex(s_list, "I", self.i)
        StringFormat.format_hex(s_list, "SEED", self.seed)
        StringFormat.format_hex(s_list, "q", u32str(self.leaf_num))
        StringFormat.line(s_list)
        return "\n".join(s_list)

    def get_next_ots_priv_key(self):
        return self.priv[self.leaf_num]

    def num_signatures_remaining(self):
        return 2 ** self.lms_type.h - self.leaf_num

    def is_exhausted(self):
        return 0 == self.num_signatures_remaining()

    def max_signatures(self):
        return 2 ** self.lms_type.h




