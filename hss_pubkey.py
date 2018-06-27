
from utils import u32str
from string_format import StringFormat


class HssPublicKey(object):
    """
    Hierarchical Signature System Public Key
    """
    def __init__(self, root_pub, levels):
        self.pub1 = root_pub
        self.levels = levels

    def __str__(self):
        """
        String representation of HSS public key object.
        :return: string
        """
        s_list = list()
        StringFormat.line(s_list)
        s_list.append("HSS public key")
        StringFormat.format_hex(s_list, "levels", u32str(self.levels))
        s_list.append(str(self.pub1))
        StringFormat.line(s_list)
        return "\n".join(s_list)
