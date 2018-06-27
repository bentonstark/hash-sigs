from utils import u32str
from string_format import StringFormat


class LmsPublicKey(object):
    """
    Leighton-Micali Signature Public Key
    """

    def __init__(self, lms_type, lmots_type, i, k, nodes=None):
        self.lms_type = lms_type
        self.lmots_type = lmots_type
        self.i = i
        self.k = k
        self.nodes = nodes

    def __str__(self):
        """
        String representation of LMS public key object.
        :return: string
        """
        s_list = list()
        StringFormat.line(s_list)
        s_list.append("LMS public key")
        StringFormat.format_hex(s_list, "LMS type", u32str(self.lms_type.type_code), self.lms_type.name)
        StringFormat.format_hex(s_list, "LMOTS_type", u32str(self.lmots_type.type_code), self.lms_type.name)
        StringFormat.format_hex(s_list, "I", self.i)
        StringFormat.format_hex(s_list, "K", self.k)
        StringFormat.line(s_list)
        return "\n".join(s_list)

    def get_path(self, node_num):
        path = list()
        while node_num > 1:
            if node_num % 2:
                path.append(self.nodes[node_num - 1])
            else:
                path.append(self.nodes[node_num + 1])
            node_num = node_num / 2
        return path

