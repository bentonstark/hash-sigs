from utils import u32str
from print_util import PrintUtl


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

    def get_path(self, node_num):
        path = list()
        while node_num > 1:
            if node_num % 2:
                path.append(self.nodes[node_num - 1])
            else:
                path.append(self.nodes[node_num + 1])
            node_num = node_num / 2
        return path

    def print_hex(self):
        PrintUtl.print_line()
        print "LMS public key"
        PrintUtl.print_hex("LMS type", u32str(self.lms_type.type_code), self.lms_type.name)
        PrintUtl.print_hex("LMOTS_type", u32str(self.lmots_type.type_code), self.lms_type.name)
        PrintUtl.print_hex("I", self.i)
        PrintUtl.print_hex("K", self.k)
        PrintUtl.print_line()
