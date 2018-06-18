
from utils import u32str
from print_util import PrintUtl


class HssPublicKey(object):
    """
    Hierarchical Signature System Public Key
    """
    def __init__(self, root_pub, levels):
        self.pub1 = root_pub
        self.levels = levels

    def print_hex(self):
        PrintUtl.print_line()
        print("HSS public key")
        PrintUtl.print_hex("levels", u32str(self.levels))
        self.pub1.print_hex()
        PrintUtl.print_line()
