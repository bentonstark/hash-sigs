from utils import u32str
from print_util import PrintUtl


class LmsPrivateKey(object):
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

    def get_next_ots_priv_key(self):
        return self.priv[self.leaf_num]

    def num_signatures_remaining(self):
        return 2 ** self.lms_type.h - self.leaf_num

    def is_exhausted(self):
        return 0 == self.num_signatures_remaining()

    def max_signatures(self):
        return 2 ** self.lms_type.h

    def print_hex(self):
        PrintUtl.print_line()
        print "LMS private key"
        PrintUtl.print_hex("LMS type", u32str(self.lms_type.type_code), self.lms_type.name)
        PrintUtl.print_hex("LMOTS_type", u32str(self.lmots_type.type_code), self.lmots_type.name)
        PrintUtl.print_hex("I", self.i)
        PrintUtl.print_hex("SEED", self.seed)
        PrintUtl.print_hex("q", u32str(self.leaf_num))

    def get_param_list(self):
        # this just dump a name/value of the different combinations of LMOTS / LMS types
        # to a list - seems to be for informational purposes
        #param_list = list()
        #for x in lmots_params.keys():
        #    for y in lms_params.keys():
        #        param_list.append({'lmots_type': x, 'lms_type': y})
        #return param_list
        return None




