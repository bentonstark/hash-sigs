from Crypto import Random
from need_to_sort import D_LEAF, D_INTR
from utils import sha256_hash, u32str, hex_u32_to_int
from print_util import PrintUtl
#from lms import Lms


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
        return 2 ** self.lmots_type.h - self.leaf_num

    def is_exhausted(self):
        return 0 == self.num_signatures_remaining()

    def max_signatures(self):
        return 2 ** self.lmots_type.h

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

    def serialize(self):
        return u32str(self.lms_type) + u32str(self.lmots_type) + self.seed + self.i + u32str(self.leaf_num)

    @classmethod
    def deserialize(cls, hex_value):
        lms_type = Lms.get_lms_type(hex_value)
        lmots_type = Lms.get_lmots_type(hex_value)
        seed = hex_value[8:8 + lmots_type.n]
        i = hex_value[8 + lmots_type.n:8 + lmots_type.n + lms_type.len_i]
        q = hex_u32_to_int(hex_value[8 + lmots_type.n + lms_type.len_i:8 + lmots_type.n + lms_type.len_i + 4])

        #pub_key, pvt_key = Lms(lms_type, lmots_type).generate_key_pair(seed=seed, i=i, q=q)

        #return pvt_key

    @staticmethod
    def deserialize_print_hex(hex_value):

        lms_type = Lms.get_lms_type(hex_value)
        lmots_type = Lms.get_lmots_type(hex_value)

        PrintUtl.print_line()
        print "LMS private key"

        seed = hex_value[8:8 + lmots_type.n]
        i = hex_value[8 + lmots_type.n:8 + lmots_type.n + lms_type.len_i]
        q = hex_u32_to_int(hex_value[8 + lmots_type.n + lms_type.len_i:8 + lmots_type.n + lms_type.len_i + 4])
        PrintUtl.print_hex("lms_type", u32str(lms_type))
        PrintUtl.print_hex("lmots_type", u32str(lmots_type))
        PrintUtl.print_hex("seed", seed)
        PrintUtl.print_hex("I", i)
        PrintUtl.print_hex("leaf_num", u32str(q))
        PrintUtl.print_line()

    @staticmethod
    def parse(hex_value):
        lms_type = Lms.get_lms_type(hex_value)
        lmots_type = Lms.get_lmots_type(hex_value)
        return hex_value[:8 + lmots_type.n + lms_type.len_i], hex_value[8 + lmots_type.n + lms_type.len_i:]



