from need_to_sort import err_private_key_exhausted, err_bad_length, D_LEAF, D_INTR, lmots_sha256_n32_w8, lmots_params, \
    lmots_name, lms_sha256_m32_h10, lms_params, lms_name, entropySource
from utils import sha256_hash, u32str, hex_u32_to_int
from lms_sig_funcs import serialize_lms_sig
from lms_pubkey import LmsPublicKey
from lmots_pvtkey import LmotsPrivateKey
from print_util import PrintUtl


class LmsPrivateKey(object):
    """
    Leighton-Micali Signature Private Key
    """
    def __init__(self, lms_type=lms_sha256_m32_h10, lmots_type=lmots_sha256_n32_w8,
                 seed=None, I=None, q_init=0, nodes=None, pub=None):
        n, p, w, ls = lmots_params[lmots_type]
        m, h, LenI = lms_params[lms_type]
        self.lms_type = lms_type
        self.lmots_type = lmots_type
        self.priv = list()
        self.pub = list()
        if I is None:
            self.I = entropySource.read(LenI)
        else:
            if len(I) != LenI:
                raise ValueError(err_bad_length, str(len(I)))
            self.I = I
        if seed is None:
            seed = entropySource.read(n)
        else:
            if len(seed) != n:
                raise ValueError(err_bad_length, str(len(seed)))
        self.SEED = seed

        # TODO: this should be an explicit call and not implicit based on parameters
        # if no key nodes are provided then generate a new key pair
        if nodes is None:
            # Q: instance number
            # w: Winternitz parameter
            # I: identity
            for Q in xrange(0, 2**h):
                s = self.I + u32str(Q)
                ots_priv = LmotsPrivateKey(s=s, seed=seed, lmots_type=lmots_type)
                ots_pub = ots_priv.generate_public_key()
                self.priv.append(ots_priv)
                self.pub.append(ots_pub)
        else:
            self.nodes = nodes
            self.pub = pub
        self.leaf_num = q_init
        self.nodes = {}
        self.lms_pub_value = self.T(1)

    def get_path(self, node_num):
        path = list()
        while node_num > 1:
            if node_num % 2:
                path.append(self.nodes[node_num - 1])
            else:
                path.append(self.nodes[node_num + 1])
            node_num = node_num/2
        return path

    def get_next_ots_priv_key(self):
        return self.priv[self.leaf_num]

    def sign(self, message):
        m, h, LenI = lms_params[self.lms_type]
        if self.leaf_num >= 2**h:
            raise ValueError(err_private_key_exhausted)
        ots_sig = self.get_next_ots_priv_key().sign(message)
        path = self.get_path(self.leaf_num + 2**h)
        leaf_num = self.leaf_num
        self.leaf_num = self.leaf_num + 1
        return serialize_lms_sig(self.lms_type, leaf_num, ots_sig, path)

    # Algorithm for computing root and other nodes (alternative to Algorithm 6)
    #
    def T(self, r):
        m, h, LenI = lms_params[self.lms_type]
        if r >= 2**h:
            self.nodes[r] = sha256_hash(self.I + self.pub[r - 2 ** h].K + u32str(r) + D_LEAF)
            return self.nodes[r]
        else:
            self.nodes[r] = sha256_hash(self.I + self.T(2 * r) + self.T(2 * r + 1) + u32str(r) + D_INTR)
            return self.nodes[r]

    def num_signatures_remaining(self):
        m, h, LenI = lms_params[self.lms_type]
        return 2**h - self.leaf_num

    def is_exhausted(self):
        return 0 == self.num_signatures_remaining()

    def max_signatures(self):
        m, h, LenI = lms_params[self.lms_type]
        return 2**h

    def print_hex(self):
        PrintUtl.print_line()
        print "LMS private key"
        PrintUtl.print_hex("LMS type", u32str(self.lms_type), lms_name[self.lms_type])
        PrintUtl.print_hex("LMOTS_type", u32str(self.lmots_type), lmots_name[self.lmots_type])
        PrintUtl.print_hex("I", self.I)
        PrintUtl.print_hex("SEED", self.SEED)
        PrintUtl.print_hex("q", u32str(self.leaf_num))
        PrintUtl.print_hex("pub", self.lms_pub_value)

    def get_public_key(self):
        return LmsPublicKey(self.I, self.lms_pub_value, self.lms_type, self.lmots_type)

    @classmethod
    def get_param_list(cls):
        param_list = list()
        for x in lmots_params.keys():
            for y in lms_params.keys():
                param_list.append({'lmots_type': x, 'lms_type': y})
        return param_list

    @classmethod
    def get_public_key_class(cls):
        return LmsPublicKey

    def serialize(self):
        return u32str(self.lms_type) + u32str(self.lmots_type) + self.SEED + self.I + u32str(self.leaf_num)

    @classmethod
    def deserialize(cls, hex_value):
        lms_type = hex_u32_to_int(hex_value[0:4])
        lmots_type = hex_u32_to_int(hex_value[4:8])
        n, p, w, ls = lmots_params[lmots_type]
        m, h, LenI = lms_params[lms_type]
        seed = hex_value[8:8 + n]
        I = hex_value[8 + n:8 + n + LenI]
        q = hex_u32_to_int(hex_value[8 + n + LenI:8 + n + LenI + 4])
        return cls(lms_type, lmots_type, seed, I, q)

    @classmethod
    def deserialize_print_hex(cls, hex_value):
        PrintUtl.print_line()
        print "LMS private key"
        lms_type = hex_u32_to_int(hex_value[0:4])
        lmots_type = hex_u32_to_int(hex_value[4:8])
        n, p, w, ls = lmots_params[lmots_type]
        m, h, LenI = lms_params[lms_type]
        seed = hex_value[8:8 + n]
        I = hex_value[8 + n:8 + n + LenI]
        q = hex_u32_to_int(hex_value[8 + n + LenI:8 + n + LenI + 4])
        PrintUtl.print_hex("lms_type", u32str(lms_type))
        PrintUtl.print_hex("lmots_type", u32str(lmots_type))
        PrintUtl.print_hex("seed", seed)
        PrintUtl.print_hex("I", I)
        PrintUtl.print_hex("leaf_num", u32str(q))
        PrintUtl.print_line()

    @classmethod
    def parse(cls, hex_value):
        lms_type = hex_u32_to_int(hex_value[0:4])
        lmots_type = hex_u32_to_int(hex_value[4:8])
        n, p, w, ls = lmots_params[lmots_type]
        m, h, LenI = lms_params[lms_type]
        return hex_value[:8 + n + LenI], hex_value[8 + n + LenI:]