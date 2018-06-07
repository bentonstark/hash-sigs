from Crypto import Random
from lms_sig import LmsSignature
from lmots import Lmots
from lmots_type import LmotsType
from lms_type import LmsType
from utils import sha256_hash, u32str, hex_u32_to_int
from need_to_sort import D_INTR, D_LEAF
from lms_pvtkey import LmsPrivateKey
from lms_pubkey import LmsPublicKey


class Lms:
    """
    Leighton-Micali Signature (LMS) Algorithm
    """

    def __init__(self, lms_type=LmsType.LMS_SHA256_M32_H10, lmots_type=LmotsType.LMOTS_SHA256_M32_W8,
                 entropy_source=None):
        self.lms_type = lms_type
        self.lmots_type = lmots_type
        if entropy_source is None:
            self._entropy_source = Random.new()
        else:
            self._entropy_source = entropy_source

    def generate_key_pair(self, seed=None, i=None, q=0):
        """
        Generate a LMS key pair.
        :param seed: seed value; if None then random bytes read from entropy source
        :param i: i value; if None then random bytes read from entropy source
        :param q: q value; if None then 0
        :return: list of LMOTS public keys and list of LMOTS private keys
        """
        if seed is not None and len(seed) != self.lmots_type.n:
            raise ValueError("seed length invalid", str(len(seed)))
        if i is not None and len(i) != self.lms_type.len_i:
            raise ValueError("var_id length invalid", str(len(i)))

        if seed is None:
            seed = self._entropy_source.read(self.lmots_type.n)
        if i is None:
            i = self._entropy_source.read(self.lms_type.len_i)

        priv = list()
        pub = list()

        # Q: instance number
        # w: Winternitz parameter
        # I: identity
        lmots = Lmots(lmots_type=self.lmots_type)
        for q in xrange(0, 2 ** self.lms_type.h):
            s = i + u32str(q)
            ots_pub, ots_priv = lmots.generate_key_pair(s=s, seed=seed)
            priv.append(ots_priv)
            pub.append(ots_pub)

        # init the lms private key object
        lms_pvt_key = LmsPrivateKey(lms_type=self.lms_type, lmots_type=self.lmots_type, private_keys=priv,
                                    seed=seed, i=i, q_init=q)

        pub_lmots_nodes = {}
        lms_pub_value = self._T(1, pub_lmots_nodes, pub, i)
        lms_pub_key = LmsPublicKey(lms_type=self.lms_type, lmots_type=self.lmots_type, i=i, k=lms_pub_value,
                                   nodes=pub_lmots_nodes)

        return lms_pub_key, lms_pvt_key

    # Algorithm for computing root and other nodes (alternative to Algorithm 6)
    #
    def _T(self, r, pub_nodes, pub_lmots_keys, i):
        if r >= 2 ** self.lms_type.h:
            pub_nodes[r] = sha256_hash(i + pub_lmots_keys[r - 2 ** self.lms_type.h].k + u32str(r) + D_LEAF)
            return pub_nodes[r]
        else:
            pub_nodes[r] = sha256_hash(i + self._T(2 * r, pub_nodes, pub_lmots_keys, i)
                                       + self._T(2 * r + 1, pub_nodes, pub_lmots_keys, i) + u32str(r) + D_INTR)
            return pub_nodes[r]

    def sign(self, message, pvt_key):
        if pvt_key.leaf_num >= 2 ** self.lms_type.h:
            raise ValueError("attempted overuse of private key")
        ots_sig = pvt_key.get_next_ots_priv_key().sign(message)
        path = pvt_key.get_path(pvt_key.leaf_num + 2 ** self.lmots_type.h)
        leaf_num = pvt_key.leaf_num
        pvt_key.leaf_num = pvt_key.leaf_num + 1
        return LmsSignature.serialize(self.lms_type, leaf_num, ots_sig, path)

    def verify(self, message, sig, i, k):
        lms_type, q, lmots_sig, path = LmsSignature.deserialize_lms_sig(sig)

        node_num = q + 2 ** self.lms_type.h
        if lms_type != self.lms_type:
            return ValueError("LMS signature type does not match expected type")
        path_value = iter(path)

        lmots = Lmots(self.lmots_type)
        sig_pub_key = lmots.extract_public_key(signature=lmots_sig, s=i + u32str(q), message=message)
        sig_pub_key = sha256_hash(i + sig_pub_key + u32str(node_num) + D_LEAF)
        while node_num > 1:
            if node_num % 2:
                sig_pub_key = sha256_hash(i + path_value.next() + sig_pub_key + u32str(node_num / 2) + D_INTR)
            else:
                sig_pub_key = sha256_hash(i + sig_pub_key + path_value.next() + u32str(node_num / 2) + D_INTR)
            node_num = node_num / 2

        is_valid = sig_pub_key == k
        return is_valid

    #TODO: move to serialization class?
    @staticmethod
    def get_lms_type(hex_value):
        # extract the type code value that identifies the LMS algorithm
        sig_type_code_lms = hex_u32_to_int(hex_value[0:4])
        lms_type = LmsType.get_by_type_code(sig_type_code_lms)
        return lms_type

    # TODO: move to serialization class?
    @staticmethod
    def get_lmots_type(hex_value):
        # extract the type code value that identifies the LMOTS algorithm
        sig_type_code_lmots = hex_u32_to_int(hex_value[4:8])
        lmots_type = LmotsType.get_by_type_code(sig_type_code_lmots)
        return lmots_type