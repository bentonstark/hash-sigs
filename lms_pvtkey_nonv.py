from lms_pvtkey import LmsPrivateKey


class LmsPrivateKeyNonvolatile(LmsPrivateKey):

    def get_next_ots_priv_key(self):
        return self.priv[self.leaf_num]
