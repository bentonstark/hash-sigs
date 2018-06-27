from utils import u32str
from string_format import StringFormat


class HssPrivateKey(object):
    """
    Hierarchical Signature System Private Key
    """
    def __init__(self, lms_type, lmots_type, levels, private_keys, public_keys, public_key_signatures):
        self.lms_type = lms_type
        self.lmots_type = lmots_type
        self.levels = levels
        self.pvt_keys = private_keys
        self.pub_keys = public_keys
        self.pub_sigs = public_key_signatures

    def num_signatures_remaining(self):
        unused = self.pvt_keys[0].num_signatures_remaining()
        for i in xrange(1, self.levels):
            unused = unused * self.pvt_keys[i].max_signatures() + self.pvt_keys[i].num_signatures_remaining()
        return unused

    def __str__(self):
        """
        String representation of HSS private key object.
        :return: string
        """
        s_list = list()
        StringFormat.line(s_list)
        s_list.append("HSS private key")
        StringFormat.format_hex(s_list, "levels", u32str(self.levels))
        for prv in self.pvt_keys:
            s_list.append(str(prv))
        StringFormat.line(s_list)
        return "\n".join(s_list)



