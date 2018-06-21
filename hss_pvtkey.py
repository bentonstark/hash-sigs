from utils import u32str, hex_u32_to_int
from lms_pvtkey import LmsPrivateKey
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
        for i in xrange(1,self.levels):
            unused = unused * self.pvt_keys[i].max_signatures() + self.pvt_keys[i].num_signatures_remaining()
        return unused

    @classmethod
    def deserialize_print_hex(cls, hex_value):
        """
        Parse all of the data elements of an HSS private key out of the string buffer.

        Does not initialize an hss_private_key (as that initialization computes at least one
        LMS public/private keypair, which can take a long time)

        :param hex_value: string representing HSS private key
        :return:
        """
        StringFormat.line()
        print "HSS private key"
        levels = hex_u32_to_int(hex_value[0:4])
        StringFormat.format_hex("levels", u32str(levels))
        print "prv[0]:"
        LmsPrivateKey.deserialize_print_hex(hex_value[4:])
        StringFormat.line()

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



