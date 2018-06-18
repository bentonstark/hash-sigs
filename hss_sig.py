from hss_serializer import HssSerializer
from lms_serializer import LmsSerializer
from lms_sig import LmsSignature
from print_util import PrintUtl
from utils import u32str


def print_hss_sig(sig):
    levels, pub_list, sig_list, lms_sig = HssSerializer.deserialize_hss_sig(sig)
    PrintUtl.print_line()
    print "HSS signature"
    PrintUtl.print_hex("Nspk", u32str(levels - 1))
    for i in xrange(0, levels - 1):
        print "sig[" + str(i) + "]: "
        LmsSignature.print_lms_sig(sig_list[i])
        print "pub[" + str(i) + "]: "
        lms_pub_key = LmsSerializer.deserialize_public_key(pub_list[i])
        lms_pub_key.print_hex()
    print "final_signature: "
    LmsSignature.print_lms_sig(lms_sig)