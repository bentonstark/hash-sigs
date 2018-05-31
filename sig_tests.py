import sys

from need_to_sort import err_private_key_exhausted, err_bad_length, err_bad_value, err_list, VALID, retcode_get_string, \
    lmots_params
from merkle import Merkle
from utils import u32str, hex_u32_to_int, string_to_hex
from lms_sig import parse_lms_sig, print_lms_sig
from lmots_sig import LmotsSignature
from lms_pubkey import LmsPublicKey
from sig_test_mangler import Mangler
from print_util import PrintUtl

test_message = "Hello, world!"


def serialize_hss_sig(levels_minus_one, pub_list, sig_list, msg_sig):
    result = u32str(levels_minus_one)
    for i in xrange(0, levels_minus_one):
        result = result + sig_list[i]
        result = result + pub_list[i + 1].serialize()
    result = result + msg_sig
    return result


def deserialize_hss_sig(hex_value):
    hss_max_levels = 8
    levels = hex_u32_to_int(hex_value[0:4]) + 1
    if levels > hss_max_levels:
        raise ValueError(err_bad_value)
    siglist = list()
    publist = list()
    tmp = hex_value[4:]
    for i in xrange(0, levels-1):
        lms_sig, tmp = parse_lms_sig(tmp)
        siglist.append(lms_sig)
        lms_pub, tmp = LmsPublicKey.parse(tmp)
        publist.append(lms_pub)
    msg_sig = tmp
    return levels, publist, siglist, msg_sig


def print_hss_sig(sig):
    levels, pub_list, sig_list, lms_sig = deserialize_hss_sig(sig)
    PrintUtl.print_line()
    print "HSS signature"
    PrintUtl.print_hex("Nspk", u32str(levels - 1))
    for i in xrange(0, levels-1):
        print "sig[" + str(i) + "]: "
        print_lms_sig(sig_list[i])
        print "pub[" + str(i) + "]: "
        LmsPublicKey.deserialize(pub_list[i]).print_hex()
    print "final_signature: "
    print_lms_sig(lms_sig)


def checksum_test():
    for typecode in [2]:
        n, p, w, ls = lmots_params[typecode]

        for j in xrange(0, n):
            x = ""
            for i in xrange(0,n):
                if i == j:
                    x = x + chr(0)
                else:
                    x = x + chr(0)
            y = x + Merkle.checksum(x, w, ls)
            print "w: " + str(w) + "\tp: " + str(p) + "\tcksm: " + string_to_hex(Merkle.checksum(x, w, ls))
            print "x + checksum(x): "
            print_as_coefs(y,w,p)
            print ""


def print_as_coefs(x, w, p):
    num_coefs = len(x)*(8/w)
    if p > num_coefs:
        raise ValueError(err_bad_length)
    for i in xrange(0, p):
        print str(Merkle.coef(x, i, w))
    print "\n"

def ntimesig_test(private_key_class, verbose=False):
    param_list = private_key_class.get_param_list()
    for param in param_list:
        ntimesig_test_param(private_key_class, param, verbose)


def ntimesig_test_param(private_key_class, param, verbose=False):
    """
    Unit test for N-time signatures

    :param param: dictionary containing private key parameters
    :param verbose: boolean that determines verbosity of output
    :return:
    """
    print "N-time signature test"
    public_key_class = private_key_class.get_public_key_class()
    private_key = private_key_class(**param)
    public_key_buffer = private_key.generate_public_key().serialize()
    public_key = public_key_class.deserialize(public_key_buffer)
    num_sigs = private_key.num_signatures_remaining()
    num_tests = min(num_sigs, 4096)

    if verbose:
        print "message: \"" + test_message + "\""
        private_key.print_hex()
        public_key.print_hex()
        print "num_signatures_remaining: " + str(private_key.num_signatures_remaining())

    for i in xrange(0,num_tests):
        sig = private_key.sign(test_message)
        sig_copy = sig

        print "signature byte length: " + str(len(sig))
        if verbose:
            # note: we need an lmsSignature class to enable printing here
            # LmotsSignature.deserialize(sig).print_hex()
            # print_lms_sig(sig)
            print "num_signatures_remaining: " + str(private_key.num_signatures_remaining())

        print "true positive test: ",
        result = public_key.verify(test_message, sig)
        if result == VALID:
            print "passed: message/signature pair is valid as expected"
        else:
            print "failed: message/signature pair is invalid (" + retcode_get_string(result) + ")"
            sys.exit()

        print "false positive test: ",
        if public_key.verify("some other message", sig) == VALID:
            print "failed: message/signature pair is valid (expected failure)"
            sys.exit(1)
        else:
            print "passed: message/signature pair is invalid as expected"

    print "overuse test: ",
    print "num_sigs: " + str(num_sigs)
    if num_sigs < 1:
        print "error: private key reports that it is a zero-time signature system"
        sys.exit(1)
    for i in xrange(0,num_sigs):
        print "sign attempt #" + str(i)
        try:
            sig = private_key.sign("some other message")
        except ValueError as err:
            if err.args[0] == err_private_key_exhausted:
                print "passed: no overuse allowed"
            else:
                err_handle(err)
        else:
            if i > num_sigs:
                print "failed: key overuse occured; created " + str(i) + "signatures"
                sys.exit()

    print "mangled signature parse test",
    err_dict = {}
    mangled_sig_iterator = Mangler(sig_copy)
    for mangled_sig in mangled_sig_iterator:
        try:
            if public_key.verify(test_message, mangled_sig) == VALID:
                print "failed: invalid signature accepted (mangled byte: " + str(mangled_sig_iterator.i) + ")"
                public_key_class.deserialize(mangled_sig).print_hex()
                sys.exit(1)
        except ValueError as err:
            if err.args[0] not in err_list:
                raise
            else:
                err_dict[err.args[0]] = err_dict.get(err.args[0], 0) + 1
    print "error counts:"
    for err_key in err_dict:
        print "\t" + err_key.ljust(40)[7:] + str(err_dict[err_key])
    print "passed"

    print "mangled public key parse test",
    mangled_pub_iterator = Mangler(public_key_buffer)
    err_dict = {}
    for mangled_pub in mangled_pub_iterator:
        try:
            public_key = public_key_class.deserialize(mangled_pub)
            if public_key.verify(test_message, mangled_sig) == VALID:
                print "failed: invalid signature accepted (mangled byte: " + str(mangled_sig_iterator.i) + ")"
                LmotsSignature.deserialize(mangled_sig).print_hex()
                sys.exit(1)
        except ValueError as err:
            if err.args[0] not in err_list:
                raise
            else:
                err_dict[err.args[0]] = err_dict.get(err.args[0], 0) + 1
    print "error counts:"
    for err_key in err_dict:
        print "\t" + err_key.ljust(40)[7:] + str(err_dict[err_key])
    print "passed"


def err_handle(err):
    if err.args[0] in err_list:
        print str(err.args)
    else:
        raise Exception()