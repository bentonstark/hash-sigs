import sys

from need_to_sort import err_private_key_exhausted, err_bad_length, err_bad_value, err_list, VALID, retcode_get_string, \
    lmots_params
from merkle_checksum import coef, checksum
from utils import u32str, hex_u32_to_int, string_to_hex
from lms_sig_funcs import parse_lms_sig, print_lms_sig
from lmots_sig import LmotsSignature
from lms_pubkey import LmsPublicKey
from mangler import Mangler
from printutl import PrintUtl


def serialize_hss_sig(levels_minus_one, publist, siglist, msg_sig):
    result = u32str(levels_minus_one)
    for i in xrange(0, levels_minus_one):
        result = result + siglist[i]
        result = result + publist[i+1].serialize()
    result = result + msg_sig
    return result


def deserialize_hss_sig(buffer):
    hss_max_levels = 8
    levels = hex_u32_to_int(buffer[0:4]) + 1
    if levels > hss_max_levels:
        raise ValueError(err_bad_value)
    siglist = list()
    publist = list()
    tmp = buffer[4:]
    for i in xrange(0, levels-1):
        lms_sig, tmp = parse_lms_sig(tmp)
        siglist.append(lms_sig)
        lms_pub, tmp = LmsPublicKey.parse(tmp)
        publist.append(lms_pub)
    msg_sig = tmp
    return levels, publist, siglist, msg_sig


def print_hss_sig(sig):
    levels, publist, siglist, lms_sig = deserialize_hss_sig(sig)
    PrintUtl.print_line()
    print "HSS signature"
    PrintUtl.print_hex("Nspk", u32str(levels - 1))
    for i in xrange(0, levels-1):
        print "sig[" + str(i) + "]: "
        print_lms_sig(siglist[i])
        print "pub[" + str(i) + "]: "
        LmsPublicKey.deserialize(publist[i]).print_hex()
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
            y = x + checksum(x, w, ls)
            print "w: " + str(w) + "\tp: " + str(p) + "\tcksm: " + string_to_hex(checksum(x, w, ls))
            print "x + checksum(x): "
            print_as_coefs(y,w,p)
            print ""


def print_as_coefs(x, w, p):
    num_coefs = len(x)*(8/w)
    if (p > num_coefs):
        raise ValueError(err_bad_length)
    for i in xrange(0, p):
        print str(coef(x, i, w))
    print "\n"


testmessage = "Hello, world!"


def ntimesig_test(private_key_class, verbose=False):
    paramlist = private_key_class.get_param_list()
    for param in paramlist:
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
    public_key_buffer = private_key.get_public_key().serialize()
    public_key = public_key_class.deserialize(public_key_buffer)
    num_sigs = private_key.num_signatures_remaining()
    num_tests = min(num_sigs, 4096)

    if verbose:
        print "message: \"" + testmessage + "\""
        private_key.print_hex()
        public_key.print_hex()
        print "num_signatures_remaining: " + str(private_key.num_signatures_remaining())

    for i in xrange(0,num_tests):
        sig = private_key.sign(testmessage)
        sigcopy = sig

        print "signature byte length: " + str(len(sig))
        if verbose:
            # note: we need an lmsSignature class to enable printing here
            # LmotsSignature.deserialize(sig).print_hex()
            # print_lms_sig(sig)
            print "num_signatures_remaining: " + str(private_key.num_signatures_remaining())

        print "true positive test: ",
        result = public_key.verify(testmessage, sig)
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
    errdict = {}
    mangled_sig_iterator = Mangler(sigcopy)
    for mangled_sig in mangled_sig_iterator:
        try:
            if (public_key.verify(testmessage, mangled_sig) == VALID):
                print "failed: invalid signature accepted (mangled byte: " + str(mangled_sig_iterator.i) + ")"
                public_key_class.deserialize(mangled_sig).print_hex()
                sys.exit(1)
        except ValueError as err:
            if err.args[0] not in err_list:
                raise
            else:
                errdict[err.args[0]] = errdict.get(err.args[0], 0) + 1
    print "error counts:"
    for errkey in errdict:
        print "\t" + errkey.ljust(40)[7:] + str(errdict[errkey])
    print "passed"

    print "mangled public key parse test",
    mangled_pub_iterator = Mangler(public_key_buffer)
    errdict = {}
    for mangled_pub in mangled_pub_iterator:
        try:
            public_key = public_key_class.deserialize(mangled_pub)
            if public_key.verify(testmessage, mangled_sig) == VALID:
                print "failed: invalid signature accepted (mangled byte: " + str(mangled_sig_iterator.i) + ")"
                LmotsSignature.deserialize(mangled_sig).print_hex()
                sys.exit(1)
        except ValueError as err:
            if err.args[0] not in err_list:
                raise
            else:
                errdict[err.args[0]] = errdict.get(err.args[0], 0) + 1
    print "error counts:"
    for errkey in errdict:
        print "\t" + errkey.ljust(40)[7:] + str(errdict[errkey])
    print "passed"


def err_handle(err):
    if err.args[0] in err_list:
        print str(err.args)
    else:
        raise Exception()