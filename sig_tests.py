import sys

from merkle import Merkle
from utils import string_to_hex
from lmots_sig import LmotsSignature
from sig_test_mangler import Mangler
from lms import Lms
from lms_type import LmsType
from lmots import Lmots
from lmots_type import LmotsType
from hss_serializer import HssSerializer


test_message = "Hello, world!"


def checksum_test():
    lmots_type_w2 = LmotsType.LMOTS_SHA256_M32_W2

    for j in xrange(0, lmots_type_w2.n):
        x = ""
        for i in xrange(0, lmots_type_w2.n):
            if i == j:
                x = x + chr(0)
            else:
                x = x + chr(0)
        y = x + Merkle.checksum(x, lmots_type_w2.w, lmots_type_w2.ls)
        print "w: " + str(lmots_type_w2.w) + "\tp: " + str(lmots_type_w2.p) + "\tcksm: " + string_to_hex(
            Merkle.checksum(x, lmots_type_w2.w, lmots_type_w2.ls))
        print "x + checksum(x): "
        print_as_coefs(y, lmots_type_w2.w, lmots_type_w2.p)
        print ""


def print_as_coefs(x, w, p):
    num_coefs = len(x) * (8 / w)
    if p > num_coefs:
        raise ValueError("p is invalid")
    for i in xrange(0, p):
        print str(Merkle.coef(x, i, w))
    print "\n"


def ntimesig_test(name, verbose=False):
    if name == "lmots":
        for lmots_type in LmotsType:
            alg = Lmots(lmots_type)
            ntimesig_test_param(alg, verbose)
    elif name == "lms":
        for lmots_type in LmotsType:
            for lms_type in LmsType:
                alg = Lms(lms_type, lmots_type)
                ntimesig_test_param(alg, verbose)
    else:
        raise ValueError("unknown test name {}".format(name))


def ntimesig_test_param(alg, verbose=False):
    """
    Unit test for N-time signatures
    """
    print "N-time signature test"

    # generate key pairs
    public_key, private_key = alg.generate_key_pair()

    public_key_buffer = HssSerializer.serialize_public_key(public_key)

    num_sigs = private_key.signatures_remaining
    num_tests = min(num_sigs, 4096)

    if verbose:
        print "message: \"" + test_message + "\""
        private_key.format_hex()
        public_key.format_hex()
        print "num_signatures_remaining: " + str(private_key.signatures_remaining)

    for i in xrange(0, num_tests):
        sig = alg.sign(test_message, private_key)
        sig_copy = sig

        print "signature byte length: " + str(len(sig))
        if verbose:
            # note: we need an lmsSignature class to enable printing here
            # LmotsSignature.deserialize(sig).print_hex()
            # print_lms_sig(sig)
            print "num_signatures_remaining: " + str(private_key.signatures_remaining)

        print "true positive test: ",
        result = alg.verify(test_message, sig, public_key)
        if result:
            print "passed: message/signature pair is valid as expected"
        else:
            print "failed: message/signature pair is invalid (" + retcode_get_string(result) + ")"
            sys.exit()

        print "false positive test: ",
        if alg.verify("some other message", sig, public_key):
            print "failed: message/signature pair is valid (expected failure)"
            sys.exit(1)
        else:
            print "passed: message/signature pair is invalid as expected"

    print "overuse test: ",
    print "num_sigs: " + str(num_sigs)
    if num_sigs < 1:
        print "error: private key reports that it is a zero-time signature system"
        sys.exit(1)
    for i in xrange(0, num_sigs):
        print "sign attempt #" + str(i)
        try:
            sig = alg.sign("some other message", private_key)
        except ValueError as err:
            if err.args[0] == "private key has no signature operations remaining":
                print "passed: no overuse allowed"
            else:
                err_handle(err)
        else:
            if i > num_sigs:
                print "failed: key overuse occurred; created " + str(i) + "signatures"
                sys.exit()

    print "mangled signature parse test",
    err_dict = {}
    mangled_sig_iterator = Mangler(sig_copy)
    for mangled_sig in mangled_sig_iterator:
        try:
            if alg.verify(test_message, mangled_sig, public_key):
                print "failed: invalid signature accepted (mangled byte: " + str(mangled_sig_iterator.i) + ")"
                public_key.deserialize(mangled_sig).format_hex()
                sys.exit(1)
        except ValueError as err:
            if err[0] != "unknown LMOTS type code" and err[0] != "hex_value is wrong length":
                raise err
            else:
                err_dict[err.args[0]] = err_dict.get(err.args[0], 0) + 1
    print "error counts:"
    for err_key in err_dict:
        print "\t" + err_key.ljust(40)[0:] + str(err_dict[err_key])
    print "passed"

    print "mangled public key parse test",
    mangled_pub_iterator = Mangler(public_key_buffer)
    err_dict = {}
    for mangled_pub in mangled_pub_iterator:
        try:
            public_key = public_key.deserialize(mangled_pub)
            if alg.verify(test_message, mangled_sig, public_key):
                print "failed: invalid signature accepted (mangled byte: " + str(mangled_sig_iterator.i) + ")"
                LmotsSignature.deserialize(mangled_sig).format_hex()
                sys.exit(1)
        except ValueError as err:
            if err[0] != "unknown LMOTS type code" and err[0] != "hex_value is wrong length":
                raise err
            else:
                err_dict[err.args[0]] = err_dict.get(err.args[0], 0) + 1
    print "error counts:"
    for err_key in err_dict:
        print "\t" + err_key.ljust(40)[0:] + str(err_dict[err_key])
    print "passed"


def err_handle(err):
    raise Exception(err)
