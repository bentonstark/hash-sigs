#!/usr/bin/python

"""
   Copyright (c) 2016 Cisco Systems, Inc.
   All rights reserved.
   
   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions
   are met:
   
     Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
   
     Redistributions in binary form must reproduce the above
     copyright notice, this list of conditions and the following
     disclaimer in the documentation and/or other materials provided
     with the distribution.
   
     Neither the name of the Cisco Systems, Inc. nor the names of its
     contributors may be used to endorse or promote products derived
     from this software without specific prior written permission.
   
   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
   FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
   COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
   INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
   (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
   SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
   HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
   STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
   ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
   OF THE POSSIBILITY OF SUCH DAMAGE.

   hss.py

   Reference implementation for Leighton-Micali Hash Based Signatures
   (HBS) and Hierarchical Signature System (HSS), as per the Internet
   Draft draft-mcgrew-hash-sigs-05.txt.
"""

import sys
import os.path
from hss_pubkey import HssPublicKey
from hss_pvtkey import HssPrivateKey
from lmots_pvtkey import LmotsPrivateKey
from lms_pvtkey import LmsPrivateKey
from need_to_sort import VALID, retcode_get_string
from print_util import PrintUtl
from sig_tests import print_hss_sig, checksum_test, ntimesig_test
from utils import sha256_hash


# ***************************************************************
#                                                               |
#             Hierarchical Signature System (HSS)               |
#                                                               |
# HSS signature format:                                         |
#   (l=number of signed_public_keys)                            |
#   array of l-2 signed_public_keys                             |
#   signature                                                   |
# ***************************************************************


def calc_check_string(path):
    """
    Compute a check string based on the file path, which can be
    included in a file to make sure that the file has not been copied.
    This is useful because hash based signature private key files
    MUST NOT be copied.

    :param path: (not full) path of file
    :return: 32-byte check string 
    """
    return sha256_hash(os.path.abspath(path))


def verify_check_string(path, buffer):
    """
    Verify that the first 32 bytes of buffer are a valid check string
    for path; if so, strip those bytes away and return the result.
    Otherwise, print and error and exit, to ensure that any private
    key file that makes use of this function will be protected against
    accidential overuse.
    """
    if buffer[0:32] != calc_check_string(path):
        print "error: file \"" + path + "\" has been copied or modified"
        sys.exit(1)
    else:
        return buffer[32:]

# Implementation note: it might be useful to add in the last-modified
# time via os.path.getmtime(path), but it might be tricky to
# predict/control that value, especially in a portable way.
# Similarly, the output of uname() could be included.
    

def usage(name):
    """
    Display the program usage options.

    :param name: Name of the file being executed
    :return:
    """
    print "commands:"
    print name + " genkey <name>"                                      
    print "   creates <name>.prv and <name>.pub"
    print ""
    print name + " sign <file> [ <file2> ... ] <prvname>"
    print "   updates <prvname>, then writes signature of <file> to <file>.sig"
    print ""
    print name + " verify <pubname> <file> [ <file2> ... ]"
    print "   verifies file using public key"
    print ""
    print name + " read <file> [ <file2> ... ]"
    print "   read and pretty-print .sig, .pub, .prv file(s)"
    print ""
    print name + " test [all | hss | lms | lmots | checksum ]"
    print "   performs algorithm tests"
    sys.exit(1)


if __name__ == "__main__":

    if len(sys.argv) < 2 or sys.argv[1] not in ["genkey", "sign", "verify", "read", "test"]:
        print "error: first argument must be a command (genkey, sign, verify, read, or test)"
        usage(sys.argv[0])
        sys.exit()

    if sys.argv[1] == "test":
        if len(sys.argv) == 2: 
            print "missing argument (expected checksum, lmots, lms, hss, or all)"
            usage(sys.argv[0])
            
        test_checksum = test_lmots = test_lms = test_hss = False
        if "checksum" in sys.argv[2:]:
            test_checksum = True
        if "lmots" in sys.argv[2:]:
            test_lmots = True
        if "lms" in sys.argv[2:]:
            test_lms = True
        if "hss" in sys.argv[2:]:
            test_hss = True
        if "all" in sys.argv[2:]:
            test_checksum = test_lmots = test_lms = test_hss = True

        if test_checksum:
            checksum_test()
        if test_lmots:
            ntimesig_test(LmotsPrivateKey, verbose=False)
        if test_lms:
            ntimesig_test(LmsPrivateKey, verbose=True)
        if test_hss:
            ntimesig_test(HssPrivateKey, verbose=True)

    if sys.argv[1] == "genkey":
        if len(sys.argv) >= 3:
            for key_name in sys.argv[2:]:
                print "generating key " + key_name
                hss_prv = HssPrivateKey()
                hss_pub = hss_prv.get_public_key()
                prv_file = open(key_name + ".prv", 'w')
                prv_file.write(calc_check_string(key_name + ".prv") + hss_prv.serialize())
                pub_file = open(key_name + ".pub", 'w')
                pub_file.write(hss_pub.serialize())
        else:
            print "error: missing keyname argument(s)\n"
            usage()
            
    if sys.argv[1] == "sign":
        key_name = None
        msg_name_list = list()
        for f in sys.argv[2:]:
            if ".prv" in f:
                if key_name is not None:
                    print "error: too many private keys given on command line"
                key_name = f
            else:
                msg_name_list.append(f)
        if key_name is None:
            print "error: no private key given on command line"
            usage(sys.argv[0])
        if len(msg_name_list) is 0:
            print "error: no messages given on command line"
            usage(sys.argv[0])
        prv_file = open(key_name, "r+")
        prv_buf = prv_file.read()
        hss_prv = HssPrivateKey.deserialize(verify_check_string(key_name, prv_buf))
        for msg_name in msg_name_list:
            print "signing file " + msg_name + " with key " + key_name
            msg_file = open(msg_name, 'r')
            msg = msg_file.read()
            tmp_sig = hss_prv.sign(msg)
            prv_file.seek(0)
            prv_file.write(calc_check_string(key_name) + hss_prv.serialize())
            prv_file.truncate()
            sig = open(msg_name + ".sig", "w")
            sig.write(tmp_sig)

    if sys.argv[1] == "verify":
        pub_name = None
        msg_name_list = list()
        for f in sys.argv[2:]:
            if ".pub" in f:
                if pub_name is not None:
                    print "error: too many public keys given on command line"
                    usage(sys.argv[0])
                pub_name = f
            else:
                msg_name_list.append(f)
        if pub_name is None:
            print "error: no public key given on command line"
            usage(sys.argv[0])
        if len(msg_name_list) is 0:
            print "error: no file(s) to be verified given on command line"
            usage(sys.argv[0])
        pubfile = open(pub_name, 'r')
        pub = HssPublicKey.deserialize(pubfile.read())
        for msg_name in msg_name_list:
            sig_name = msg_name + ".sig"
            print "verifying signature " + sig_name + " on file " + msg_name + " with pubkey " + pub_name
            sig_file = open(sig_name, 'r')
            sig = sig_file.read()
            msg_file = open(msg_name, 'r')
            msg = msg_file.read()
            result = pub.verify(msg, sig)
            if result == VALID:
                print "VALID"
            else:
                print "INVALID (" + retcode_get_string(result) + ")"

    if sys.argv[1] == "read":
        if len(sys.argv) < 3:
            print 'error: expecting filename(s) after "read" command'
            usage(sys.argv[0])

        for f in sys.argv[2:]:
            in_file = open(f, 'r')
            buf = in_file.read()
            if ".sig" in f:
                print_hss_sig(buf)
            elif ".pub" in f:
                HssPublicKey.deserialize(buf).print_hex()
            elif ".prv" in f:
                # strip check string from start of buffer
                HssPrivateKey.deserialize_print_hex(buf[32:])
            else:                
                PrintUtl.print_line()
                PrintUtl.print_hex("Message", buf)
                PrintUtl.print_line()

