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
from print_util import PrintUtl
#from sig_tests import checksum_test, ntimesig_test
from hss_sig import print_hss_sig
from utils import sha256_hash
from hss import Hss
from hss_serializer import HssSerializer
import argparse
from version import PROGRAM_VERSION
from argparse import RawDescriptionHelpFormatter


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
    accidental overuse.
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


class HssMenu:
    # program name
    PROGRAM_NAME = "hss_cli"
    MENU_MAIN_DESC = "HSS program"

    @staticmethod
    def build_menu():
        # build main parser
        parser = argparse.ArgumentParser(prog=HssMenu.PROGRAM_NAME, description=HssMenu.MENU_MAIN_DESC)
        parser.add_argument('-V', '--version', action='version', version='%(prog)s (version ' + PROGRAM_VERSION + ')')

        # build the sub program parsers
        main_subs = parser.add_subparsers(title=HssMenu.PROGRAM_NAME + " commands")
        HssMenu.build_genkey_menu(main_subs)
        HssMenu.build_sign_menu(main_subs)
        HssMenu.build_verify_menu(main_subs)
        HssMenu.build_read_menu(main_subs)

        # parse command line args and invoke handler functions
        args = parser.parse_args()
        args.func(args)

    @staticmethod
    def build_genkey_menu(main_subs):
        gen_key = main_subs.add_parser('genkey', help="Creates a <name>.prv and <name>.pub file",
                                       formatter_class=RawDescriptionHelpFormatter,
                                       description="Generates a new HSS key pair and writes the keys to a public and "
                                                   "private key file.\n\n\n"
                                                   "Usage Examples:\n"
                                                   "     genkey -key my_key\n\n")
        gen_key_req = gen_key.add_argument_group('required arguments')
        gen_key_req.add_argument("-key", dest="key_name", required=True, help="Name of the key to be generated.")
        gen_key_req.add_argument("-out", dest="out", default=".", required=False,
                                 help="Output file path for key file.")
        gen_key.set_defaults(func=HssMenu.gen_key_handler)

    @staticmethod
    def build_sign_menu(main_subs):
        sign = main_subs.add_parser('sign', help="Signs one ore more files and writes output as a detached "
                                                 "signature file.",
                                    formatter_class=RawDescriptionHelpFormatter,
                                    description="Signs one or more files using the specified private key file."
                                                "Signature is written to file system as <file>.sig.\n\n\n"
                                                "Usage Examples:\n"
                                                "     sign -key my_key -files my_file1 my_file2\n\n")
        sign_req = sign.add_argument_group('required arguments')
        sign_req.add_argument("-key", dest="key_name", required=True, help="Name of the key to be generated.")
        sign_req.add_argument("-files", dest="file_list", nargs='+', required=True,
                              help="One or more files to sign")
        sign.set_defaults(func=HssMenu.sign_handler)

    @staticmethod
    def build_verify_menu(main_subs):
        verify = main_subs.add_parser('verify', help="Verifies one ore more signature files.",
                                      formatter_class=RawDescriptionHelpFormatter,
                                      description="Verifies one or more files using the specified public key file.\n\n"
                                                  "Usage Examples:\n"
                                                  "     verify -key my_key -files my_file1 my_file2\n\n")
        verify_req = verify.add_argument_group('required arguments')
        verify_req.add_argument("-key", dest="key_name", required=True, help="Name of the key to be generated.")
        verify_req.add_argument("-files", dest="file_list", nargs='+', required=True,
                                help="One or more files to verify")
        verify.set_defaults(func=HssMenu.verify_handler)

    @staticmethod
    def build_read_menu(main_subs):
        read = main_subs.add_parser('read', help="Reads a key file or signature file and displays the data.",
                                    formatter_class=RawDescriptionHelpFormatter,
                                    description="Reads a key file or signature file and displays the data.\n\n"
                                                "Usage Examples:\n"
                                                "     read -files mykey.prv\n\n")
        read_req = read.add_argument_group('required arguments')
        read_req.add_argument("-files", dest="file_list", nargs='+', required=True, help="One or more files to read")
        read.set_defaults(func=HssMenu.read_handler)

    @staticmethod
    def gen_key_handler(args):
        hss = Hss()
        hss_pub, hss_prv = hss.generate_key_pair()
        pvt_file_path = args.out + "/" + args.key_name + ".prv"
        pub_file_path = args.out + "/" + args.key_name + ".pub"
        prv_file = open(pvt_file_path, 'w')
        prv_file.write(calc_check_string(pvt_file_path) + HssSerializer.serialize_private_key(hss_prv))
        pub_file = open(pub_file_path, 'w')
        pub_file.write(HssSerializer.serialize_public_key(hss_pub))

    @staticmethod
    def sign_handler(args):
        # read private key file
        prv_file = open(args.key_name + ".prv", "r+")
        prv_buf = prv_file.read()
        # deserialized the private key
        pvt_hex = verify_check_string(args.key_name + ".prv", prv_buf)
        lms_root_pub_key, lms_root_pvt_key, levels, lms_type, lmots_type = HssSerializer.deserialize_private_key(pvt_hex)

        hss = Hss(lms_type=lms_type, lmots_type=lmots_type)
        hss_pub, hss_prv = hss.build_key_pair_from_root(levels=levels, lms_root_pub_key=lms_root_pub_key,
                                                        lms_root_pvt_key=lms_root_pvt_key)

        # loop file list and sign each file with the specified private key
        for file_name in args.file_list:
            print "signing file " + file_name + " with key " + args.key_name
            # read the message
            msg_file = open(file_name, 'r')
            msg = msg_file.read()
            # sign message
            tmp_sig = hss.sign(msg, hss_prv)
            # update the private key file with notated changes (mark used up keys)
            prv_file.seek(0)
            prv_file.write(calc_check_string(args.key_name + ".prv") + HssSerializer.serialize_private_key(hss_prv))
            prv_file.truncate()
            # write the signature out to file
            sig = open(file_name + ".sig", "w")
            sig.write(tmp_sig)

    @staticmethod
    def verify_handler(args):
        pub_file = open(args.key_name + ".pub", 'r')
        lms_root_pub_key, levels = HssSerializer.deserialize_public_key(pub_file.read())
        hss_pub_key = HssPublicKey(root_pub=lms_root_pub_key, levels=levels)
        hss = Hss(lms_type=lms_root_pub_key.lms_type, lmots_type=lms_root_pub_key.lmots_type)
        for file_name in args.file_list:
            sig_name = file_name + ".sig"
            print "verifying signature " + sig_name + " on file " + file_name + " with pubkey " + args.key_name + ".pub"
            data_sig_file = open(sig_name, 'r')
            sig = data_sig_file.read()
            data_file = open(file_name, 'r')
            msg = data_file.read()
            result = hss.verify(msg, sig, hss_pub_key)
            if result:
                print "VALID"
            else:
                print "INVALID"

    @staticmethod
    def read_handler(args):
        for file_name in args.file_list:
            in_file = open(file_name, 'r')
            file_data = in_file.read()
            if ".sig" in file_name:
                print_hss_sig(file_data)
            elif ".pub" in file_name:
                lms_root_pub_key, levels = HssSerializer.deserialize_public_key(file_data)
                hss_pub_key = HssPublicKey(root_pub=lms_root_pub_key, levels=levels)
                hss_pub_key.print_hex()
            elif ".prv" in file_name:
                # strip check string from start of buffer
                HssPrivateKey.deserialize_print_hex(file_data[32:])
            else:
                PrintUtl.print_line()
                PrintUtl.print_hex("Message", file_data)
                PrintUtl.print_line()


if __name__ == "__main__":
    # build parser menu
    HssMenu.build_menu()

    # if sys.argv[1] == "test":
    #     if len(sys.argv) == 2:
    #         print "missing argument (expected checksum, lmots, lms, hss, or all)"
    #         usage(sys.argv[0])
    #
    #     test_checksum = test_lmots = test_lms = test_hss = False
    #     if "checksum" in sys.argv[2:]:
    #         test_checksum = True
    #     if "lmots" in sys.argv[2:]:
    #         test_lmots = True
    #     if "lms" in sys.argv[2:]:
    #         test_lms = True
    #     if "hss" in sys.argv[2:]:
    #         test_hss = True
    #     if "all" in sys.argv[2:]:
    #         test_checksum = test_lmots = test_lms = test_hss = True
    #
    #     if test_checksum:
    #         checksum_test()
    #     if test_lmots:
    #         ntimesig_test("lmots", verbose=False)
    #     if test_lms:
    #         ntimesig_test("lms", verbose=True)
    #     if test_hss:
    #         ntimesig_test(HssPrivateKey, verbose=True)
    #
    #
