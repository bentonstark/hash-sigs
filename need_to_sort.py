from Crypto import Random


entropySource = Random.new()

# return codes
err_private_key_exhausted = 'error: attempted overuse of private key'
err_unknown_typecode = 'error: unrecognized typecode'
err_bad_length = 'error: parameter has wrong length'
err_bad_value = 'error: parameter has inadmissable value'

# informative return codes for debugging
err_list = [
    #err_private_key_exhausted,
    err_unknown_typecode,
    err_bad_length,
    err_bad_value
]

###################################
INVALID_LMS_TYPE_ERR = 2
INVALID_LMS_PUB_ERR = 3
INVALID_HSS_LEVEL_ERR = 4
INVALID_WITH_REASON = 5

retcode_dict = {
    INVALID_LMS_TYPE_ERR:  "error: LMS typecode mismatch",
    INVALID_LMS_PUB_ERR:   "error: LMS public key mismatch",
    INVALID_HSS_LEVEL_ERR: "error: HSS level mismatch",
    INVALID_WITH_REASON:   "error: exception"
}

def retcode_get_string(x):
    if x in retcode_dict:
        return retcode_dict[x]
    else:
        return "unknown error"
###################################


D_ITER = chr(0x00)  # in the iterations of the LM-OTS algorithms
D_PBLC = chr(0x01)  # when computing the hash of all of the iterates in the LM-OTS algorithm
D_MESG = chr(0x02)  # when computing the hash of the message in the LMOTS algorithms
D_LEAF = chr(0x03)  # when computing the hash of the leaf of an LMS tree
D_INTR = chr(0x04)  # when computing the hash of an interior node of an LMS tree
D_PRG = chr(0x05)  # when computing LMS private keys pseudo-randomly


###################################
# LMOTS typecodes and parameters
#lmots_sha256_n32_w1 = 0x00000001
#lmots_sha256_n32_w2 = 0x00000002
#lmots_sha256_n32_w4 = 0x00000003
#LMOTS_SHA256_N32_W8 = 0x00000004
#
#lmots_params = {
#    #                      n    p  w  ls
#    lmots_sha256_n32_w1: (32, 265, 1, 7),
#    lmots_sha256_n32_w2: (32, 133, 2, 6),
#    lmots_sha256_n32_w4: (32,  67, 4, 4),
#    LMOTS_SHA256_N32_W8: (32, 34, 8, 0)
#}
#
#lmots_name = {
#    lmots_sha256_n32_w1: "LMOTS_SHA256_N32_W1",
#    lmots_sha256_n32_w2: "LMOTS_SHA256_N32_W2",
#    lmots_sha256_n32_w4: "LMOTS_SHA256_N32_W4",
#    LMOTS_SHA256_N32_W8: "LMOTS_SHA256_N32_W8"
#}
###################################


###################################
LMS_SHA256_M32_H05 = 0x00000005
lms_sha256_m32_h10 = 0x00000006
lms_sha256_m32_h15 = 0x00000007
lms_sha256_m32_h20 = 0x00000008
lms_sha256_m32_h25 = 0x00000009

lms_params = {
    #                     m,  h, LenI
    LMS_SHA256_M32_H05: (32, 5, 64),
    lms_sha256_m32_h10: (32, 10, 64),
    lms_sha256_m32_h15: (32, 15, 64),
    lms_sha256_m32_h20: (32, 20, 64),
    lms_sha256_m32_h25: (32, 25, 64)
}

lms_name = {
    LMS_SHA256_M32_H05: "LMS_SHA256_M32_H5",
    lms_sha256_m32_h10: "LMS_SHA256_M32_H10",
    lms_sha256_m32_h15: "LMS_SHA256_M32_H15",
    lms_sha256_m32_h20: "LMS_SHA256_M32_H20",
    lms_sha256_m32_h25: "LMS_SHA256_M32_H25"
}
###################################


