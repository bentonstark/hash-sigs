from need_to_sort import err_unknown_typecode, err_bad_value, lmots_params, lms_params, lms_name
from utils import u32str, hex_u32_to_int, hex_u32_to_int, serialize_array
from lmots_sig import LmotsSignature
from printutl import PrintUtl


def serialize_lms_sig(typecode, q, lmots_sig, path):
    return u32str(q) + lmots_sig + u32str(typecode) + serialize_array(path)


def deserialize_lms_sig(hex_value):
    q = hex_u32_to_int(hex_value[0:4])
    # print "q: " + str(q)
    lmots_type = hex_u32_to_int(hex_value[4:8])
    # print "lmots_type: " + str(lmots_type)
    if lmots_type in lmots_params:
        pos = 4 + LmotsSignature.bytes(lmots_type)
    else:
        raise ValueError(err_unknown_typecode, str(lmots_type))
    lmots_sig = hex_value[4:pos]
    lms_type = hex_u32_to_int(hex_value[pos:pos + 4])
    if lms_type in lms_params:
        m, h, LenI = lms_params[lms_type]
    else:
        raise ValueError(err_unknown_typecode, str(lms_type))
    if q >= 2**h:
        raise ValueError(err_bad_value)
    pos = pos + 4
    path = list()
    for i in xrange(0, h):
        path.append(hex_value[pos:pos + m])
        pos = pos + m
    # PrintUtl.print_hex("buffer tail", buffer[pos:])
    return lms_type, q, lmots_sig, path


def parse_lms_sig(hex_value):
    lmots_type = hex_u32_to_int(hex_value[4:8])
    if lmots_type in lmots_params:
        pos = 4 + LmotsSignature.bytes(lmots_type)
    else:
        raise ValueError(err_unknown_typecode)
    lms_type = hex_u32_to_int(hex_value[pos:pos + 4])
    if lms_type in lms_params:
        m, h, LenI = lms_params[lms_type]
    else:
        raise ValueError(err_unknown_typecode)
    pos = pos + 4 + h*m
    return hex_value[0:pos], hex_value[pos:]


def print_lms_sig(sig):
    PrintUtl.print_line()
    print "LMS signature"
    lms_type, q, lmots_sig, path = deserialize_lms_sig(sig)
    PrintUtl.print_hex("q", u32str(q))
    LmotsSignature.deserialize(lmots_sig).print_hex()
    PrintUtl.print_hex("LMS type", u32str(lms_type), lms_name[lms_type])
    for i, e in enumerate(path):
        PrintUtl.print_hex("path[" + str(i) + "]", e)