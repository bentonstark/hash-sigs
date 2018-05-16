from need_to_sort import err_unknown_typecode, err_bad_length, lmots_sha256_n32_w8, lmots_params, lmots_name
from utils import u32str, hex_u32_to_int, serialize_array
from printutl import PrintUtl


class LmotsSignature():
    """
    Leighton-Micali One Time Signature
    """
    def __init__(self, C, y, typecode=lmots_sha256_n32_w8):
        self.C = C
        self.y = y
        self.type = typecode

    def serialize(self):
        return u32str(self.type) + self.C + serialize_array(self.y)

    @classmethod
    def deserialize(cls, buffer):
        lmots_type = hex_u32_to_int(buffer[0:4])
        if lmots_type in lmots_params:
            n, p, w, ls = lmots_params[lmots_type]
        else:
            raise ValueError(err_unknown_typecode, str(lmots_type))
        if len(buffer) != cls.bytes(lmots_type):
            raise ValueError(err_bad_length)
        C = buffer[4:n+4]
        y = list()
        pos = n+4
        for i in xrange(0, p):
            y.append(buffer[pos:pos+n])
            pos = pos + n
        return cls(C, y, lmots_type)

    @classmethod
    def bytes(cls, lmots_type):
        n, p, w, ls = lmots_params[lmots_type]
        return 4 + n*(p+1)

    def print_hex(self):
        PrintUtl.print_line()
        print "LMOTS signature"
        PrintUtl.print_hex("LMOTS type", u32str(self.type), lmots_name[self.type])
        PrintUtl.print_hex("C", self.C)
        for i, e in enumerate(self.y):
            PrintUtl.print_hex("y[" + str(i) + "]", e)
        PrintUtl.print_line()