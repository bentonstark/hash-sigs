from enum import Enum


class LmotsType(Enum):
    """
    Leighton-Micali One Time Signature (LMOTS) Algorithm Type Enumeration
    """

    def __new__(cls, *args, **kwds):
        value = len(cls.__members__) + 1
        obj = object.__new__(cls)
        obj._value_ = value
        return obj

    def __init__(self, n, p, w, ls, type_code):
        self.n = n
        self.p = p
        self.w = w
        self.ls = ls
        self.type_code = type_code

    #                      n    p  w  ls type_code
    LMOTS_SHA256_M32_W1 = 32, 265, 1, 7, 0x00000001
    LMOTS_SHA256_M32_W2 = 32, 133, 2, 6, 0x00000002
    LMOTS_SHA256_M32_W4 = 32,  67, 4, 4, 0x00000003
    LMOTS_SHA256_M32_W8 = 32,  34, 8, 0, 0x00000004

    @staticmethod
    def get_by_type_code(type_code):
        if type_code == LmotsType.LMOTS_SHA256_M32_W1.type_code:
            return LmotsType.LMOTS_SHA256_M32_W1
        elif type_code == LmotsType.LMOTS_SHA256_M32_W2.type_code:
            return LmotsType.LMOTS_SHA256_M32_W2
        elif type_code == LmotsType.LMOTS_SHA256_M32_W4.type_code:
            return LmotsType.LMOTS_SHA256_M32_W4
        elif type_code == LmotsType.LMOTS_SHA256_M32_W8.type_code:
            return LmotsType.LMOTS_SHA256_M32_W8
        else:
            raise ValueError("unknown LMOTS type code", str(type_code))

    @staticmethod
    def get_param_list():
        params = {}
        for t in LmotsType:
            params[t.name] = (t.n, t.p, t.w, t.ls)
        return params

