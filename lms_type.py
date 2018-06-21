from enum import Enum


class LmsType(Enum):
    """
    Leighton-Micali Signature (LMS) Algorithm Type Enumeration
    """

    def __new__(cls, *args, **kwds):
        value = len(cls.__members__) + 1
        obj = object.__new__(cls)
        obj._value_ = value
        return obj

    def __init__(self, m, h, len_i, hash_alg, type_code):
        self.m = m
        self.h = h
        self.len_i = len_i
        self.hash_alg = hash_alg
        self.type_code = type_code

    #                    m  h len_i  hash_alg  type_code
    LMS_SHA256_M32_H5 = 32, 5,   64, 'sha256', 5
    LMS_SHA256_M32_H10 = 32, 10, 64, 'sha256', 6
    LMS_SHA256_M32_H15 = 32, 15, 64, 'sha256', 7
    LMS_SHA256_M32_H20 = 32, 20, 64, 'sha256', 8
    LMS_SHA256_M32_H25 = 32, 25, 64, 'sha256', 9

    @staticmethod
    def get_by_type_code(type_code):
        if type_code == LmsType.LMS_SHA256_M32_H5.type_code:
            return LmsType.LMS_SHA256_M32_H5
        elif type_code == LmsType.LMS_SHA256_M32_H10.type_code:
            return LmsType.LMS_SHA256_M32_H10
        elif type_code == LmsType.LMS_SHA256_M32_H15.type_code:
            return LmsType.LMS_SHA256_M32_H15
        elif type_code == LmsType.LMS_SHA256_M32_H20.type_code:
            return LmsType.LMS_SHA256_M32_H20
        elif type_code == LmsType.LMS_SHA256_M32_H25.type_code:
            return LmsType.LMS_SHA256_M32_H25
        else:
            raise ValueError("unknown LMS type code", str(type_code))