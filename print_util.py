from utils import string_to_hex


class PrintUtl(object):
    margin = 12
    width = 16

    @classmethod
    def print_hex(cls, LHS, RHS, comment=""):
        s = RHS
        LHS = LHS + (" " * (cls.margin - len(LHS)))
        if len(s) < cls.width and comment != "":
            comment = " " * 2 * (cls.width - len(s)) + " # " + comment
        print(LHS + string_to_hex(s[0:cls.width]) + comment)
        s = s[cls.width:]
        LHS = " " * cls.margin
        while len(s) is not 0:
            print(LHS + string_to_hex(s[0:cls.width]))
            s = s[cls.width:]

    @classmethod
    def print_line(cls):
        print "-" * (cls.margin + 2*cls.width)