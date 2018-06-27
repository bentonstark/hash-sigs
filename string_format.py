from utils import string_to_hex


class StringFormat(object):
    margin = 12
    width = 16

    @staticmethod
    def format_hex(str_list, lhs, rhs, comment=""):
        s = rhs
        lhs = lhs + (" " * (StringFormat.margin - len(lhs)))
        if len(s) < StringFormat.width and comment != "":
            comment = " " * 2 * (StringFormat.width - len(s)) + " # " + comment
        str_list.append(lhs + string_to_hex(s[0:StringFormat.width]) + comment)
        s = s[StringFormat.width:]
        lhs = " " * StringFormat.margin
        while len(s) is not 0:
            str_list.append(lhs + string_to_hex(s[0:StringFormat.width]))
            s = s[StringFormat.width:]

    @staticmethod
    def line(str_list):
        str_list.append("-" * (StringFormat.margin + 2 * StringFormat.width))