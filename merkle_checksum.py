from utils import u16str


def coef(S, i, w):
    return (2**w - 1) & (ord(S[i*w/8]) >> (8 - (w*(i%(8/w)) + w)))


def checksum(x, w, ls):
    sum = 0
    num_coefs = len(x)*(8/w)
    for i in xrange(0, num_coefs):
        sum = sum + (2**w - 1) - coef(x, i, w)
    return u16str(sum << ls)