from need_to_sort import entropySource


class ByteFlipMangler:
    def __init__(self, value):
        self.value = value
        self.i = 0

    def __iter__(self):
        return self

    def next(self):
        if self.i < len(self.value):
            i = self.i
            self.i += 1
            tmp = entropySource.read(1)
            while tmp == self.value[i]:
                tmp = entropySource.read(1)
            return self.value[:i] + tmp + self.value[i+1:]
        else:
            raise StopIteration()


class ByteSnipMangler:
    def __init__(self, value):
        self.value = value
        self.i = 0

    def __iter__(self):
        return self

    def next(self):
        if self.i < len(self.value):
            i = self.i
            self.i += 1
            return self.value[:i] + self.value[i+1:]
        else:
            raise StopIteration()


class Mangler:
    def __init__(self, value):
        self.byte_flip = ByteFlipMangler(value)
        self.byte_snip = ByteSnipMangler(value)

    def __iter__(self):
        return self

    def next(self):
        try:
            return self.byte_flip.next()
        except StopIteration:
            return self.byte_snip.next()