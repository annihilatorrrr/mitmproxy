def setbit(byte, offset, value):
    """
    Set a bit in a byte to 1 if value is truthy, 0 if not.
    """
    return byte | (1 << offset) if value else byte & ~(1 << offset)


def getbit(byte, offset):
    mask = 1 << offset
    return bool(byte & mask)
