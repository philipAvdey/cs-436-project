import random
from typing import Tuple

# convert bytes to int
def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, byteorder='big')

# convert int to bytes
def int_to_bytes(i: int, length: int = None) -> bytes:
    if length is None:
        # compute minimal length
        length = (i.bit_length() + 7) // 8 or 1
    return i.to_bytes(length, byteorder='big')

def egcd(a: int, b: int) -> Tuple[int,int,int]:
    if b == 0:
        return (a, 1, 0)
    else:
        g, x1, y1 = egcd(b, a % b)
        return (g, y1, x1 - (a // b) * y1)
    
# modulo inverse
def modinv(a: int, m: int) -> int:
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("modular inverse does not exist")
    return x % m