# ---------- PKCS#1 v1.5 encryption padding (BT = 02) ----------
# For demo only. Real implementations should prefer OAEP.
import os

# encryption padding
# k = length in bytes of modulus n 
def pkcs1_v1_5_pad_encrypt(message: bytes, k: int) -> bytes:
    mlen = len(message)
    if mlen > k - 11:
        raise ValueError("message too long for PKCS#1 v1.5 padding")
    ps_len = k - mlen - 3
    ps = bytearray()
    while len(ps) < ps_len:
        b = os.urandom(1)
        if b != b'\x00':
            ps.extend(b)
    return b"\x00\x02" + bytes(ps) + b"\x00" + message

# decrypt padding
def pkcs1_v1_5_unpad_decrypt(padded: bytes) -> bytes:
    if len(padded) < 11:
        raise ValueError("decryption error (padded too short)")
    if not (padded[0] == 0x00 and padded[1] == 0x02):
        raise ValueError("decryption error (invalid padding)")
    try:
        sep_idx = padded.index(0x00, 2)
    except ValueError:
        raise ValueError("decryption error (no separator)")
    if sep_idx < 10:
        raise ValueError("decryption error (ps too short)")
    return padded[sep_idx+1:]