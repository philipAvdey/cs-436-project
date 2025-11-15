# ---------- PKCS#1 v1.5 encryption padding (BT = 02) ----------
# For demo only. Real implementations should prefer OAEP.
import os


def pkcs1_v1_5_pad_encrypt(message: bytes, k: int) -> bytes:
    """
    PKCS#1 v1.5 padding for encryption (block type 02).
    k = length in bytes of modulus n.
    Result is k bytes: 0x00 || 0x02 || PS || 0x00 || M
    PS = random non-zero bytes, length at least 8.
    """
    mlen = len(message)
    if mlen > k - 11:
        raise ValueError("message too long for PKCS#1 v1.5 padding")
    # PS length
    ps_len = k - mlen - 3
    # generate PS of non-zero random bytes
    ps = bytearray()
    while len(ps) < ps_len:
        b = os.urandom(1)
        if b != b'\x00':
            ps.extend(b)
    return b"\x00\x02" + bytes(ps) + b"\x00" + message

def pkcs1_v1_5_unpad_decrypt(padded: bytes) -> bytes:
    """
    Remove PKCS#1 v1.5 padding. Returns message or raises ValueError.
    """
    if len(padded) < 11:
        raise ValueError("decryption error (padded too short)")
    if not (padded[0] == 0x00 and padded[1] == 0x02):
        raise ValueError("decryption error (invalid padding)")
    # find 0x00 separator
    try:
        sep_idx = padded.index(0x00, 2)
    except ValueError:
        raise ValueError("decryption error (no separator)")
    # PS must be at least 8 bytes
    if sep_idx < 10:
        raise ValueError("decryption error (ps too short)")
    return padded[sep_idx+1:]