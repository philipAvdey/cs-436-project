import secrets
import hashlib
import math
from typing import Tuple

from rsa.helper import generate_prime, modinv, bytes_to_int, int_to_bytes
from rsa.padding import pkcs1_v1_5_pad_encrypt, pkcs1_v1_5_unpad_decrypt

# generate rsa key. returns (n, e, d)
def generate_rsa_keypair(bits: int = 2048, e: int = 65537) -> Tuple[int,int,int]:
    if bits < 64:
        raise ValueError("bits too small for security; use >= 2048 for real use")
    p = generate_prime()
    q = generate_prime()
    while q == p:
        q = generate_prime()
    n = p * q
    phi = (p - 1) * (q - 1)
    if math.gcd(e, phi) != 1:
        return generate_rsa_keypair(bits, e)
    d = modinv(e, phi)
    return (n, e, d)

# encrypt integer m: c = m^e mod n 
def rsa_encrypt_int(m: int, e: int, n: int) -> int:
    if m < 0 or m >= n:
        raise ValueError("message representative out of range")
    return pow(m, e, n)

# decrypt integer c: m = c^d mod n 
def rsa_decrypt_int(c: int, d: int, n: int) -> int:
    return pow(c, d, n)

# encrypt w/bytes and padding (we don't have to use this I don't think)
def rsa_encrypt(message: bytes, e: int, n: int) -> bytes:
    k = (n.bit_length() + 7) // 8
    padded = pkcs1_v1_5_pad_encrypt(message, k)
    m_int = bytes_to_int(padded)
    c_int = rsa_encrypt_int(m_int, e, n)
    return int_to_bytes(c_int, k)

# decrypt bytes
def rsa_decrypt(ciphertext: bytes, d: int, n: int) -> bytes:
    k = (n.bit_length() + 7) // 8
    if len(ciphertext) != k:
        raise ValueError("ciphertext length mismatch")
    c_int = bytes_to_int(ciphertext)
    m_int = rsa_decrypt_int(c_int, d, n)
    padded = int_to_bytes(m_int, k)
    return pkcs1_v1_5_unpad_decrypt(padded)

# sign an rsa message
# s = (H(m))^d mod n, H is integer.
def rsa_sign(message: bytes, d: int, n: int) -> bytes:
    h = hashlib.sha256(message).digest()
    h_int = bytes_to_int(h)
    if h_int >= n:
        raise ValueError("hash value too large for modulus")
    s_int = pow(h_int, d, n)
    k = (n.bit_length() + 7) // 8
    return int_to_bytes(s_int, k)

# verify a signature
# returns true or false based on whether it was verified successfully or not
def rsa_verify(message: bytes, signature: bytes, e: int, n: int) -> bool:
    h_int = bytes_to_int(hashlib.sha256(message).digest())
    s_int = bytes_to_int(signature)
    m_int = pow(s_int, e, n)
    return m_int == h_int

# ---------- Example / quick tests ----------
if __name__ == "__main__":
    BITS = 1024  # we can also use 2048 or other sizes for testing
    print("Generating RSA keypair (this may take a moment)...")
    n, e, d = generate_rsa_keypair(BITS, e=65537)
    print("n bit-length:", n.bit_length())
    msg = b"Hello, RSA manual test!"
    print("Message:", msg)

    # encrypt/decrypt
    ct = rsa_encrypt(msg, e, n)
    print("Ciphertext (hex prefix):", ct.hex()[:80])
    pt = rsa_decrypt(ct, d, n)
    print("Decrypted OK?:", pt == msg)

    # sign/verify
    sig = rsa_sign(msg, d, n)
    ok = rsa_verify(msg, sig, e, n)
    print("Signature valid?:", ok)

    # test message length limit
    try:
        big = b"A" * ((n.bit_length()+7)//8)  # too big
        rsa_encrypt(big, e, n)
    except Exception as exc:
        print("Expected error for too-large message:", exc)
