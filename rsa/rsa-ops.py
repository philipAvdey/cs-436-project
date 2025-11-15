#!/usr/bin/env python3
"""
rsa_manual.py

Educational/learning RSA implementation WITHOUT third-party crypto libraries.

Features:
- Miller-Rabin probable prime test
- Generate prime numbers of given bit length
- Generate RSA keypair (n, e, d)
- Convert bytes <-> integer
- PKCS#1 v1.5-style padding for encryption (BT=02) and unpadding
- Basic sign (RSA raw on SHA-256 digest) and verify

NOT FOR PRODUCTION. For real systems use a vetted library.
"""
import secrets
import hashlib
import math
from typing import Tuple

from rsa.helper import generate_prime, modinv, bytes_to_int, int_to_bytes
from rsa.padding import pkcs1_v1_5_pad_encrypt, pkcs1_v1_5_unpad_decrypt

# ---------- Utilities ----------



# ---------- RSA key generation ----------

def generate_rsa_keypair(bits: int = 2048, e: int = 65537) -> Tuple[int,int,int]:
    """
    Generate RSA keypair with modulus of ~bits.
    Returns (n, e, d).
    WARNING: This simple function picks p and q of bits/2 each.
    """
    if bits < 64:
        raise ValueError("bits too small for security; use >= 2048 for real use")
    # generate distinct primes p and q
    p = generate_prime()
    q = generate_prime()
    while q == p:
        q = generate_prime()
    n = p * q
    phi = (p - 1) * (q - 1)
    if math.gcd(e, phi) != 1:
        # rare, choose another e or regenerate primes; here we'll regenerate
        return generate_rsa_keypair(bits, e)
    d = modinv(e, phi)
    return (n, e, d)

def rsa_encrypt_int(m: int, e: int, n: int) -> int:
    """Encrypt integer m: c = m^e mod n"""
    if m < 0 or m >= n:
        raise ValueError("message representative out of range")
    return pow(m, e, n)

def rsa_decrypt_int(c: int, d: int, n: int) -> int:
    """Decrypt integer c: m = c^d mod n"""
    return pow(c, d, n)

# Higher-level encrypt/decrypt (with PKCS#1 v1.5 padding)
def rsa_encrypt(message: bytes, e: int, n: int) -> bytes:
    k = (n.bit_length() + 7) // 8
    padded = pkcs1_v1_5_pad_encrypt(message, k)
    m_int = bytes_to_int(padded)
    c_int = rsa_encrypt_int(m_int, e, n)
    return int_to_bytes(c_int, k)

def rsa_decrypt(ciphertext: bytes, d: int, n: int) -> bytes:
    k = (n.bit_length() + 7) // 8
    if len(ciphertext) != k:
        raise ValueError("ciphertext length mismatch")
    c_int = bytes_to_int(ciphertext)
    m_int = rsa_decrypt_int(c_int, d, n)
    padded = int_to_bytes(m_int, k)
    return pkcs1_v1_5_unpad_decrypt(padded)

# ---------- Sign / Verify (simple) ----------
def rsa_sign(message: bytes, d: int, n: int) -> bytes:
    """
    Simple RSA signature on SHA-256 digest.
    This computes s = (H(m))^d mod n, where H is interpreted as integer.
    This is NOT the secure EMSA-PSS scheme — it's for demo.
    """
    h = hashlib.sha256(message).digest()
    h_int = bytes_to_int(h)
    if h_int >= n:
        # extremely unlikely for typical n sizes, but handle.
        raise ValueError("hash value too large for modulus")
    s_int = pow(h_int, d, n)
    k = (n.bit_length() + 7) // 8
    return int_to_bytes(s_int, k)

def rsa_verify(message: bytes, signature: bytes, e: int, n: int) -> bool:
    h = hashlib.sha256(message).digest()
    s_int = bytes_to_int(signature)
    m_int = pow(s_int, e, n)
    recovered = int_to_bytes(m_int)
    # recovered is the integer representation of hash. It may have leading zeros,
    # so align lengths when comparing.
    # Convert both to ints and compare.
    return bytes_to_int(recovered) == bytes_to_int(h)

# ---------- Example / quick tests ----------
if __name__ == "__main__":
    # quick demo (small bits for speed in tests; for real use choose 2048 or more)
    BITS = 1024  # use 2048+ in real experiments
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
