from rsa.helper import bytes_to_int, int_to_bytes

# Encrypt integer m: c = m^e mod n
def rsa_encrypt_int(m: int, e: int, n: int) -> int:
    if m < 0 or m >= n:
        raise ValueError("message representative out of range")
    return pow(m, e, n)

# Decrypt integer c: m = c^d mod n
def rsa_decrypt_int(c: int, d: int, n: int) -> int:
    return pow(c, d, n)

# Encrypt string without padding
def rsa_encrypt(message: str, e: int, n: int) -> bytes:
    message_bytes = message.encode("utf-8")
    m_int = bytes_to_int(message_bytes)
    if m_int >= n:
        raise ValueError("message too large for modulus", m_int, n)
    c_int = rsa_encrypt_int(m_int, e, n)
    k = (n.bit_length() + 7) // 8
    return int_to_bytes(c_int, k)

# Decrypt bytes without padding
def rsa_decrypt(ciphertext: bytes, d: int, n: int) -> str:
    c_int = bytes_to_int(ciphertext)
    m_int = rsa_decrypt_int(c_int, d, n)
    k = (n.bit_length() + 7) // 8
    message_bytes = int_to_bytes(m_int, k).lstrip(b'\x00')  # remove leading zeros
    return message_bytes.decode("utf-8")
