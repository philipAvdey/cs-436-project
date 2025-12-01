#!/usr/bin/env python3
"""
Attack Client
Client for testing encryption attacks
"""
import time
import requests

from Crypto.Cipher import DES
from Crypto.Util.Padding import unpad
from Crypto.Cipher import AES

from rsa.rsa_ops import rsa_decrypt
from rsa.helper import modinv

SERVER_URL = "http://localhost:5001"

def print_header(text):
    """Print formatted header"""
    print("\n" + "="*50)
    print(f"  {text}")
    print("="*50)


def get_challenge(algorithm):
    """Get encryption challenge from server"""
    response = requests.get(f"{SERVER_URL}/challenge/{algorithm}")
    return response.json()


def submit_attack(algorithm, result):
    """Submit attack result to server"""
    response = requests.post(
        f"{SERVER_URL}/attack/{algorithm}",
        json={"result": result}
    )
    return response.json()


# ============================================
# ATTACK IMPLEMENTATIONS
# ============================================

def attack_rsa():
    """RSA Attack - Factor n and decrypt message using rsa_ops functions"""
    print_header("RSA ATTACK")

    # Get challenge
    challenge = get_challenge("rsa")
    n = challenge['public_key']['n']
    e = challenge['public_key']['e']
    c_hex = challenge['encrypted_message']
    c = bytes.fromhex(c_hex)

    print(f"\nPublic Key: n={n}, e={e}")
    print(f"Encrypted Message: {c}")

    print("\n[*] Factoring n...")

    def factor(n):
        for i in range(2, int(n**0.5) + 1):
            if n % i == 0:
                return i, n // i
        return None, None

    p, q = factor(n)
    if p is None or q is None:
        print(f"Error, p or q were not factored correctly")
        return
    print(f"Found factors: p={p}, q={q}")

    phi = (p - 1) * (q - 1)
    print(f"φ(n) = {phi}")

    d = modinv(e, phi)
    print(f"Private key d={d}")

    m = rsa_decrypt(c, d, n)
    print(f"Decrypted message: {m}")
    
    print("\n[*] Submitting result...")
    response = submit_attack("rsa", m)
    print(f"{response['message']}")


def decrypt_des_message(ciphertext_hex, key):
    """Decrypt using given key"""
    cipher = DES.new(key, DES.MODE_ECB)
    ciphertext = bytes.fromhex(ciphertext_hex)
    return unpad(cipher.decrypt(ciphertext), DES.block_size).decode()


def brute_force_des(ciphertext_hex, plaintext_hint, correct_last_byte=None):
    """
    Brute-force 256 possible 8th bytes of the DES key.
    Stops when correct_last_byte is reached.
    """
    ciphertext = bytes.fromhex(ciphertext_hex)
    base_key = b"8byteke"
    print(f"\n[*] Starting reduced key brute-force demo (256 possibilities)...")
    start = time.time()

    for attempts, last_byte in enumerate(range(256), start=1):
        key = base_key + bytes([last_byte])
        cipher = DES.new(key, DES.MODE_ECB)
        try:
            decrypted = unpad(cipher.decrypt(ciphertext), DES.block_size)
            text = decrypted.decode(errors="ignore")
            if plaintext_hint in text:
                elapsed = time.time() - start
                print(f"\n[+] Found key: {key}")
                print(f"[+] Decrypted text: {text}")
                print(f"[+] Attempts: {attempts} | Time: {elapsed:.3f}s")
                return text
        except Exception:
            pass

        if attempts % 20 == 0:
            print(f"   Tried {attempts} keys...", end="\r")

        # stop when we hit the correct last byte for a visually variable result
        if correct_last_byte is not None and last_byte == correct_last_byte:
            elapsed = time.time() - start
            print(f"\n[+] Found demo key: {key}")
            print(f"[+] Attempts: {attempts} | Time: {elapsed:.3f}s")
            # decrypt once with actual key to show real plaintext
            try:
                decrypted = unpad(cipher.decrypt(ciphertext), DES.block_size)
                text = decrypted.decode(errors="ignore")
                print(f"[+] Decrypted text: {text}")
                return text
            except Exception:
                return plaintext_hint

    print("[-] Key not found in reduced key space (demo).")
    return None

def attack_des():
    print_header("DES ENCRYPTION AND BRUTE-FORCE DEMO")

    challenge = get_challenge("des")
    encrypted = challenge["encrypted_message"]
    correct_last_byte = challenge.get("last_byte")
    print(f"\nEncrypted Message: {encrypted}")

    # Brute-force simulation
    print("\n[*] Simulating reduced-key brute-force...")
    demo_result = brute_force_des(encrypted, "HELLO")

    # Choose whichever result to submit (either direct or found)
    final_result = demo_result if demo_result else "[unknown result]"

    print("\n[*] Submitting result to server...")
    response = submit_attack("des", final_result)
    print(f"    {response['message']}")

##################### AES ATTACK ################################################################
def attack_aes():
    dat = get_challenge("aes")    #collect data from get_challenge 

    #break down encrypted message################################
    nonce = bytes.fromhex(dat["encrypted_message"]["nonce"]) 
    tag = bytes.fromhex(dat["encrypted_message"]["tag"])
    ciphertext = bytes.fromhex(dat["encrypted_message"]["ciphertext"])
    ####################outputs###########################################
    print("AES-16 Brute force attack")
    print(f"Nonce:{nonce.hex()}")
    print(f"Tag:{tag.hex()}")
    print(f"Ciphertext:{ciphertext.hex()}")
######################### actual attack################
    for key_val in range(65536):    #loop through all possible combinations for AES 16 0 - 65536
        #test each key val as the key
        real_key = key_val.to_bytes(2, "big")   #big for most sig bytes sim 
        full_key = real_key * 8                  #expand to 16 bytes
        try:
            cipher = AES.new(full_key, AES.MODE_GCM, nonce=nonce)       #create cipher with test key and nonce
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)         #collect plain text from cipher

            print(f"KEY: {key_val}")
            print(f"PLAINTEXT: {plaintext}")
            payload_res = {"result": key_val}   #send payload for confirmation
            resp = requests.post("http://localhost:5001/attack/aes", json=payload_res)
            print(resp.json()["message"])
            print("SUCCESS!!!!!!!!!!!!!!!!!!!!!!!")
            return

        except Exception:
            continue

    print("ATTACK FAILED")

# ============================================
# MAIN MENU
# ============================================

def main():
    """Main menu"""
    print_header("ENCRYPTION ATTACK CLIENT")
    
    print("\nSelect Algorithm to Attack:")
    print("1. RSA")
    print("2. DES")
    print("3. AES")
    print("4. Exit")
    
    choice = input("\nChoice: ")
    
    if choice == "1":
        attack_rsa()
    elif choice == "2":
        attack_des()
    elif choice == "3":
        attack_aes()
    elif choice == "4":
        print("\nGoodbye!")
        return
    else:
        print("\nInvalid choice!")
    
    # Ask if they want to continue
    if input("\n\nAttack another? (y/n): ").lower() == 'y':
        main()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nExiting...")
    except requests.exceptions.ConnectionError:
        print("\n[!] Cannot connect to server!")
        print("    Make sure server is running: python server.py")