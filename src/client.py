#!/usr/bin/env python3
"""
Attack Client
Client for testing encryption attacks
"""
import random
import time
import requests
import json
from Crypto.Cipher import DES
from Crypto.Util.Padding import unpad

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
    """RSA Attack - Factor n to find private key"""
    print_header("RSA ATTACK")
    
    # Get challenge
    challenge = get_challenge("rsa")
    n = challenge['public_key']['n']
    e = challenge['public_key']['e']
    encrypted = challenge['encrypted_message']
    
    print(f"\nPublic Key: n={n}, e={e}")
    print(f"Encrypted Message: {encrypted}")
    
    # YOUR ATTACK CODE HERE
    print("\n[*] Attacking RSA...")
    print("    TODO: Factor n, calculate private key, decrypt message")
    
    # Example: For demo, we'll just use the answer
    result = 42
    
    # Submit attack
    print(f"\n[*] Submitting result: {result}")
    response = submit_attack("rsa", result)
    print(f"    {response['message']}")


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


def attack_aes():
    """AES Attack - Side channel attack"""
    print_header("AES ATTACK")
    
    # Get challenge
    challenge = get_challenge("aes")
    encrypted = challenge['encrypted_message']
    
    print(f"\nEncrypted Message: {encrypted}")
    
    # YOUR ATTACK CODE HERE
    print("\n[*] Attacking AES...")
    print("    TODO: Implement AES attack")
    
    # Example: For demo
    result = "SECRET"
    
    # Submit attack
    print(f"\n[*] Submitting result: {result}")
    response = submit_attack("aes", result)
    print(f"    {response['message']}")


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