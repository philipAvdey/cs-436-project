#!/usr/bin/env python3
"""
Attack Client
Client for testing encryption attacks
"""

import requests

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


def attack_des():
    """DES Attack - Brute force weak key"""
    print_header("DES ATTACK")
    
    # Get challenge
    challenge = get_challenge("des")
    encrypted = challenge['encrypted_message']
    
    print(f"\nEncrypted Message: {encrypted}")
    
    # YOUR ATTACK CODE HERE
    print("\n[*] Attacking DES...")
    print("    TODO: Implement DES key brute force")
    
    # Example: For demo
    result = "HELLO"
    
    # Submit attack
    print(f"\n[*] Submitting result: {result}")
    response = submit_attack("des", result)
    print(f"{response['message']}")


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
    print(f"{response['message']}")


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