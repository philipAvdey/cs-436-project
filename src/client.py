#!/usr/bin/env python3
"""
Attack Client
Client for testing encryption attacks
"""

import requests
import json
import time
import random
from Crypto.Cipher import AES
import requests

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