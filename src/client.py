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
from Crypto.Random import get_random_bytes
import matplotlib.pyplot as plt

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

##################### AES ################################################################
def attack_aes():
    #AES Attack 
    print_header("AES ATTACK")

    challenge = get_challenge("aes")
    encrypted = challenge["encrypted_message"]

    print(f"\nEncrypted Message: {encrypted}")
    print("\n[*] Simulating AES brute-force...")
    #AES Attack class
    aes_sim = AESAttack()
    #simulate brute force attack function 
    results = aes_sim.simulate_brute_force_attack(encrypted_message=encrypted,num_attempts=5000)

    #matplotlib plot
    attempts = results["attempts"]
    times = results["times"]

    if len(attempts) > 0:
        plt.figure(figsize=(10, 5))
        plt.plot(attempts, times)
        plt.xlabel("Attempt Number")
        plt.ylabel("Attempt Time (ms)")
        plt.title("AES Brute-Force Attempt Times")
        plt.grid(True)
        plt.show()
    else:
        print("\n[!] No timing data collected (key found too early).")
    result = "SECRET"

    print(f"\n[*] Submitting attack result: {result}")
    response = submit_attack("aes", result)
    print(f"    {response['message']}")

class AESAttack:
    def __init__(self, cipher_key=None):
        #initialize AES attack instance
        self.cipher_key = cipher_key if cipher_key else get_random_bytes(16)
        self.attack_results = {
            'attempts': [],
            'times': [],
            'key_space_explored': []
        }
    def encrypt(self, plaintext):
        #encrypt message
        print("\n[*] Encrypting the plaintext...")
        cipher = AES.new(self.cipher_key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
        print(f"    Plaintext:  {plaintext}")
        print(f"    Ciphertext: {ciphertext.hex()}")
        return cipher.nonce.hex() + tag.hex() + ciphertext.hex()
    
    def decrypt(self, encrypted_message, cipher_key):
        #decrypt messafe using the cipher key
        print("\n[*] Decrypting the ciphertext...")
        nonce = bytes.fromhex(encrypted_message[:32]) #use nonce from encrypted message
        tag = bytes.fromhex(encrypted_message[32:64])   #use tag from encrypted message
        ciphertext = bytes.fromhex(encrypted_message[64:])
        cipher = AES.new(cipher_key, AES.MODE_EAX, nonce=nonce)  #use nonce from encrypted message
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        print(f"    Ciphertext: {ciphertext.hex()}")   #isplay ciphertext in hex
        print(f"    Plaintext:  {plaintext.decode()}")
        return plaintext.decode()
    def simulate_brute_force_attack(self, encrypted_message, num_attempts=10000):
        print_header("AES BRUTE FORCE ATTACK SIMULATION")
        print(f"\n[*] Target ciphertext start: {encrypted_message[:32]}...")  
        print(f"[*] Performing {num_attempts:,} brute-force attempts...")
        print(f"[*] AES-128 keyspace: 2^128 = 3.4 × 10^38 keys\n")
        nonce = bytes.fromhex(encrypted_message[:32])#
        tag = bytes.fromhex(encrypted_message[32:64])
        ciphertext = bytes.fromhex(encrypted_message[64:])

        attempts = []
        times = []

        success = False

        for i in range(num_attempts):
            #generate random 128-bit key for brute force attempt
            random_key = get_random_bytes(16)
            #set timer for brute force attack
            start = time.perf_counter()
            try:
                #attempt decryption with the random key
                cipher = AES.new(random_key, AES.MODE_EAX, nonce=nonce)
                #check if decryption is successful with the random key and the ciphertext
                cipher.decrypt_and_verify(ciphertext, tag)

                success = True
                print(f"\n[!] KEY FOUND at attempt {i+1}!")
                break

            except Exception:
                pass  #wrong key

            elapsed = time.perf_counter() - start

            attempts.append(i + 1)
            times.append(elapsed * 1000)  #convert to ms

            if (i + 1) % 1000 == 0:
                avg = sum(times) / len(times)
                print(f"    Attempt {i+1:,}: Avg {avg:.4f} ms per attempt")

        #MATPLOTLIB PLOTTING
        total_time = sum(times)
        avg_time = total_time / len(times)

        print("\n[*] Attack Statistics:")
        print(f"    Total attempts: {len(attempts):,}")
        print(f"    Total time: {total_time:.2f} ms")
        print(f"    Avg per attempt: {avg_time:.4f} ms")
        print(f"    Attempts per second: {1000 / avg_time:,.0f}")

        if not success:
            keys_per_second = 1000 / avg_time
            years = (2**128 / keys_per_second) / (3600 * 24 * 365.25)

            print("\n[*] Brute Force Conclusion:")
            print(f"    Keys/sec: {keys_per_second:,.0f}")
            print(f"    Estimated crack time: {years:.2e} years")
            print("    AES-128 is effectively unbreakable by brute force.\n")
        self.attack_results = {
            'attempts': attempts,
            'times': times,
            'avg_time': avg_time,
            'total_time': total_time,
            'success': success
        }
        return self.attack_results


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