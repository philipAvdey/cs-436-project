#!/usr/bin/env python3
"""
Encryption Testing Server
Simple server for testing encryption algorithm attacks
"""

from flask import Flask, request, jsonify
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import random

last_byte = random.randint(0, 255)
DES_KEY = b"8byteke" + bytes([last_byte])  # 8-byte key for DES (56 bits)
print(f"[Server] Using DES key: {DES_KEY.hex()} (last byte = {last_byte})")

def encrypt_des_message(plaintext: str) -> str:
    """Encrypt plaintext using DES (ECB mode)"""
    cipher = DES.new(DES_KEY, DES.MODE_ECB)
    padded = pad(plaintext.encode(), DES.block_size)
    return cipher.encrypt(padded).hex()

def decrypt_des_message(ciphertext_hex: str) -> str:
    """Decrypt hex-encoded ciphertext using DES"""
    cipher = DES.new(DES_KEY, DES.MODE_ECB)
    ciphertext = bytes.fromhex(ciphertext_hex)
    decrypted = unpad(cipher.decrypt(ciphertext), DES.block_size)
    return decrypted.decode()

app = Flask(__name__)

# Store encryption challenges
challenges = {
    "rsa": {
        "algorithm": "RSA",
        "public_key": {"n": 3233, "e": 17},
        "encrypted_message": 2557,
        "secret": 42
    },
    "des": {
        "algorithm": "DES",
        "encrypted_message": encrypt_des_message("HELLO"),
        "secret": "HELLO",
        "last_byte": last_byte
    },
    "aes": {
        "algorithm": "AES",
        "encrypted_message": "5F9D2A8E3B7C1D4F",
        "secret": "SECRET"
    }
}

@app.route('/')
def home():
    """Main page - show available algorithms"""
    return jsonify({
        "server": "Encryption Attack Server",
        "algorithms": list(challenges.keys()),
        "endpoints": {
            "/challenge/<algorithm>": "Get encryption challenge",
            "/attack/<algorithm>": "Submit your attack"
        }
    })


@app.route('/challenge/<algorithm>')
def get_challenge(algorithm):
    """Get the encryption challenge"""
    if algorithm not in challenges:
        return jsonify({"error": "Algorithm not found"}), 404
    
    # Return everything except the secret
    challenge_data = challenges[algorithm].copy()
    challenge_data.pop('secret', None)
    
    return jsonify(challenge_data)


@app.route('/attack/<algorithm>', methods=['POST'])
def submit_attack(algorithm):
    """Submit your attack attempt"""
    if algorithm not in challenges:
        return jsonify({"error": "Algorithm not found"}), 404
    
    data = request.get_json()
    if not data or 'result' not in data:
        return jsonify({"error": "Missing 'result' field"}), 400
    
    # Check if attack was successful
    correct_answer = challenges[algorithm]['secret']
    user_answer = data['result']
    
    # Convert to same type for comparison
    try:
        if isinstance(correct_answer, int):
            user_answer = int(user_answer)
    except:
        pass
    
    if user_answer == correct_answer:
        return jsonify({
            "status": "success",
            "message": f"✓ Correct! You cracked {algorithm.upper()}!"
        })
    else:
        return jsonify({
            "status": "failed",
            "message": "✗ Incorrect. Try again!"
        })


if __name__ == '__main__':
    print("\n" + "="*50)
    print("  ENCRYPTION ATTACK SERVER")
    print("="*50)
    print("\nAvailable Algorithms: RSA, DES, AES")
    print("Server: http://localhost:5001")
    print("="*50 + "\n")
    
    app.run(debug=True, port=5001)