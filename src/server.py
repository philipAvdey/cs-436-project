#!/usr/bin/env python3
"""
Encryption Testing Server
Simple server for testing encryption algorithm attacks
"""

from flask import Flask, request, jsonify
from Crypto.Cipher import AES

app = Flask(__name__)

def aes16_encrypt(secret_val):
    real_key = secret_val.to_bytes(2, 'big')  #convert to 2 byte key
    key = real_key * 8                        #expand to repeated 2 byte key 8 times ; fit 16 byte AES 128 mold
    plaintext = b"SECRET_SECRET?"         #plaintext to be encrypted      
    cipher = AES.new(key, AES.MODE_GCM)                 #create AES cipher with key
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)          #use cipher on plain text for encryption and nonce value
        #nonce for random vals for combination with key
        #tag for auth in AES GCM
        #ciphertext for encrpyted plaintext with 
    return {
        "nonce": cipher.nonce.hex(),  
        "tag": tag.hex(),
        "ciphertext": ciphertext.hex()}

#######################AES global secret val#########################
aes_secret = 65535
aes_enc = aes16_encrypt(aes_secret)      #encrypt with screct val
#######################################################################
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
        "encrypted_message": "8A7B3C2D1E4F5A6B",
        "secret": "HELLO"
    },
    "aes": {
         "algorithm": "AES8",
        "encrypted_message": aes_enc,
        "secret": aes_secret
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