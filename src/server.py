#!/usr/bin/env python3
"""
Encryption Testing Server
Simple server for testing encryption algorithm attacks
"""
from flask import Flask, request, jsonify, session
import secrets
from rsa import (
    generate_rsa_keypair, rsa_encrypt, rsa_decrypt, 
    rsa_sign, rsa_verify, rsa_encrypt_int, rsa_decrypt_int
)

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Required for sessions
app.config['SESSION_PERMANENT'] = True

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

def get_rsa_keys():
    """Helper to get RSA keys from session with initialization"""
    if 'rsa_keys' not in session:
        session['rsa_keys'] = {}
    return session['rsa_keys']

def validate_rsa_params(bits: int, e: int):
    if bits < 512 or bits > 4096:
        raise ValueError("Bits must be between 512 and 4096")
    if e % 2 == 0 or e < 3:
        raise ValueError("Public exponent must be odd and >= 3")
"""
Request can be made in this format, if custom data preferred:
{"bits": 2048, "e": 3}
"""
@app.route('/rsa/generate-keys', methods=["POST"])
def rsa_server_generate_keys():
    data = request.get_json()
    bits = data.get("bits", 1024)
    e = data.get("e", 65537)
    validate_rsa_params(data, e)
    n, e, d = generate_rsa_keypair(bits, e)
    # Store in session
    keys = get_rsa_keys()
    keys.update({
        "n": n,
        "e": e,
        "d": d
    })
    session.modified = True  # Ensure session is saved

    return jsonify({
        "n": n,
        "e": e
    })

"""
Before running this, keys must be generated using rsa/generate-keys so they get stored in "local storage"
Then those keys are used in encryption

Request should be in this format:
{"message": "Hello world"}

"""
@app.route('/rsa/encrypt', methods=["POST"])
def rsa_server_encrypt():
    data = request.get_json()
    msg_str = data.get("message", "")
    keys = get_rsa_keys()
    e = keys.get("e")
    n = keys.get("n")
    if not e or not n :
        return jsonify({"error": "Error: keys not generated. Run rsa/generate-keys first."}), 400
    if msg_str == "":
        return jsonify({"error": "Error: message not provided. please structure your query: {\"message\": \"Hello world\"}"}), 400
    msg = msg_str.encode()
    encryption = rsa_encrypt(msg, e, n)
    return jsonify({
        "encrypted_message": encryption.hex()
    })

"""
Request should be in this format:
{"encrypted_message": "encrypted message that the user got from rsa/encrypt"}

"""
@app.route('/rsa/decrypt', methods=["POST"])
def rsa_server_decrypt():
    data = request.get_json()
    ciphertext = data.get("encrypted_message", "")
    keys = get_rsa_keys()
    d, n = keys.get("d"), keys.get("n")
    if not d or not n:
        return jsonify({"error": "Error: keys not generated. Run rsa/generate-keys first."}), 400
    if ciphertext == "":
        return jsonify({"error": "Error: encrypted message not provided. please structure your query: {\"encrypted_message\": \"Hello world\"}"}), 400
    try:
        ciphertext_bytes = bytes.fromhex(ciphertext)
        decrypted_message = rsa_decrypt(ciphertext_bytes, d, n)
        return jsonify({
            "decrypted_message": decrypted_message.decode()
        })
    except:
        return jsonify({"error": "Error with rsa decrypt"}), 400    
    
@app.route('/rsa/sign', methods=["POST"])
def rsa_server_sign():
    data = request.get_json()
    msg = data.get("message", "")
    if msg == "":
        return jsonify({"error": "Error: message not provided. please structure your query: {\"message\": \"Hello world\"}"}), 400
    keys = get_rsa_keys()
    d, n = keys.get("d"), keys.get("n")
    if not d or not n:
        return jsonify({"error": "Error: keys not generated. Run rsa/generate-keys first."}), 400
    signature = rsa_sign(msg.encode(), d, n)
    return jsonify({"signature": signature.hex()})

@app.route('/rsa/verify', methods=["POST"])
def rsa_server_verify():
    data = request.get_json()
    signature = data.get("signature", "")
    msg_str = data.get("message", "")
    if msg_str == "" or signature == "":
        return jsonify({"error": "Error: signature or message not provided. please structure your query: {\"signature\": \"signature from rsa/sign\", message: \"Hello World\"}"}), 400
    msg = msg_str.encode()
    keys = get_rsa_keys()
    e = keys.get("e")
    n = keys.get("n")
    if not e or not n:
        return jsonify({"error": "Error: keys not generated. Run rsa/generate-keys first."}), 400
    try:
        signature_bytes = bytes.fromhex(signature)
        valid = rsa_verify(msg, signature_bytes, e, n)
        return jsonify({"valid": valid})
    except:
        return jsonify({"error": "Error with verification occurred"}), 400

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