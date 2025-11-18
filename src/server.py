#!/usr/bin/env python3
"""
Encryption Testing Server
Simple server for testing encryption algorithm attacks
"""

from flask import Flask, request, jsonify

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