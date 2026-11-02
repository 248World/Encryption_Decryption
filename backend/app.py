from flask import Flask, request, jsonify
from flask_cors import CORS
import random

app = Flask(__name__)

# Only these sites may call the API from a browser
CORS(app, origins=[
    "https://YOUR-PROJECT.vercel.app",   # replace after deploying on Vercel
    "http://localhost:3000",             # local testing
])

def make_cipher(key):
    """Create secret alphabet using key"""
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .,!?"

    random.seed(key)
    secret = list(alphabet)
    random.shuffle(secret)

    encrypt = {alphabet[i]: secret[i] for i in range(len(alphabet))}
    decrypt = {secret[i]: alphabet[i] for i in range(len(alphabet))}

    return encrypt, decrypt

# API to handle encryption
@app.route('/api/encrypt', methods=['POST'])
def encrypt_api():
    data = request.get_json(silent=True) or {}
    text = data.get('text', '')
    key = data.get('key', '')

    if not text or not key:
        return jsonify({'error': 'Need text and key'}), 400

    encrypt_dict, _ = make_cipher(key)
    result = ''.join([encrypt_dict.get(c, c) for c in text])

    return jsonify({'result': result})

# API to handle decryption
@app.route('/api/decrypt', methods=['POST'])
def decrypt_api():
    data = request.get_json(silent=True) or {}
    text = data.get('text', '')
    key = data.get('key', '')

    if not text or not key:
        return jsonify({'error': 'Need text and key'}), 400

    _, decrypt_dict = make_cipher(key)
    result = ''.join([decrypt_dict.get(c, c) for c in text])

    return jsonify({'result': result})

# Simple check that the server is running
@app.route('/health')
def health():
    return jsonify({'status': 'ok'})

if __name__ == '__main__':
    app.run(debug=True, port=5000)