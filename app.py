from flask import Flask, render_template, request, jsonify
import random

app = Flask(__name__)

def make_cipher(key):
    """Create secret alphabet using key"""
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .,!?"
    
    random.seed(key)
    secret = list(alphabet)
    random.shuffle(secret)
    
    encrypt = {alphabet[i]: secret[i] for i in range(len(alphabet))}
    decrypt = {secret[i]: alphabet[i] for i in range(len(alphabet))}
    
    return encrypt, decrypt

# Home page - choose encryption or decryption
@app.route('/')
def home():
    return render_template('index.html')

# Encryption page
@app.route('/encrypt')
def encrypt_page():
    return render_template('encrypt.html')

# Decryption page  
@app.route('/decrypt')
def decrypt_page():
    return render_template('decrypt.html')

# API to handle encryption
@app.route('/api/encrypt', methods=['POST'])
def encrypt_api():
    data = request.json
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
    data = request.json
    text = data.get('text', '')
    key = data.get('key', '')
    
    if not text or not key:
        return jsonify({'error': 'Need text and key'}), 400
    
    _, decrypt_dict = make_cipher(key)
    result = ''.join([decrypt_dict.get(c, c) for c in text])
    
    return jsonify({'result': result})

if __name__ == '__main__':
    print("Simple Encryption App")
    print("Open: http://localhost:5000")
    print("Routes:")
    print("  /          - Home page")
    print("  /encrypt   - Encryption page")
    print("  /decrypt   - Decryption page")
    app.run(debug=True)