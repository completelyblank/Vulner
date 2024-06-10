from flask import Flask, request, jsonify
from cryptography.fernet import Fernet
from flask import render_template

app = Flask(__name__)

# Generate a secret key
secret_key = Fernet.generate_key()

@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.json['data']
    encrypted_data = Fernet(secret_key).encrypt(data.encode())
    return jsonify({'encrypted_data': encrypted_data.decode()})

@app.route('/decrypt', methods=['POST'])
def decrypt():
    encrypted_data = request.json['encrypted_data']
    decrypted_data = Fernet(secret_key).decrypt(encrypted_data.encode()).decode()
    return jsonify({'decrypted_data': decrypted_data})

@app.route('/static/<path:path>')
def send_static(path):
    return send_from_directory('static', path)

@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)