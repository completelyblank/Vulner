from flask import Flask, request, jsonify, send_from_directory, render_template
from cryptography.fernet import Fernet
import traceback

app = Flask(__name__)

# Generate a secret key
# Note: In a real application, this key should be stored securely and reused across sessions.
secret_key = Fernet.generate_key()
cipher_suite = Fernet(secret_key)

@app.route('/encrypt', methods=['POST'])
def encrypt():
    try:
        data = request.json['data']
        print('Data to Encrypt:', data)
        encrypted_data = cipher_suite.encrypt(data.encode())
        print('Encrypted Data:', encrypted_data.decode())
        return jsonify({'encrypted_data': encrypted_data.decode()})
    except Exception as e:
        print('Encryption Error:', str(e))
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/decrypt', methods=['POST'])
def decrypt():
    try:
        # Log the entire JSON payload received
        print('Received JSON Payload:', request.json)
        
        if request.json is None:
            raise ValueError('No JSON payload received')
        
        if 'encrypted_data' not in request.json:
            raise KeyError('encrypted_data key is missing from the payload')
        
        encrypted_data = request.json['encrypted_data']
        print('Received Encrypted Data:', encrypted_data)
        
        decrypted_data = cipher_suite.decrypt(encrypted_data.encode()).decode()
        print('Decrypted Data:', decrypted_data)
        return jsonify({'decrypted_data': decrypted_data})
    except KeyError as e:
        error_message = f'Missing key in JSON payload: {str(e)}'
        print('Decryption Error:', error_message)
        traceback.print_exc()
        return jsonify({'error': error_message}), 400
    except ValueError as e:
        error_message = str(e)
        print('Decryption Error:', error_message)
        traceback.print_exc()
        return jsonify({'error': error_message}), 400
    except Exception as e:
        print('Decryption Error:', str(e))
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/static/<path:path>')
def send_static(path):
    return send_from_directory('static', path)

@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
