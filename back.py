from flask import Flask, request, jsonify, send_from_directory, render_template, session
from cryptography.fernet import Fernet
import traceback
import hashlib
import random
import string
import logging

app = Flask(__name__)

# Set the secret key for the session
app.secret_key = 'supersecretkey'  # Change this to a random secret key in production

# Generate a secret key for encryption
# Note: In a real application, this key should be stored securely and reused across sessions.
secret_key = Fernet.generate_key()
cipher_suite = Fernet(secret_key)

# Set up logging
logging.basicConfig(level=logging.DEBUG)

@app.route('/encrypt', methods=['GET', 'POST'])
def encrypt():
    if request.method == 'POST':
        try:
            data = request.json['data']
            logging.debug('Data to Encrypt: %s', data)
            encrypted_data = cipher_suite.encrypt(data.encode())
            logging.debug('Encrypted Data: %s', encrypted_data.decode())
            return jsonify({'encrypted_data': encrypted_data.decode()})
        except Exception as e:
            logging.error('Encryption Error: %s', str(e))
            traceback.print_exc()
            return jsonify({'error': str(e)}), 500

    return render_template('encrypt.html')

@app.route('/decrypt', methods=['POST'])
def decrypt():
    try:
        # Log the entire JSON payload received
        logging.debug('Received JSON Payload: %s', request.json)
        
        if request.json is None:
            raise ValueError('No JSON payload received')
        
        if 'encrypted_data' not in request.json:
            raise KeyError('encrypted_data key is missing from the payload')
        
        encrypted_data = request.json['encrypted_data']
        logging.debug('Received Encrypted Data: %s', encrypted_data)
        
        decrypted_data = cipher_suite.decrypt(encrypted_data.encode()).decode()
        logging.debug('Decrypted Data: %s', decrypted_data)
        return jsonify({'decrypted_data': decrypted_data})
    except KeyError as e:
        error_message = f'Missing key in JSON payload: {str(e)}'
        logging.error('Decryption Error: %s', error_message)
        traceback.print_exc()
        return jsonify({'error': error_message}), 400
    except ValueError as e:
        error_message = str(e)
        logging.error('Decryption Error: %s', error_message)
        traceback.print_exc()
        return jsonify({'error': error_message}), 400
    except Exception as e:
        logging.error('Decryption Error: %s', str(e))
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/password_cracking', methods=['GET', 'POST'])
def password_cracking():
    if 'hashed_password' not in session:
        random_password = generate_random_password()
        hashed_password, salt = generate_hashed_password(random_password)
        session['hashed_password'] = hashed_password
        session['original_password'] = random_password
        session['salt'] = salt
        logging.debug('Generated new password for the session')

    if request.method == 'POST':
        if 'password' in request.json:
            input_password = request.json['password']
            logging.debug('Received Password: %s', input_password)
            salt = session['salt']  # Use the salt stored in the session
            hashed_input = hashlib.sha256((input_password + salt).encode()).hexdigest()
            logging.debug("Hashed_Input: %s", hashed_input)

            if hashed_input == session['hashed_password']:
                logging.debug("Password has been cracked.")
                return jsonify({'message': 'Password has been cracked.', 'password': input_password, 'method': 'Hash Matching'})
            else:
                dictionary_path = 'dictionary.txt'  # Path to the dictionary file
                cracked_password = dictionary_attack(hashed_input, salt, dictionary_path)
                if cracked_password is not None:
                    logging.debug("Password has been cracked via dictionary attack.")
                    return jsonify({'message': 'Password has been cracked via dictionary attack.', 'password': cracked_password, 'method': 'Dictionary Attack'})
                else:
                    logging.debug("Failed to crack password.")
                    return jsonify({'message': 'Failed to crack password.'})
        else:
            return jsonify({'error': 'No password provided.'})
    return render_template('password_cracking.html')

@app.route('/malnysis', methods=['GET', 'POST'])
def malnysis():
    if request.method == 'POST':
        if 'file' not in request.files:
            return jsonify({'error': 'No file part'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400
        
        try:
            file_content = file.read().decode('utf-8')
        except UnicodeDecodeError:
            file.seek(0)  # Reset file pointer to the beginning
            file_content = file.read().decode('latin1')
        
        result = scan_file(file_content)
        return jsonify(result)
    
    return render_template('malnysis.html')

@app.route('/static/<path:path>')
def send_static(path):
    return send_from_directory('static', path)

@app.route('/')
def index():
    return render_template('dashboard.html')

def generate_random_password(length=8):
    # Generate a random password
    characters = string.ascii_letters + string.digits
    password = ''.join(random.choice(characters) for _ in range(length))
    return password

def generate_hashed_password(password):
    # Generate a random salt
    salt = str(random.getrandbits(128))
    # Combine the password and salt
    combined = password + salt
    # Hash the combined string using SHA-256
    hashed_password = hashlib.sha256(combined.encode()).hexdigest()
    return hashed_password, salt

def dictionary_attack(hash_to_crack, salt, dictionary_file):
    with open(dictionary_file, 'r') as f:
        for word in f:
            word = word.strip()
            hashed_word = hashlib.sha256((word + salt).encode()).hexdigest()
            if hashed_word == hash_to_crack:
                logging.debug("Cracked.")
                return word
    return None

def load_signatures():
    with open('signatures.txt', 'r') as file:
        signatures = file.read().splitlines()
    return signatures

signatures = load_signatures()

def scan_file(content):
    for signature in signatures:
        if signature in content:
            return {'result': 'Malware detected.', 'signature': signature}
    return {'result': 'No malware detected.'}

if __name__ == '__main__':
    app.run(debug=True)
