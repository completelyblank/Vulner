from flask import Flask, request, jsonify, send_from_directory, render_template, session
from cryptography.fernet import Fernet
import traceback
import hashlib
import random
import string

app = Flask(__name__)

# Set the secret key for the session
app.secret_key = 'supersecretkey'  # Change this to a random secret key in production

# Generate a secret key for encryption
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
    hashed_words = []
    words = []
    with open(dictionary_file, 'r') as f:
        for word in f:
            word = word.strip()
            hashed_word = hashlib.sha256((word + salt).encode()).hexdigest()
            hashed_words.append(hashed_word)
            words.append(word)
    for i in range(len(hashed_words)):
        [print(hashed_words[i])]
        if hashed_words[i] == hash_to_crack:
            print("Cracked.")
            return True
    return False

@app.route('/password_cracking', methods=['GET', 'POST'])
def password_cracking():
    if 'hashed_password' not in session:
        random_password = generate_random_password()
        hashed_password, salt = generate_hashed_password(random_password)
        session['hashed_password'] = hashed_password
        session['original_password'] = random_password
        session['salt'] = salt
        print('Generated new password for the session')

    if request.method == 'POST':
        if 'password' in request.json:
            input_password = request.json['password']
            print('Received Password:', input_password)
            salt = session['salt']  # Use the salt stored in the session
            hashed_input = hashlib.sha256((input_password + salt).encode()).hexdigest()
            print("Hashed_Input: ", hashed_input)

            if hashed_input == session['hashed_password']:
                print("Password has been cracked.")
                return jsonify({'message': 'Password has been cracked.', 'password': input_password, 'method': 'Hash Matching'})
            else:
                dictionary_path = 'dictionary.txt'  # Path to the dictionary file
                cracked_password = dictionary_attack(hashed_input, salt, dictionary_path)
                if cracked_password is not None:
                    print("Password has been cracked via dictionary attack.")
                    return jsonify({'message': 'Password has been cracked via dictionary attack.', 'password': cracked_password, 'method': 'Dictionary Attack'})
                else:
                    print("Failed to crack password.")
                    return jsonify({'message': 'Failed to crack password.'})
        else:
            return jsonify({'error': 'No password provided.'})
    return render_template('password_cracking.html')

if __name__ == '__main__':
    app.run(debug=True)
