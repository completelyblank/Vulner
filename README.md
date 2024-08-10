![vul](https://github.com/user-attachments/assets/7a144183-0121-4e9c-8a1e-31f9455ccfa9)

# Vulner

This repository contains a Flask-based web application with features for data encryption, decryption, password cracking, and basic malware analysis. The application also includes logging for debugging purposes.

## Features

![encrypt](https://github.com/user-attachments/assets/eda53964-4287-4fef-865b-1407bcc9d8b0)

- **Encryption and Decryption**: Encrypt and decrypt sensitive data using the Fernet symmetric encryption method.
  
![pass_crack](https://github.com/user-attachments/assets/824f8c56-3b2c-4149-909b-a358b724cf2c)

- **Password Cracking**: Simulate password cracking using a dictionary attack and hash matching.

![malnysis](https://github.com/user-attachments/assets/664c7d7c-8284-4b91-b027-4a2a021cc72d)
  
- **Malware Analysis**: Analyze uploaded files for malware by scanning their content against known signatures.

## Requirements

Before you begin, ensure you have met the following requirements:

- Python 3.x
- Flask
- cryptography

## Installation

1. Clone this repository:

    ```bash
    git clone https://github.com/yourusername/yourrepositoryname.git
    cd yourrepositoryname
    ```

2. Install the required packages:

    ```bash
    pip install -r requirements.txt
    ```

3. Run the Flask application:

    ```bash
    python app.py
    ```

4. Open your browser and navigate to `http://127.0.0.1:5000` to access the application.

## Usage

### Encryption

1. Navigate to the `/encrypt` endpoint.
2. Enter the data you want to encrypt in the provided input field.
3. Click on the "Encrypt" button to get the encrypted output.

### Decryption

1. Navigate to the `/decrypt` endpoint.
2. Enter the encrypted data you want to decrypt in the provided input field.
3. Click on the "Decrypt" button to get the decrypted output.

### Password Cracking

1. Navigate to the `/password_cracking` endpoint.
2. Enter a password to simulate a password cracking attempt.
3. If the password matches the stored hash, you will receive a success message. Otherwise, the application will attempt to crack the password using a dictionary attack.

### Malware Analysis

1. Navigate to the `/malnysis` endpoint.
2. Upload a file to be scanned for malware.
3. The application will analyze the file content against known malware signatures and return the result.

## Logging

Logging is set up to help debug and trace the application's behavior. Logs are printed to the console.

## File Structure

- **app.py**: The main Flask application file.
- **templates/**: HTML files for rendering web pages.
- **static/**: Static files such as CSS, JavaScript, and images.
- **dictionary.txt**: A file containing a list of words used for the dictionary attack.
- **signatures.txt**: A file containing known malware signatures for scanning files.

## Security Considerations

- **Secret Key**: The `app.secret_key` should be changed to a more secure, random value before deploying the application.
- **Encryption Key**: The encryption key is generated per session. In a production environment, consider securely storing and reusing the key across sessions.

## Contributing

If you want to contribute to this project:

1. Fork the repository.
2. Create a new branch (`git checkout -b feature-branch`).
3. Make your changes.
4. Commit and push your changes (`git commit -m 'Add new feature'`).
5. Create a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgements

- [Flask Documentation](https://flask.palletsprojects.com/)
- [Cryptography Documentation](https://cryptography.io/)
