![image](https://github.com/completelyblank/Vulner/assets/105001837/36a53da5-3013-4695-b8dd-3e02dbfb1963)

# Vulner

Vulner is a basic encryption project designed to introduce me to the world of cyber security. This project demonstrates the implementation of encryption and decryption using Flask, Axios, basic HTML, and CSS. The encryption algorithms used are RSA and AWA, with Flask Cryptography handling the encryption and decryption processes.

## Features

- **Encryption and Decryption**: Implemented using RSA and AWA encryption algorithms.
- **Web Interface**: Simple and user-friendly interface built with basic HTML and CSS.
- **Backend**: Flask is used as the web framework for the backend.
- **Frontend**: Axios is used for making HTTP requests from the frontend to the backend.

## Technologies Used

- **Flask**: A micro web framework for Python.
- **Axios**: A promise-based HTTP client for the browser and Node.js.
- **HTML & CSS**: Basic web technologies for building the user interface.
- **RSA & AWA**: Encryption algorithms used for securing data.
- **Flask Cryptography**: A library for cryptographic operations within Flask.

## Future Development
This project is ongoing, and I will continue to add new cybersecurity protocols and features to advance its capabilities. 
-Some upcoming features include:
-Implementing additional encryption algorithms.
-Integrating secure authentication and authorization mechanisms.
-Enhancing the web interface with more advanced features.
-Expanding the project to include more advanced cybersecurity concepts.

## Getting Started

### Prerequisites

- Python 3.x
- Flask
- Flask-Cryptography
- Node.js (for Axios)

### Installation

1. **Clone the repository**:

    ```bash
    git clone https://github.com/yourusername/vulner.git
    cd vulner
    ```

2. **Create a virtual environment**:

    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
    ```

3. **Install the required Python packages**:

    ```bash
    pip install Flask Flask-Cryptography
    ```

4. **Install Axios**:

    If you don't have Node.js and npm installed, download and install them from [Node.js](https://nodejs.org/). Then, install Axios:

    ```bash
    npm install axios
    ```

### Running the Application

1. **Start the Flask server**:

    ```bash
    flask run
    ```

2. **Open your browser and navigate to**:

    ```
    http://127.0.0.1:5000/
    ```

## Usage

1. **Encrypt a message**:
    - Enter the message you want to encrypt in the provided text box.
    - Select the encryption algorithm (RSA or AWA).
    - Click the "Encrypt" button to encrypt the message.

2. **Decrypt a message**:
    - Enter the encrypted message in the provided text box.
    - Select the encryption algorithm (RSA or AWA).
    - Click the "Decrypt" button to decrypt the message.

## Project Structure

vulner/
├── static/
│ ├── css/
│ │ └── styles.css
│ └── js/
│ └── app.js
├── templates/
│ └── index.html
├── app.py
└── README.md


- **static/**: Contains CSS and JavaScript files.
- **templates/**: Contains HTML templates.
- **app.py**: Main Flask application file.
- **README.md**: Project documentation.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgements

- Thanks to the Flask and Flask-Cryptography communities for their helpful resources and documentation.
- Special thanks to the creators of RSA and AWA encryption algorithms.

---

Always.
