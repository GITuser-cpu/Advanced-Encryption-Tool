from cryptography.fernet import Fernet
import os

def generate_key():
    """Generate a new key for encryption."""
    return Fernet.generate_key()

def encrypt_file(file_path, key):
    """Encrypt the file at the given path using the provided key."""
    fernet = Fernet(key)
    
    with open(file_path, 'rb') as file:
        original = file.read()
    
    encrypted = fernet.encrypt(original)
    
    with open(file_path + '.enc', 'wb') as encrypted_file:
        encrypted_file.write(encrypted)

def decrypt_file(encrypted_file_path, key):
    """Decrypt the encrypted file at the given path using the provided key."""
    fernet = Fernet(key)
    
    with open(encrypted_file_path, 'rb') as encrypted_file:
        encrypted = encrypted_file.read()
    
    try:
        decrypted = fernet.decrypt(encrypted)
    except Exception as e:
        print(f"Decryption failed: {str(e)}")
        return
    
    with open(encrypted_file_path[:-4], 'wb') as decrypted_file:
        decrypted_file.write(decrypted)

from flask import Flask, request, jsonify, send_from_directory

app = Flask(__name__)

@app.route('/')
def home():
    return send_from_directory('.', 'index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.json
    file_path = data['file_path']
    key = data['key'].encode()
    encrypt_file(file_path, key)
    return jsonify({"message": "File encrypted successfully."})

@app.route('/decrypt', methods=['POST'])
def decrypt():
    data = request.json
    encrypted_file_path = data['encrypted_file_path']
    key = data['key'].encode()
    decrypt_file(encrypted_file_path, key)
    return jsonify({"message": "File decrypted successfully."})

if __name__ == "__main__":
    app.run(debug=True)
    
def main():
    while True:
        choice = input("Do you want to (e)ncrypt or (d)ecrypt a file? (q to quit): ")
        if choice == 'e':
            file_path = input("Enter the file path to encrypt: ").strip().strip('"')
            key = generate_key()
            encrypt_file(file_path, key)
            print(f"File encrypted. Key: {key.decode()}")
        elif choice == 'd':
            encrypted_file_path = input("Enter the encrypted file path: ").strip().strip('"')
            key = input("Enter the key: ").encode()
            decrypt_file(encrypted_file_path, key)
            print("File decrypted.")
        elif choice == 'q':
            break
        else:
            print("Invalid choice. Please choose again.")

if __name__ == "__main__":
    main()
