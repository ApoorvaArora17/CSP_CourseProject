from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import socket

# File to store index database
INDEX_DB_FILE = "index_database.txt"

def load_index_database():
    index_db = {}
    try:
        with open(INDEX_DB_FILE, "r") as file:
            for line in file:
                username, index = line.strip().split(":")
                index_db[username] = int(index)
    except FileNotFoundError:
        # If file doesn't exist, return an empty dictionary
        pass
    return index_db

def save_index_database(index_db):
    with open(INDEX_DB_FILE, "w") as file:
        for username, index in index_db.items():
            file.write(f"{username}:{index}\n")

def check_index(db, username, index):
    if username in db and db[username] == index:
        return "Yes"
    else:
        return "No"
    
def set_index(db, username, index):
    db[username] = index
    return db

def main():
    global index_database
    index_database = load_index_database()
    key = RSA.generate(2048)

    honeychecker_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    honeychecker_socket.bind(('127.0.0.1', 9999))  # Assuming Honeychecker listens on port 9999
    honeychecker_socket.listen(5)

    while True:
        client_socket, addr = honeychecker_socket.accept()
        print(f"Connection from {addr[0]}:{addr[1]}")

        client_socket.send(key.publickey().export_key())

        cipher_rsa = PKCS1_OAEP.new(key)
        encrypted_session_key = client_socket.recv(256)
        session_key = cipher_rsa.decrypt(encrypted_session_key)

        encrypted_data = client_socket.recv(1024)

        iv = encrypted_data[:16]
        cipher = encrypted_data[16:]
        plaintext = decrypt_aes_cbc(cipher, session_key, iv)

        data = plaintext.decode().split(':')
        action = data[0]
        username = data[1]
        index = int(data[2])

        if action == "login":
            iv = get_random_bytes(16)
            response = encrypt_aes_cbc(check_index(index_database, username, index).encode('utf-8'), session_key, iv)

            client_socket.send(response)

        else:
            index_database = set_index(index_database, username, index)
            save_index_database(index_database)

def encrypt_aes_cbc(plaintext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = plaintext + b'\x00' * (16 - len(plaintext) % 16)
    ciphertext = iv + cipher.encrypt(padded_plaintext)
    return ciphertext

def decrypt_aes_cbc(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext.rstrip(b'\x00')

if __name__ == "__main__":
    main()
