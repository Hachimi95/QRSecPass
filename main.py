import pyqrcode
from PIL import Image
from pyzbar.pyzbar import decode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from base64 import urlsafe_b64encode, urlsafe_b64decode
import json
import getpass

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_data(data, key):
    cipher = Cipher(algorithms.AES(key), modes.GCM(b'\x00' * 16), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return ciphertext, encryptor.tag

def decrypt_data(ciphertext, key, tag):
    try:
        cipher = Cipher(algorithms.AES(key), modes.GCM(b'\x00' * 16, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()
    except Exception as e:
        print("Authentication tag mismatch. Please check your master password.")
        return None

def save_qr_code(data, filename):
    qr = pyqrcode.create(data)
    qr.png(filename, scale=6)
    print(f"QR code saved to {filename}")

def read_qr_code(filename):
    qr_data = decode(Image.open(filename))
    if qr_data:
        return qr_data[0].data.decode()
    else:
        print("No QR code found in the image.")
        return None

def print_accounts(accounts):
    for i, account in enumerate(accounts, 1):
        print(f"Account {i}:")
        print(f"  - Website: {account['website']}")
        print(f"  - Username: {account['username']}")
        print(f"  - Password: {account['password']}")
        print("\n")

def main():
    print("Options:")
    print("1. Upload QR code")
    print("2. Create new QR code")

    choice = input("Enter your choice: ")

    if choice == "2":
        while True:
            master_password = getpass.getpass("Enter your master password: ")
            if len(master_password) < 8 or not any(char.isdigit() for char in master_password) or not any(char.isalpha() for char in master_password):
                print("Master password is too weak. It should be at least 8 characters long and include both letters and numbers.")
            else:
                break

        try:
            salt = b'\x00' * 16  # Generate a random salt for each user
            key = derive_key(master_password, salt)
        except ValueError as e:
            print(f"Error: {e}")
            return

        website_infos = []

        while True:
            website = input("Enter website (or type 'done' to finish): ")
            if website.lower() == 'done':
                break

            username = input("Enter username: ")
            password = getpass.getpass("Enter password: ")

            account_data = {"website": website, "username": username, "password": password}
            website_infos.append(account_data)

        # Check if there's existing data
        qr_file = "password_qr_code.png"
        existing_data = []
        try:
            qr_data = read_qr_code(qr_file)
            if qr_data:
                existing_data = json.loads(
                    decrypt_data(urlsafe_b64decode(qr_data).split(b':')[0], key, urlsafe_b64decode(qr_data).split(b':')[1]).decode())
        except Exception as e:
            print(f"Error reading existing data: {e}")

        # Combine existing data with new data
        website_infos += existing_data

        # Save the updated data to QR code
        data_to_encode = json.dumps(website_infos, indent=2).encode()
        ciphertext, tag = encrypt_data(data_to_encode, key)
        save_qr_code(urlsafe_b64encode(ciphertext + b':' + tag).decode(), "updated_qr_code.png")
        print("Account added successfully.")

    elif choice == "1":
        qr_file = input("Enter the path to your QR code image: ")
        qr_data = read_qr_code(qr_file)

        if qr_data:
            master_password = getpass.getpass("Enter your master password: ")

            try:
                salt = b'\x00' * 16  # Retrieve the salt associated with the user
                key = derive_key(master_password, salt)
            except ValueError as e:
                print(f"Error: {e}")
                return

            decoded_parts = urlsafe_b64decode(qr_data).split(b':')

            if len(decoded_parts) >= 2:
                ciphertext = decoded_parts[0]
                tag = decoded_parts[1]

                decrypted_data = decrypt_data(ciphertext, key, tag)
                try:
                    website_infos = json.loads(decrypted_data.decode())
                    print_accounts(website_infos)

                    # Option to add new information
                    add_new_info = input("Do you want to add new information? (y/n): ")
                    if add_new_info.lower() == 'y':
                        new_website = input("Enter website: ")
                        new_username = input("Enter username: ")
                        new_password = getpass.getpass("Enter password: ")

                        # Add new information to existing data
                        website_infos.append(
                            {"website": new_website, "username": new_username, "password": new_password})

                        # Save the updated data to QR code
                        data_to_encode = json.dumps(website_infos, indent=2).encode()
                        ciphertext, tag = encrypt_data(data_to_encode, key)
                        save_qr_code(urlsafe_b64encode(ciphertext + b':' + tag).decode(), "updated_qr_code.png")
                        print("New information added successfully.")

                except json.JSONDecodeError as e:
                    print(f"Error decoding JSON: {e}")

            else:
                print("Invalid QR code format.")

    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()
