
# Password Manager using QR Codes

This Python-based password manager utilizes QR codes for storing and managing encrypted account credentials. It uses AES encryption and allows you to add, view, and update account information through a user-friendly command-line interface.

## Features

- **Create New QR Code:** Generate a new QR code to store your account information securely.
- **Upload QR Code:** Decode and access the stored account information from an existing QR code.
- **Strong Encryption:** Utilizes AES encryption to secure your sensitive data.

## Requirements
- Python 3.x
- `pyqrcode` library
- `PIL` (Python Imaging Library)
- `pyzbar` library
- `cryptography` library

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/password-manager.git
2. Clone the repository:
   ```bash
   pip install pyqrcode pillow pyzbar cryptography  
## Usage
3. Run the Script :
   ```bash
   python main.py
4. Follow Prompts :
   - Create new QR code: Choose a master password and account details.
   - Upload QR code: Enter the path to your QR code and master password to access account    information and add new information.
## Security Considerations
   - Always use a strong master password: a combination of letters, numbers, and symbols.
   - Avoid storing your master password digitally.
   - Store QR codes in a secure location.    
## Contributing

Contributions are welcome! Feel free to open issues and pull requests.

