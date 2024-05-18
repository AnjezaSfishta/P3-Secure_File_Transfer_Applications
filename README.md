# Secure File Transfer Application

This is a simple application built using Python and Tkinter GUI toolkit, designed for secure file transfer over a network connection. It provides a user-friendly interface for sending and receiving files while ensuring data security through end-to-end encryption and integrity checks.


## Features
- **Send Files**: Easily select files from your local system and securely send them to another user.
- **Receive Files**: Receive files sent by others securely and ensure data integrity during transmission.
- **Encryption**: Files are encrypted using RSA-OAEP encryption to protect them from unauthorized access.
- **Decryption**: Received files are decrypted using the recipient's private key, ensuring data confidentiality.
- **Integrity Check**: SHA-256 hash is used to verify the integrity of the received files, detecting any tampering or corruption.


## Usage

### Send Files:

1. Click on the "Send" button.
2. Select the file you want to send.
3. Click on the "SEND" button to initiate the transfer.

### Receive Files:

1. Click on the "Receive" button.
2. Enter the sender's ID (IP address) and the filename for the incoming file.
3. Click on the "RECEIVE" button to start receiving the file.

## Contributors
- Anjeza Gashi
- Anjeza Sfishta
- Arbnore Qorraj
