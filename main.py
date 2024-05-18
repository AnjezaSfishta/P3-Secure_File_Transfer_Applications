import socket
from tkinter import *
from tkinter import filedialog
import os
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
import threading

root = Tk()
root.title("Shareit")
root.geometry("450x560+500+200")
root.configure(bg="#f4fdfe")
root.resizable(False, False)

def Send():
    window = Toplevel(root)
    window.title("Send")
    window.geometry('450x560+500+200')
    window.configure(bg="#f4fdfe")
    window.resizable(False, False)

    def select_file():
        global filename
        filename = filedialog.askopenfilename(initialdir=os.getcwd(),
                                              title='Select File',
                                              filetype=(('all files', '*.*'),))

    def encrypt_file(filename, public_key_path):
        with open(public_key_path, "rb") as key_file:
            public_key = serialization.load_pem_public_key(key_file.read())

        with open(filename, "rb") as f:
            file_data = f.read()

        # Compute hash of the file data
        hasher = hashes.Hash(hashes.SHA256())
        hasher.update(file_data)
        file_hash = hasher.finalize()

        encrypted_data = public_key.encrypt(
            file_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        encrypted_filename = f"{filename}.enc"
        with open(encrypted_filename, "wb") as f:
            f.write(file_hash + encrypted_data)

        return encrypted_filename
