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
    
    def sender():
        encrypted_filename = encrypt_file(filename, "public_keys/receiver_public_key.pem")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((socket.gethostname(), 8080))
        s.listen(1)
        print('waiting for incoming connections...')
        conn, addr = s.accept()
        print(f'Connection from {addr}')

        with open(encrypted_filename, 'rb') as file:
            file_data = file.read(1024)
            while file_data:
                conn.send(file_data)
                file_data = file.read(1024)
        conn.close()
        print("Data has been transmitted successfully...")

    def start_sending():
        threading.Thread(target=sender).start()

    image_icon1 = PhotoImage(file="Image/send.png")
    window.iconphoto(False, image_icon1)

    Sbackground = PhotoImage(file="Image/sender.png").subsample(1)
    Label(window, image=Sbackground).place(x=-2, y=0)

    Mbackground = PhotoImage(file="Image/id.png").subsample(2)
    Label(window, image=Mbackground, bg='#f4fdfe').place(x=50, y=300)

    host = socket.gethostname()
    ip = socket.gethostbyname(host)
    Label(window, text=f'ID: {ip}', bg='white', fg='black').place(x=182, y=339)

    Button(window, text="+ select file", width=10, height=1, font='arial 14 bold', bg="#fff", fg="#000", command=select_file).place(x=190, y=230)
    Button(window, text="SEND", width=8, height=1, font='arial 14 bold', bg='#000', fg="#fff", command=start_sending).place(x=330, y=230)

    window.mainloop()

def Receive():
    main = Toplevel(root)
    main.title("Receive")
    main.geometry('450x560+500+200')
    main.configure(bg="#f4fdfe")
    main.resizable(False, False)

    def receiver():
        ID = SenderID.get()
        filename1 = incoming_file.get()

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ID, 8080))
        with open("received_encrypted_file", 'wb') as file:
            while True:
                file_data = s.recv(1024)
                if not file_data:
                    break
                file.write(file_data)
        s.close()

        decrypt_file("received_encrypted_file", filename1, "private_keys/private_key.pem")
        print("File has been received and decrypted successfully!")

    def start_receiving():
        threading.Thread(target=receiver).start()

    def decrypt_file(encrypted_file, output_file, private_key_path):
        with open(private_key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(key_file.read(), password=None)

        with open(encrypted_file, "rb") as f:
            encrypted_data = f.read()

        # Extract hash and encrypted data
        file_hash = encrypted_data[:32]  # SHA-256 hash is 32 bytes
        encrypted_data = encrypted_data[32:]

        decrypted_data = private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Compute hash of the decrypted data
        hasher = hashes.Hash(hashes.SHA256())
        hasher.update(decrypted_data)
        computed_hash = hasher.finalize()

        if file_hash != computed_hash:
            print("Integrity check failed: The file has been tampered with or corrupted.")
            return

        with open(output_file, "wb") as f:
            f.write(decrypted_data)

    image_icon1 = PhotoImage(file="Image/receive.png")
    main.iconphoto(False, image_icon1)

    Hbackground = PhotoImage(file="Image/receiver.png").subsample(2)
    Label(main, image=Hbackground, bd=0).place(x=0, y=0, relwidth=1)

    logo = PhotoImage(file='Image/profile.png').subsample(8)
    Label(main, image=logo, bg="#f4fdfe").place(x=30, y=200)

    Label(main, text="Receive", font=('arial', 20), bg="#f4fdfe").place(x=100, y=218)
